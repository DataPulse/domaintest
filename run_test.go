package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// scenario wires a fakeRunner and a mapped dialer for one domain. Every
// delv call not registered explicitly is answered from the fixture index,
// nameserver-audit digs from a healthy authoritative capture, and
// quicprobe from an unsupported result.
type scenario struct {
	r      *fakeRunner
	cfg    config
	dialer *mappedDialer
}

func (s *scenario) delv(name, qtype, file string, t *testing.T) {
	s.r.on("delv", delvArgs(s.cfg.Resolver, "", name, qtype), fakeCall{stdout: fixture(t, file)})
}

func (s *scenario) reach(family, file string, t *testing.T) {
	s.r.on("delv", delvArgs(s.cfg.Resolver, family, reachabilityQuery, "NS"), fakeCall{stdout: fixture(t, file)})
}

func (s *scenario) trace(file string, t *testing.T) {
	s.r.on("dig", traceArgs(familyIPv4, s.cfg.TimeoutSec, s.cfg.Domain), fakeCall{stdout: fixture(t, file)})
}

// glue registers the parent-side NS answer used for the glue check.
func (s *scenario) glue(parentServer, file string, t *testing.T) {
	s.r.on("dig", glueArgs(parentServer, familyIPv4, s.cfg.TimeoutSec, s.cfg.Domain), fakeCall{stdout: fixture(t, file)})
}

func (s *scenario) run() *Report {
	return run(context.Background(), s.cfg, s.r, s.dialer)
}

// digCalls returns the dig invocations containing every substring.
func (s *scenario) digCalls(subs ...string) []string {
	var out []string
	for _, c := range s.r.called("dig") {
		ok := true
		for _, sub := range subs {
			ok = ok && strings.Contains(c, sub)
		}
		if ok {
			out = append(out, c)
		}
	}
	return out
}

func newScenario(t *testing.T, domain, server string) *scenario {
	t.Helper()
	withResolvConf(t, "nameserver 10.12.60.1\n")
	old := preloadFetcher
	preloadFetcher = func(context.Context, string, time.Duration) (string, error) { return "unknown", nil }
	t.Cleanup(func() { preloadFetcher = old })
	r := newFakeRunner()
	r.fallback = fixtureFallback(t)
	cfg := baseConfig(domain, server)
	cfg.HSTSPreload = true
	return &scenario{r: r, cfg: cfg, dialer: newMappedDialer()}
}

func jschmidtScenario(t *testing.T) *scenario {
	s := newScenario(t, "jschmidt.org", "")
	s.reach(familyIPv4, "delv/root_ns_v4.yaml", t)
	s.trace("trace/jschmidt.txt", t)
	return s
}

func TestRun_SignedDomainWithoutWeb(t *testing.T) {
	s := jschmidtScenario(t)
	rep := s.run()

	check(t, "errors", rep.Errors, []string{})
	check(t, "ok", rep.OK, true)
	check(t, "resolver", rep.Resolver, "system")
	check(t, "timeouts", []int{rep.TimeoutSec, rep.TCPTimeoutSec, rep.QuicTimeoutSec}, []int{5, 2, 2})
	check(t, "families", rep.Families, []string{familyIPv4, familyIPv6})
	check(t, "dnssec state", rep.DNSSEC.State, DNSSECSecure)
	check(t, "delegation", rep.Delegation.Status, DelegationMatch)
	check(t, "reachability", rep.DNS.ResolverReachable, map[string]string{familyIPv4: ReachYes, familyIPv6: ReachSkipped})
	check(t, "web", rep.Web, WebSection{})
	check(t, "warnings", rep.Warnings, []string{"apex has no A or AAAA records", "www has no A or AAAA records"})
	check(t, "no quic", len(s.r.called("quicprobe")), 0)
	check(t, "no dials", len(s.dialer.seen), 0)
	check(t, "no bogus probe", len(s.digCalls("+cd")), 0)
	check(t, "preload consulted", rep.HSTSPreload, "unknown")
}

func TestRun_MailAndNameserverSections(t *testing.T) {
	s := jschmidtScenario(t)
	rep := s.run()
	m := rep.Mail
	if m == nil {
		t.Fatal("mail section missing")
	}
	check(t, "dmarc", []string{m.DMARC.Policy, m.SPF.All}, []string{"quarantine", "~all"})
	check(t, "spf includes outlook", m.SPF.Includes[0], "outlook.com")
	check(t, "spf within limit", m.SPF.Lookups <= spfLookupLimit, true)
	check(t, "mx checked", len(m.MX), 1)
	check(t, "mx addresses", m.MX[0].Addresses, 8)
	check(t, "dkim", m.DKIM.SelectorsFound, []string{"selector1", "selector2"})
	check(t, "mta-sts absent", m.MTASTS.Record, false)
	check(t, "tls-rpt", m.TLSRPT, false)

	n := rep.Nameservers
	if n == nil {
		t.Fatal("nameservers section missing")
	}
	check(t, "count", n.Count, 4)
	check(t, "eight audited", len(n.Servers), 8)
	for _, srv := range n.Servers {
		check(t, "aa "+srv.IP, srv.AA, true)
		check(t, "edns "+srv.IP, srv.EDNS, true)
		check(t, "tcp "+srv.IP, srv.TCP, true)
	}
	check(t, "serials", n.SerialsConsistent, true)
	check(t, "prefix diversity", []int{n.IPv4Prefixes24, n.IPv6Prefixes48}, []int{4, 4})
	check(t, "no glue needed", len(n.Glue.Required), 0)
	check(t, "caa", rep.CAA.Note, "no certificate observed")
	check(t, "tlsa", rep.TLSA.Result, TLSANone)
	check(t, "wildcard", rep.Wildcard.Present, false)
	check(t, "audit digs", len(s.digCalls("+norecurse", "SOA")), 8)
}

// googleWeb stands up local servers for google.com / www.google.com and
// maps the fixture addresses to them: v4 serves HTTP (redirect to https)
// and HTTPS, v6 serves HTTPS only.
type googleWeb struct {
	s      *scenario
	v4, v6 netip.Addr
	ca     *testCA
	leaf   *x509.Certificate
	key    *ecdsa.PrivateKey
}

func googleScenario(t *testing.T) *googleWeb {
	s := newScenario(t, "google.com", "")
	s.reach(familyIPv4, "delv/root_ns_v4.yaml", t)
	s.trace("trace/google.txt", t)
	s.glue("l.gtld-servers.net", "dig/ns/glue_google_at_gtld.yaml", t)
	s.delv("www.google.com", "A", "delv/google_a_unsigned.yaml", t)
	s.delv("www.google.com", "AAAA", "delv/google_aaaa_unsigned.yaml", t)
	s.r.fallback = func(inner func(string, []string) (fakeCall, bool)) func(string, []string) (fakeCall, bool) {
		return func(tool string, args []string) (fakeCall, bool) {
			if tool == "quicprobe" {
				return fakeCall{stdout: fixture(t, "quicprobe/google_supported.json")}, true
			}
			return inner(tool, args)
		}
	}(s.r.fallback)
	v4 := parseDelvYAML(fixture(t, "delv/google_a_unsigned.yaml"), "A").Addrs()[0]
	v6 := parseDelvYAML(fixture(t, "delv/google_aaaa_unsigned.yaml"), "AAAA").Addrs()[0]
	ca := newTestCAWithOrg(t, "GTS Root R1", "Google Trust Services LLC")
	withRoots(t, ca.pool)
	leaf, key := ca.issue(t, certSpec{sans: []string{"google.com", "www.google.com"}, issuer: ca, org: "Google LLC"})
	g := &googleWeb{s: s, v4: v4, v6: v6, ca: ca, leaf: leaf}
	https := tlsServer(t, okHandler(map[string]string{"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload", "Server": "gws"}), []*x509.Certificate{leaf, ca.cert}, key, tls.VersionTLS12, tls.VersionTLS13)
	http80 := plainServer(t, redirectHandler(301, "https://google.com/"))
	s.dialer.mapTarget(v4.String(), 80, http80)
	s.dialer.mapTarget(v4.String(), 443, https)
	s.dialer.mapTarget(v6.String(), 443, https)
	g.key = key
	return g
}

func TestRun_WebDomainFullProbe(t *testing.T) {
	g := googleScenario(t)
	rep := g.s.run()
	check(t, "errors", rep.Errors, []string{})
	// Google's four nameservers really do share 2001:4860:4802::/48.
	check(t, "warnings", rep.Warnings, []string{"all IPv6 nameserver addresses share one /48"})
	check(t, "dnssec", rep.DNSSEC.State, DNSSECInsecure)
	check(t, "delegation", rep.Delegation.Status, DelegationMatch)
	apex := rep.Web.Apex
	if apex == nil || len(apex.IPv4) != 1 || len(apex.IPv6) != 1 {
		t.Fatalf("apex web %+v", apex)
	}
	a4 := apex.IPv4[0]
	check(t, "v4 ports", []PortState{a4.HTTP, a4.HTTPS}, []PortState{PortOpen, PortOpen})
	check(t, "v4 http redirect", []interface{}{a4.HTTPRes.Status, a4.HTTPRes.Location}, []interface{}{301, "https://google.com/"})
	check(t, "v4 https status", a4.HTTPSRes.Status, 200)
	check(t, "v4 server header", a4.HTTPSRes.Server, "gws")
	check(t, "v4 hsts", a4.HTTPSRes.HSTS, &HSTS{MaxAge: 31536000, IncludeSubdomains: true, Preload: true})
	check(t, "v4 tls chain", a4.TLS.Chain, ChainValid)
	check(t, "v4 tls version", a4.TLS.Version, "TLS 1.3")
	check(t, "v4 old versions rejected", a4.TLS.TLS10 || a4.TLS.TLS11, false)
	check(t, "v4 cert covers both", []bool{a4.TLS.Cert.CoversApex, a4.TLS.Cert.CoversWWW}, []bool{true, true})
	check(t, "v4 quic", a4.QUIC.Supported, true)
	a6 := apex.IPv6[0]
	check(t, "v6 80 refused", a6.HTTP, PortRefused)
	check(t, "v6 443 open", a6.HTTPS, PortOpen)
	check(t, "cert consistent", *apex.CertConsistent, true)
	chain := apex.Redirects[familyIPv4]
	check(t, "redirect chain", chain.Hops, []RedirectHop{{"http://google.com/", 301}, {"https://google.com/", 200}})
	check(t, "final url", chain.FinalURL, "https://google.com/")
	check(t, "www probed separately", rep.Web.WWW.SameAsApex && len(rep.Web.WWW.IPv4) == 1, true)
	check(t, "www cert", rep.Web.WWW.IPv4[0].TLS.Chain, ChainValid)
	check(t, "quic per name per family", len(g.s.r.called("quicprobe")), 4)
	check(t, "caa permitted", *rep.CAA.Permitted, true)
	check(t, "nameservers glue ok", []int{len(rep.Nameservers.Glue.Required), len(rep.Nameservers.Glue.Missing)}, []int{4, 0})
	check(t, "mail dmarc reject", rep.Mail.DMARC.Policy, "reject")
}

func TestRun_WebProblems(t *testing.T) {
	g := googleScenario(t)
	s := g.s
	// v4: expired certificate that also covers only the apex; HTTP 80 serves
	// content in the clear; TLS 1.0 accepted. www: 503 on 443.
	expired, ekey := g.ca.issue(t, certSpec{sans: []string{"google.com"}, issuer: g.ca, notBefore: time.Now().Add(-48 * time.Hour), notAfter: time.Now().Add(-time.Hour)})
	badTLS := tlsServer(t, okHandler(map[string]string{"Strict-Transport-Security": "max-age=300"}), []*x509.Certificate{expired, g.ca.cert}, ekey, tls.VersionTLS10, tls.VersionTLS12)
	s.dialer.mapTarget(g.v4.String(), 443, badTLS)
	s.dialer.mapTarget(g.v4.String(), 80, plainServer(t, okHandler(nil)))
	s.dialer.mapTarget(g.v6.String(), 443, tlsServer(t, statusHandler(503), []*x509.Certificate{g.leaf, g.ca.cert}, g.key, tls.VersionTLS12, tls.VersionTLS13))

	rep := s.run()
	check(t, "not ok", rep.OK, false)
	check(t, "expired is an error", contains(rep.Errors, "certificate expired:"), true)
	check(t, "5xx on one address is a warning", contains(rep.Warnings, "1 of 2 addresses return a server error on port 443"), true)
	check(t, "old tls warning aggregated", contains(rep.Warnings, "apex: TLS 1.0/1.1 still accepted on 1 of 2 addresses"), true)
	check(t, "no tls 1.3 warning", contains(rep.Warnings, "apex: no TLS 1.3 on 1 of 2 addresses"), true)
	check(t, "cleartext warning", contains(rep.Warnings, "apex: HTTP serves content in the clear"), true)
	check(t, "short hsts warning", contains(rep.Warnings, "apex: HSTS max-age 300 is under 180 days"), true)
	check(t, "expired cert covers apex only but www has its own valid cert: no coverage warning", contains(rep.Warnings, "does not cover"), false)
	check(t, "certificates differ", contains(rep.Warnings, "addresses serve different certificates"), true)
	check(t, "expired chain recorded", rep.Web.Apex.IPv4[0].TLS.Chain, ChainExpired)
	check(t, "cert consistent false", *rep.Web.Apex.CertConsistent, false)
}

func TestRun_FamilyRestriction(t *testing.T) {
	g := googleScenario(t)
	g.s.cfg.Families = []string{familyIPv4}
	rep := g.s.run()
	check(t, "no ipv6 entries", len(rep.Web.Apex.IPv6), 0)
	check(t, "ipv4 entry", len(rep.Web.Apex.IPv4), 1)
	_, hasV6 := rep.DNS.ResolverReachable[familyIPv6]
	check(t, "ipv6 reachability not checked", hasV6, false)
	for _, d := range g.s.dialer.seen {
		check(t, "no ipv6 dial: "+d, strings.HasPrefix(d, "tcp6"), false)
	}
	check(t, "quic apex+www v4", len(g.s.r.called("quicprobe")), 2)
	check(t, "ipv4 nameservers only", len(rep.Nameservers.Servers), 4)
}

func TestRun_WWWWithDifferentAddresses(t *testing.T) {
	g := googleScenario(t)
	g.s.delv("www.google.com", "A", "delv/www_isc_a_validated.yaml", t)
	g.s.delv("www.google.com", "AAAA", "delv/jschmidt_aaaa_nxrrset.yaml", t)
	rep := g.s.run()
	check(t, "not same as apex", rep.Web.WWW.SameAsApex, false)
	check(t, "www ipv4 entries", len(rep.Web.WWW.IPv4), 4)
	check(t, "www addresses refused", rep.Web.WWW.IPv4[0].HTTPS, PortRefused)
	check(t, "www AAAA warning", contains(rep.Warnings, "www has no AAAA"), true)
	check(t, "www no listener warning", contains(rep.Warnings, "www 151.101.3.42: no listener"), true)
	check(t, "apex cert does not cover... no: it does", contains(rep.Warnings, "does not cover www"), false)
}

func TestRun_BogusZoneViaPublicResolver(t *testing.T) {
	s := newScenario(t, "dnssec-failed.org", "8.8.8.8")
	inner := s.r.fallback
	s.r.fallback = func(tool string, args []string) (fakeCall, bool) {
		if tool == "delv" && strings.Contains(strings.Join(args, " "), "dnssec-failed.org") {
			return fakeCall{stdout: fixture(t, "delv/dnssec_failed_failure.yaml")}, true
		}
		return inner(tool, args)
	}
	s.delv("dnssec-failed.org", "DS", "delv/dnssec_failed_ds.yaml", t)
	s.reach(familyIPv4, "delv/root_ns_v4_8888.yaml", t)
	s.trace("trace/dnssec_failed_mismatch.txt", t)
	s.r.on("dig", digArgs(resolver{Host: "8.8.8.8"}, true, 5, "dnssec-failed.org", "A"), fakeCall{stdout: fixture(t, "dig/dnssec_failed_cd.yaml")})
	s.r.on("dig", digArgs(resolver{Host: "8.8.8.8"}, false, 5, "dnssec-failed.org", "A"), fakeCall{stdout: fixture(t, "dig/dnssec_failed_nocd.yaml"), err: errFake})
	for _, ns := range []string{"dns101", "dns104", "dns105"} {
		for _, ip := range parseDelvYAML(fixture(t, "delv/ns/"+ns+"_comcast_a.yaml"), "A").Addrs() {
			s.r.on("dig", nsAuditArgs(ip, "dnssec-failed.org", 5), fakeCall{stdout: fixture(t, "dig/ns/dnssec_failed_at_"+ns+".yaml")})
		}
	}

	rep := s.run()
	check(t, "ok", rep.OK, false)
	check(t, "dnssec state", rep.DNSSEC.State, DNSSECBogus)
	check(t, "ede", strings.Contains(rep.DNSSEC.EDE, "DNSKEY Missing"), true)
	check(t, "delegation", rep.Delegation.Status, DelegationMismatch)
	check(t, "errors", len(rep.Errors), 2)
	check(t, "bogus error", contains(rep.Errors, "bogus"), true)
	check(t, "mismatch error", contains(rep.Errors, "mismatch"), true)
	check(t, "nameservers from the parent set", rep.Nameservers.Count, 3)
	check(t, "audited", len(rep.Nameservers.Servers) > 0, true)
	check(t, "resolver", rep.Resolver, "8.8.8.8")
}

func TestRun_ResolverUnreachableAndTimeouts(t *testing.T) {
	s := jschmidtScenario(t)
	withResolvConf(t, "nameserver 10.12.60.1\nnameserver 2001:db8::53\n")
	s.reach(familyIPv6, "delv/root_ns_v6_refused.yaml", t)
	s.cfg.TimeoutSec = 1
	s.trace("trace/jschmidt.txt", t)
	s.r.on("delv", delvArgs(resolver{}, "", "jschmidt.org", "TXT"), fakeCall{delay: 3 * time.Second})

	start := time.Now()
	rep := s.run()
	if elapsed := time.Since(start); elapsed > 2500*time.Millisecond {
		t.Errorf("run took %v, expected the 1s timeout to bound it", elapsed)
	}
	check(t, "ok", rep.OK, false)
	check(t, "ipv6 error", contains(rep.Errors, "not reachable over ipv6"), true)
	check(t, "timeout error", contains(rep.Errors, "apex TXT lookup timed out"), true)
	check(t, "TXT status", rep.DNS.Apex["TXT"].Status, StatusTimeout)
}

func TestRun_NXDomain(t *testing.T) {
	s := newScenario(t, "nonexistent-zzz-qq.org", "")
	s.r.fallback = func(tool string, args []string) (fakeCall, bool) {
		if tool == "delv" {
			return fakeCall{stdout: fixture(t, "delv/nxdomain_signed.yaml")}, true
		}
		return fakeCall{}, false
	}
	s.reach(familyIPv4, "delv/root_ns_v4.yaml", t)
	s.trace("trace/nxdomain.txt", t)
	rep := s.run()
	check(t, "ok", rep.OK, false)
	check(t, "nxdomain error", contains(rep.Errors, "NXDOMAIN"), true)
	check(t, "not delegated error", contains(rep.Errors, "not delegated"), true)
	check(t, "dnssec", rep.DNSSEC.State, DNSSECInsecure)
	check(t, "no nameserver audit", rep.Nameservers, (*NSReport)(nil))
}

func TestRun_ReservedAddress(t *testing.T) {
	s := newScenario(t, "localtest.me", "")
	s.reach(familyIPv4, "delv/root_ns_v4.yaml", t)
	s.trace("trace/jschmidt.txt", t) // any healthy trace shape; delegation is not under test
	rep := s.run()
	check(t, "reserved listed", rep.ReservedAddresses, []string{"127.0.0.1 (loopback)", "127.0.0.1 (loopback)"})
	check(t, "error", contains(rep.Errors, "reserved address published in DNS: 127.0.0.1 (loopback)"), true)
	check(t, "ports skipped", []PortState{rep.Web.Apex.IPv4[0].HTTP, rep.Web.Apex.IPv4[0].HTTPS}, []PortState{PortSkipped, PortSkipped})
	check(t, "nothing dialed", len(s.dialer.seen), 0)
	check(t, "no quic", len(s.r.called("quicprobe")), 0)
}

func TestRun_WildcardZone(t *testing.T) {
	s := newScenario(t, "github.io", "")
	s.reach(familyIPv4, "delv/root_ns_v4.yaml", t)
	s.trace("trace/jschmidt.txt", t)
	rep := s.run()
	check(t, "wildcard present", rep.Wildcard.Present, true)
	check(t, "wildcard addresses", len(rep.Wildcard.Addresses), 8)
	// www.github.io has A records only while the wildcard answers A and AAAA,
	// so the address sets differ and www is not marked as wildcard-only.
	check(t, "www not via wildcard", rep.Wildcard.WWWViaWildcard, false)
}

func TestRun_ReportSerialises(t *testing.T) {
	s := jschmidtScenario(t)
	rep := s.run()
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"domain", "resolver", "families", "timeout_sec", "tcp_timeout_sec", "quic_timeout_sec", "dns", "dnssec", "delegation", "web", "mail", "nameservers", "caa", "tlsa", "wildcard", "hsts_preload", "errors", "warnings", "ok", "elapsed_ms"} {
		if _, ok := generic[key]; !ok {
			t.Errorf("report missing %q", key)
		}
	}
	for _, hidden := range []string{`"rrs"`, `"chain":[`, `"pkixValid"`} {
		check(t, "internal field hidden "+hidden, strings.Contains(string(b), hidden), false)
	}
}

func TestResolvConfFamilies(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "resolv.conf")
	write := func(content string) {
		if err := writeFile(p, content); err != nil {
			t.Fatal(err)
		}
	}
	write("# comment\nnameserver 10.0.0.1\nsearch example.org\nnameserver fe80::1%eth0\n")
	check(t, "dual", resolvConfFamilies(p), map[string]bool{familyIPv4: true, familyIPv6: true})
	write("nameserver 10.0.0.1\n")
	check(t, "v4 only", resolvConfFamilies(p), map[string]bool{familyIPv4: true})
	write("options edns0\n")
	check(t, "no nameservers", resolvConfFamilies(p), map[string]bool{})
	check(t, "missing file", resolvConfFamilies(filepath.Join(dir, "missing")), map[string]bool{})
}

func TestResolverSupports(t *testing.T) {
	withResolvConf(t, "nameserver 10.0.0.1\n")
	sys := baseConfig("x.org", "")
	check(t, "system v4", resolverSupports(sys, familyIPv4), true)
	check(t, "system v6", resolverSupports(sys, familyIPv6), false)
	withResolvConf(t, "")
	check(t, "unknown resolv.conf", resolverSupports(sys, familyIPv6), true)
	v6 := baseConfig("x.org", "2001:4860:4860::8888")
	check(t, "literal v6 server, v4", resolverSupports(v6, familyIPv4), false)
	check(t, "literal v6 server, v6", resolverSupports(v6, familyIPv6), true)
	host := baseConfig("x.org", "dns.google")
	check(t, "hostname v4", resolverSupports(host, familyIPv4), true)
	check(t, "hostname v6", resolverSupports(host, familyIPv6), true)
}

func TestDetectNotAZone(t *testing.T) {
	ns := parseDelvYAML(fixture(t, "delv/outlook_host_ns_nxrrset.yaml"), "NS")
	a := parseDelvYAML(fixture(t, "delv/outlook_host_a.yaml"), "A")
	none := parseDelvYAML(fixture(t, "delv/jschmidt_aaaa_nxrrset.yaml"), "AAAA")
	host := "aelcs-com.mail.protection.outlook.com"
	noDeleg := Delegation{Status: DelegationNotDelegated}

	is, zone := detectNotAZone(host, dnsResults{apex: map[string]Lookup{"NS": ns, "A": a}}, noDeleg)
	check(t, "addresses but no NS", is, true)
	check(t, "zone unknown without SOA", zone, "")

	is, zone = detectNotAZone("host.jschmidt.org", dnsResults{apex: map[string]Lookup{"NS": ns, "A": a, "AAAA": none}}, noDeleg)
	check(t, "zone from the negative answer's SOA", zone, "jschmidt.org")
	check(t, "is host", is, true)

	txt := parseDelvYAML(fixture(t, "delv/dmarc_jschmidt_txt.yaml"), "TXT")
	is, _ = detectNotAZone("_dmarc.jschmidt.org", dnsResults{apex: map[string]Lookup{"NS": ns, "TXT": txt}}, noDeleg)
	check(t, "TXT-only host", is, true)

	dns := dnsResults{apex: map[string]Lookup{"NS": parseDelvYAML(fixture(t, "delv/dmarc_jschmidt_ns.yaml"), "NS")}}
	is, zone = detectNotAZone("_dmarc.jschmidt.org", dns, noDeleg)
	check(t, "SOA above the name", is, true)
	check(t, "zone", zone, "jschmidt.org")

	self := Lookup{Status: StatusNXRRSet, rrs: []RR{{Owner: host + ".", Type: "SOA"}}}
	is, _ = detectNotAZone(host, dnsResults{apex: map[string]Lookup{"NS": ns, "AAAA": self}}, noDeleg)
	check(t, "own SOA and no data", is, false)

	other := Lookup{Status: StatusNXRRSet, rrs: []RR{{Owner: "example.net.", Type: "SOA"}}}
	is, _ = detectNotAZone(host, dnsResults{apex: map[string]Lookup{"NS": ns, "AAAA": other}}, noDeleg)
	check(t, "unrelated SOA", is, false)

	lame := Delegation{Status: DelegationChildNoNS, ParentNS: []string{"ns1.example."}}
	is, _ = detectNotAZone(host, dnsResults{apex: map[string]Lookup{"NS": ns, "A": a}}, lame)
	check(t, "delegated name is a zone", is, false)

	real := parseDelvYAML(fixture(t, "delv/jschmidt_ns.yaml"), "NS")
	is, _ = detectNotAZone("jschmidt.org", dnsResults{apex: map[string]Lookup{"NS": real, "A": a}}, Delegation{})
	check(t, "zone apex with NS", is, false)
}

func TestRun_TXTOnlyNameInSignedZone(t *testing.T) {
	name := "_dmarc.jschmidt.org"
	s := newScenario(t, name, "")
	for _, tt := range []string{"A", "AAAA", "MX", "TXT", "NS", "DS", "DNSKEY"} {
		s.delv(name, tt, "delv/dmarc_jschmidt_"+strings.ToLower(tt)+".yaml", t)
	}
	s.delv("www."+name, "A", "delv/www_dmarc_jschmidt_a.yaml", t)
	s.delv("www."+name, "AAAA", "delv/www_dmarc_jschmidt_a.yaml", t)
	s.reach(familyIPv4, "delv/root_ns_v4.yaml", t)
	s.trace("trace/dmarc_jschmidt_not_delegated.txt", t)
	rep := s.run()
	check(t, "not a zone", rep.NotAZone, true)
	check(t, "enclosing zone", rep.EnclosingZone, "jschmidt.org")
	check(t, "delegation", rep.Delegation.Status, DelegationNotAZone)
	check(t, "dnssec follows the validated TXT answer", rep.DNSSEC.State, DNSSECSecure)
	check(t, "healthy", rep.Errors, []string{})
	check(t, "warned once about the zone", contains(rep.Warnings, "not a zone apex (inside zone jschmidt.org)"), true)
	check(t, "no bogus probe", len(s.digCalls("+cd")), 0)
	check(t, "no nameserver audit for a host", rep.Nameservers, (*NSReport)(nil))
}

func TestRun_ResolverWithPort(t *testing.T) {
	s := newScenario(t, "jschmidt.org", "127.0.0.1:5353")
	s.trace("trace/jschmidt.txt", t)
	rep := s.run()
	check(t, "resolver shown with port", rep.Resolver, "127.0.0.1:5353")
	check(t, "delv calls made", len(s.r.called("delv")) > 10, true)
	for _, c := range s.r.called("delv") {
		check(t, "delv call carries the port: "+c, strings.Contains(c, "@127.0.0.1 -p 5353"), true)
	}
	check(t, "trace still goes to the root", strings.Contains(s.digCalls("+trace")[0], "-p"), false)
	for _, c := range s.digCalls("+norecurse") {
		check(t, "authoritative queries never use the resolver port: "+c, strings.Contains(c, "-p 5353"), false)
	}
}

func TestRun_IDNDomainUsesALabel(t *testing.T) {
	cfg, err := parseArgs([]string{"MÜNCHEN.de."})
	if err != nil {
		t.Fatal(err)
	}
	s := newScenario(t, cfg.Domain, "")
	s.cfg.UnicodeDomain = cfg.UnicodeDomain
	s.reach(familyIPv4, "delv/root_ns_v4.yaml", t)
	s.trace("trace/muenchen.txt", t)
	rep := s.run()
	check(t, "domain is the A-label", rep.Domain, "xn--mnchen-3ya.de")
	check(t, "unicode form reported", rep.UnicodeDomain, "münchen.de")
	check(t, "errors", rep.Errors, []string{})
	check(t, "delegation", rep.Delegation.Status, DelegationMatch)
	check(t, "www shares the apex address", rep.Web.WWW.SameAsApex, true)
	for _, c := range s.r.called("") {
		check(t, "no U-label reaches a tool: "+c, strings.Contains(c, "ü"), false)
	}
	for _, c := range s.r.called("quicprobe") {
		check(t, "quicprobe SNI is an A-label: "+c, strings.HasSuffix(c, "xn--mnchen-3ya.de"), true)
	}
	check(t, "nameservers audited", rep.Nameservers.Count, 4)
}

func TestRun_HostInsideZoneIsNotAZone(t *testing.T) {
	host := "aelcs-com.mail.protection.outlook.com"
	s := newScenario(t, host, "")
	s.delv(host, "TXT", "delv/outlook_host_txt_failure.yaml", t)
	s.reach(familyIPv4, "delv/root_ns_v4.yaml", t)
	s.r.on("dig", traceArgs(familyIPv4, 5, host), fakeCall{stdout: fixture(t, "trace/nxdomain.txt")})
	rep := s.run()
	check(t, "not_a_zone", rep.NotAZone, true)
	check(t, "delegation", rep.Delegation.Status, DelegationNotAZone)
	check(t, "dnssec from answer trust", rep.DNSSEC.State, DNSSECInsecure)
	check(t, "no bogus probe for a non-zone", len(s.digCalls("+cd")), 0)
	check(t, "only the TXT failure remains an error", rep.Errors, []string{"apex TXT lookup failed: delv: resolution failed"})
	check(t, "not-a-zone warning", contains(rep.Warnings, "is not a zone apex"), true)
	check(t, "addresses probed (refused)", rep.Web.Apex.IPv4[0].HTTPS, PortRefused)
}
