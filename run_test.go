package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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

// testWildcardLabels are the labels every scenario probes with. The
// fixtures under testdata/delv/wild are captured for exactly these names.
var testWildcardLabels = []string{"qhrmzvbxklap", "tzwnpcdfjyeu", "kbsvxlmqrtdh"}

// stubWildcardLabels pins the random probe labels so a run is reproducible
// and its queries match captured fixtures.
func stubWildcardLabels(t *testing.T, labels ...string) {
	t.Helper()
	if len(labels) == 0 {
		labels = testWildcardLabels
	}
	prev := wildcardLabels
	wildcardLabels = func(n int) []string {
		if n > len(labels) {
			n = len(labels)
		}
		return labels[:n]
	}
	t.Cleanup(func() { wildcardLabels = prev })
}

func newScenario(t *testing.T, domain, server string) *scenario {
	t.Helper()
	withResolvConf(t, "nameserver 10.12.60.1\n")
	stubWildcardLabels(t)
	// Not on the list, and no filesystem cache in unit tests.
	stubList(t, &preloadList{entries: map[string]preloadRecord{"example.net": {includeSubdomains: true}}}, nil)
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
	check(t, "reachability", rep.DNS.ResolverReachable, map[string]string{familyIPv4: ReachYes, familyIPv6: "skipped: resolver has no ipv6 address"})
	check(t, "web", rep.Web, WebSection{})
	// jschmidt.org's SPF includes amazonses.com, whose TXT answer is 523
	// octets on the wire.
	check(t, "warnings", notes(rep), []string{"apex has no A or AAAA records", "www has no A or AAAA records", "SPF: include:amazonses.com TXT answer is 523 octets, over the 512-octet UDP limit (RFC 7208 §3.4)"})
	check(t, "no quic", len(s.r.called("quicprobe")), 0)
	check(t, "no dials", len(s.dialer.seen), 0)
	check(t, "no bogus probe", len(s.digCalls("+cd")), 0)
	check(t, "not on the list", rep.HSTSPreload, PreloadAbsent)
	check(t, "no preload error", rep.HSTSPreloadError, "")
	check(t, "no covered-by", rep.HSTSPreloadCoveredBy, "")
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
	check(t, "serials", *n.SerialsConsistent, true)
	check(t, "prefix diversity", []int{*n.IPv4Prefixes24, *n.IPv6Prefixes48}, []int{4, 4})
	check(t, "no glue needed", len(n.Glue.Required), 0)
	check(t, "caa", rep.CAA.Hosts["apex"].Note, "no certificate observed")
	check(t, "caa hosts", len(rep.CAA.Hosts), 2)
	check(t, "tlsa", rep.TLSA.Result, TLSANone)
	check(t, "tlsa absence is signed in a signed zone", rep.TLSA.Signed, true)
	check(t, "tlsa lists present", rep.TLSA.Apex != nil && rep.TLSA.WWW != nil, true)
	check(t, "wildcard", rep.Wildcard.Status, WildcardAbsent)
	check(t, "denied by a random name, not a vacuous false", rep.Wildcard.DeterminedBy, "the random name qhrmzvbxklap is denied")
	check(t, "nothing to compare", rep.Wildcard.Consistent == nil, true)
	check(t, "stopped after one probe", len(rep.Wildcard.Probes), 1)
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
	// google.com publishes 17 apex TXT records (1176 octets without EDNS;
	// a live dig +noedns really is truncated), and Google's four
	// nameservers really do share 2001:4860:4802::/48.
	check(t, "warnings", notes(rep), []string{
		"SPF: apex TXT answer is 1176 octets, over the 512-octet UDP limit (RFC 7208 §3.4): resolvers without EDNS get a truncated reply and must retry over TCP",
		"all IPv6 nameserver addresses share one /48",
	})
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
	check(t, "v4 old versions rejected", []any{a4.TLS.TLS10, a4.TLS.TLS11}, []any{boolPtr(false), boolPtr(false)})
	check(t, "v4 cert covers both", []bool{a4.TLS.Cert.CoversApex, a4.TLS.Cert.CoversWWW}, []bool{true, true})
	check(t, "v4 quic", a4.QUIC.Supported, true)
	a6 := apex.IPv6[0]
	check(t, "v6 80 refused", a6.HTTP, PortRefused)
	check(t, "v6 443 open", a6.HTTPS, PortOpen)
	check(t, "cert consistent", *apex.CertConsistent, true)
	chain := apex.Redirects[familyIPv4]
	check(t, "redirect chain", chain.Hops, []RedirectHop{{URL: "http://google.com/", Status: 301, Location: "https://google.com/"}, {URL: "https://google.com/", Status: 200}})
	check(t, "final url", chain.FinalURL, "https://google.com/")
	check(t, "www probed separately", rep.Web.WWW.SameAsApex && len(rep.Web.WWW.IPv4) == 1, true)
	check(t, "www cert", rep.Web.WWW.IPv4[0].TLS.Chain, ChainValid)
	check(t, "quic on every address of both names", len(g.s.r.called("quicprobe")), 4)
	check(t, "v6 quic attached", apex.IPv6[0].QUIC != nil, true)
	check(t, "caa apex permitted", *rep.CAA.Hosts["apex"].Permitted, true)
	check(t, "caa www permitted", *rep.CAA.Hosts["www"].Permitted, true)
	check(t, "tlsa unsigned in an unsigned zone", rep.TLSA.Signed, false)
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
	check(t, "expired is an error", contains(rep.Errors, "apex: certificate expired on 1 of 2 addresses:"), true)
	check(t, "5xx on one address is a warning", contains(notes(rep), "1 of 2 addresses return a server error on port 443"), true)
	check(t, "old tls warning aggregated", contains(notes(rep), "apex: TLS 1.0/1.1 still accepted on 1 of 2 addresses"), true)
	check(t, "no tls 1.3 warning", contains(notes(rep), "apex: no TLS 1.3 on 1 of 2 addresses"), true)
	check(t, "cleartext warning", contains(notes(rep), "apex: HTTP serves content in the clear"), true)
	check(t, "short hsts warning", contains(notes(rep), "apex: HSTS max-age 300 is under 180 days"), true)
	check(t, "expired cert covers apex only but www has its own valid cert: no coverage warning", contains(notes(rep), "does not cover"), false)
	check(t, "certificates differ", contains(notes(rep), "addresses serve certificates that differ in validity or in the names they cover"), true)
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
	check(t, "www AAAA warning", contains(notes(rep), "www has no AAAA"), true)
	check(t, "www no listener warning", contains(notes(rep), "www 151.101.3.42: no listener"), true)
	check(t, "apex cert does not cover... no: it does", contains(notes(rep), "does not cover www"), false)
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
	// One address published at both apex and www is one reserved address.
	check(t, "reserved listed once", rep.ReservedAddresses, []string{"127.0.0.1 (loopback)"})
	reserved := 0
	for _, e := range rep.Errors {
		if strings.Contains(e, "reserved address published") {
			reserved++
		}
	}
	check(t, "one error, not one per host", reserved, 1)
	// The probe declined to connect; nothing failed to listen.
	check(t, "says why it was not probed", contains(notes(rep), "apex 127.0.0.1: not probed (reserved address)"), true)
	check(t, "not reported as a dead listener", contains(notes(rep), "no listener"), false)
	check(t, "ports skipped", []PortState{rep.Web.Apex.IPv4[0].HTTP, rep.Web.Apex.IPv4[0].HTTPS}, []PortState{PortSkipped, PortSkipped})
	check(t, "nothing dialed", len(s.dialer.seen), 0)
	check(t, "no quic", len(s.r.called("quicprobe")), 0)
}

func TestRun_WildcardZone(t *testing.T) {
	s := newScenario(t, "github.io", "")
	s.reach(familyIPv4, "delv/root_ns_v4.yaml", t)
	s.trace("trace/jschmidt.txt", t)
	rep := s.run()
	check(t, "wildcard present", rep.Wildcard.Status, WildcardPresent)
	check(t, "three names agreed", rep.Wildcard.DeterminedBy, "3 random names all answer")
	check(t, "wildcard addresses", len(rep.Wildcard.Addresses), 8)
	check(t, "all three probed", len(rep.Wildcard.Probes), 3)
	check(t, "and they agree", *rep.Wildcard.Consistent, true)
	// www.github.io has A records only while the wildcard answers A and AAAA,
	// so the address sets differ and www is not marked as wildcard-only.
	check(t, "www not via wildcard", rep.Wildcard.WWWViaWildcard, false)
	check(t, "six probe queries", probeQueries(s), 6)
}

// probeQueries counts the delv calls made for the random wildcard names.
func probeQueries(s *scenario) int {
	n := 0
	for _, c := range s.r.called("delv") {
		for _, l := range testWildcardLabels {
			if strings.Contains(c, " "+l+".") {
				n++
			}
		}
	}
	return n
}

// A zone that denies a random name costs the same two queries as the single
// probe this check replaces, and one whose www does not exist costs none.
func TestRun_WildcardQueryBudget(t *testing.T) {
	s := jschmidtScenario(t)
	s.run()
	check(t, "one probe, both types", probeQueries(s), 2)

	// www NXDOMAIN is an answer already in hand: no probe is worth issuing.
	gone := newScenario(t, "jschmidt.org", "")
	gone.reach(familyIPv4, "delv/root_ns_v4.yaml", t)
	gone.trace("trace/jschmidt.txt", t)
	gone.delv("www.jschmidt.org", "A", "delv/nxdomain_unsigned.yaml", t)
	rep := gone.run()
	check(t, "no probe issued", probeQueries(gone), 0)
	check(t, "still a definite answer", rep.Wildcard.Status, WildcardAbsent)
	check(t, "and it says why", rep.Wildcard.DeterminedBy, "www is NXDOMAIN, so no wildcard could have answered for it")
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
	check(t, "warned once about the zone", contains(notes(rep), "not a zone apex (inside zone jschmidt.org)"), true)
	check(t, "no bogus probe", len(s.digCalls("+cd")), 0)
	check(t, "no nameserver audit for a host", rep.Nameservers, (*NSReport)(nil))
	check(t, "no mail section for a host", rep.Mail, (*MailReport)(nil))
	check(t, "no DMARC noise", contains(notes(rep), "DMARC"), false)
}

func TestRun_PreloadStatuses(t *testing.T) {
	// google.com itself listed: preloaded, no covered-by.
	g := googleScenario(t) // header: max-age 1y, includeSubDomains, preload
	stubList(t, &preloadList{entries: map[string]preloadRecord{"google.com": {includeSubdomains: true}}}, nil)
	rep := g.s.run()
	check(t, "preloaded", rep.HSTSPreload, PreloadPreloaded)
	check(t, "no covered-by for an exact entry", rep.HSTSPreloadCoveredBy, "")
	check(t, "entry includes subdomains", rep.HSTSPreloadIncludeSubdomains, boolPtr(true))
	check(t, "header meets requirements", contains(notes(rep), "preload"), false)

	// Covered by an ancestor with include_subdomains.
	g = googleScenario(t)
	stubList(t, &preloadList{entries: map[string]preloadRecord{"com": {includeSubdomains: true}}}, nil)
	rep = g.s.run()
	check(t, "preloaded via ancestor", rep.HSTSPreload, PreloadPreloaded)
	check(t, "covered by", rep.HSTSPreloadCoveredBy, "com")
	check(t, "an ancestor covers through include_subdomains", rep.HSTSPreloadIncludeSubdomains, boolPtr(true))
	check(t, "no policy on the stub entry", rep.HSTSPreloadPolicy, "")

	// Preloaded but the served header has decayed (cloudflare.com's case).
	g = googleScenario(t)
	stubList(t, &preloadList{entries: map[string]preloadRecord{"google.com": {includeSubdomains: true}}}, nil)
	weak := tlsServer(t, okHandler(map[string]string{"Strict-Transport-Security": "max-age=15780000"}), []*x509.Certificate{g.leaf, g.ca.cert}, g.key, tls.VersionTLS12, tls.VersionTLS13)
	g.s.dialer.mapTarget(g.v4.String(), 443, weak)
	g.s.dialer.mapTarget(g.v6.String(), 443, weak)
	rep = g.s.run()
	check(t, "decayed header warned", contains(notes(rep), "on the HSTS preload list but the served header does not meet"), true)

	// An apex that only redirects and serves no header, the shape gmail.com
	// has. Submitted through hstspreload.org it owes the header; kept by
	// hand (policy google) it does not, and the policy is reported instead.
	for policy, warned := range map[string]bool{"bulk-1-year": true, "google": false} {
		g = googleScenario(t)
		stubList(t, &preloadList{entries: map[string]preloadRecord{"google.com": {policy: policy}}}, nil)
		bare := tlsServer(t, redirectHandler(301, "https://mail.google.com/mail/u/0/"), []*x509.Certificate{g.leaf, g.ca.cert}, g.key, tls.VersionTLS12, tls.VersionTLS13)
		g.s.dialer.mapTarget(g.v4.String(), 443, bare)
		g.s.dialer.mapTarget(g.v6.String(), 443, bare)
		rep = g.s.run()
		check(t, policy+": preloaded", rep.HSTSPreload, PreloadPreloaded)
		check(t, policy+": policy reported", rep.HSTSPreloadPolicy, policy)
		check(t, policy+": the apex answered a bare redirect", []interface{}{rep.Web.Apex.IPv4[0].HTTPSRes.Status, rep.Web.Apex.IPv4[0].HTTPSRes.HSTS}, []interface{}{301, (*HSTS)(nil)})
		check(t, policy+": missing header warned", contains(notes(rep), "serves no HSTS header on this response (https://google.com/ answered with a 301 redirect"), warned)
	}

	// Not on the list but the header claims preload without meeting the bar.
	g = googleScenario(t)
	stubList(t, &preloadList{entries: map[string]preloadRecord{"example.net": {includeSubdomains: true}}}, nil)
	claim := tlsServer(t, okHandler(map[string]string{"Strict-Transport-Security": "max-age=300; preload"}), []*x509.Certificate{g.leaf, g.ca.cert}, g.key, tls.VersionTLS12, tls.VersionTLS13)
	g.s.dialer.mapTarget(g.v4.String(), 443, claim)
	g.s.dialer.mapTarget(g.v6.String(), 443, claim)
	rep = g.s.run()
	check(t, "absent", rep.HSTSPreload, PreloadAbsent)
	check(t, "directive without requirements warned", contains(notes(rep), "carries the preload directive but does not meet"), true)

	// The list could not be obtained: unknown plus a scrubbed reason.
	g = googleScenario(t)
	stubList(t, nil, errors.New("Get \"https://chromium.googlesource.com\": dial tcp: lookup chromium.googlesource.com on 10.0.0.2:53: server misbehaving"))
	rep = g.s.run()
	check(t, "unknown", rep.HSTSPreload, PreloadUnknown)
	check(t, "reason kept", strings.Contains(rep.HSTSPreloadError, "server misbehaving"), true)
	check(t, "resolver scrubbed", strings.Contains(rep.HSTSPreloadError, "10.0.0.2"), false)
	check(t, "warned", contains(notes(rep), "HSTS preload list could not be consulted"), true)

	// Disabled: no status, no error, no warning, and no fetch.
	g = googleScenario(t)
	calls := stubList(t, fixtureList(t), nil)
	g.s.cfg.HSTSPreload = false
	rep = g.s.run()
	check(t, "disabled", rep.HSTSPreload+rep.HSTSPreloadError+rep.HSTSPreloadCoveredBy+rep.HSTSPreloadPolicy, "")
	check(t, "no fetch when disabled", calls.Load(), int32(0))
}

// The cache is read once per run and shared by every domain checked on the
// host: a populated cache means no fetch at all.
func TestRun_UsesPopulatedCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hsts-preload.tsv")
	if err := writePreloadCache(path, &preloadList{entries: map[string]preloadRecord{"google.com": {includeSubdomains: true}}}); err != nil {
		t.Fatal(err)
	}
	g := googleScenario(t)
	g.s.cfg.HSTSCache = path
	calls := stubList(t, fixtureList(t), nil)
	rep := g.s.run()
	check(t, "answered from the cache", rep.HSTSPreload, PreloadPreloaded)
	check(t, "no network", calls.Load(), int32(0))
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
	check(t, "not-a-zone warning", contains(notes(rep), "is not a zone apex"), true)
	check(t, "addresses probed (refused)", rep.Web.Apex.IPv4[0].HTTPS, PortRefused)
	check(t, "no mail section", rep.Mail, (*MailReport)(nil))
}

// A first-wave lookup that hangs must not poison the nameserver audit:
// the pre-fetch wave runs on the spent DNS budget, but the audit later
// resolves the names with the probe phase's own budget.
func TestRun_ExhaustedDNSBudgetDoesNotPoisonLateLookups(t *testing.T) {
	s := jschmidtScenario(t)
	s.cfg.TimeoutSec = 1
	s.trace("trace/jschmidt.txt", t)
	s.r.on("delv", delvArgs(resolver{}, "", "jschmidt.org", "DNSKEY"), fakeCall{delay: 3 * time.Second})
	rep := s.run()
	check(t, "dnskey timed out", rep.DNSSEC.State, DNSSECUnknown)
	if rep.Nameservers == nil {
		t.Fatal("nameservers missing")
	}
	check(t, "nameservers resolved after the DNS phase", rep.Nameservers.Unresolvable, []string{})
	check(t, "all eight audited", len(rep.Nameservers.Servers), 8)
	check(t, "mx still resolved", rep.Mail.MX[0].Addresses, 8)
	check(t, "no bogus 'no address' errors", contains(rep.Errors, "has no address"), false)
}

// With a cap of one, every DNS tool runs in turn and the report is the
// same as the uncapped one; quicprobe is deliberately not capped.
func TestRun_DNSConcurrencyCap(t *testing.T) {
	s := jschmidtScenario(t)
	s.cfg.DNSConcurrency = 1
	rep := s.run()
	check(t, "still healthy", rep.Errors, []string{})
	check(t, "dnssec", rep.DNSSEC.State, DNSSECSecure)
	check(t, "delegation", rep.Delegation.Status, DelegationMatch)
	check(t, "nameservers audited", len(rep.Nameservers.Servers), 8)
	check(t, "mail evaluated", rep.Mail.DMARC.Policy, "quarantine")
	check(t, "cap echoed in the report", rep.DNSConcurrency, 1)

	uncapped := jschmidtScenario(t)
	full := uncapped.run()
	check(t, "same errors", rep.Errors, full.Errors)
	check(t, "same warnings", notes(rep), notes(full))
	check(t, "same NS verdicts", len(rep.Nameservers.Servers), len(full.Nameservers.Servers))
}

// A cap must never starve the resolver-reachability probe: it measures our
// own resolver, and queueing it behind a target's hung lookups would turn
// a slow domain into a false claim that the resolver is down.
func TestRun_CapDoesNotStarveReachabilityProbe(t *testing.T) {
	s := jschmidtScenario(t)
	s.cfg.DNSConcurrency = 1
	s.cfg.TimeoutSec = 2
	// Every record lookup hangs for the whole budget; the root NS probe is
	// instant, as a healthy resolver would be.
	inner := s.r.fallback
	s.r.fallback = func(tool string, args []string) (fakeCall, bool) {
		joined := strings.Join(args, " ")
		if tool == "delv" && !strings.HasSuffix(joined, " . NS") {
			return fakeCall{delay: 5 * time.Second}, true
		}
		return inner(tool, args)
	}
	s.reach(familyIPv4, "delv/root_ns_v4.yaml", t)

	rep := s.run()
	check(t, "resolver still measured as reachable", rep.DNS.ResolverReachable[familyIPv4], ReachYes)
	check(t, "no false resolver error", contains(rep.Errors, "resolver not reachable"), false)
	check(t, "the domain's own lookups did time out", rep.DNS.Apex["A"].Status, StatusTimeout)
}

// budgetRunner records the deadline each distinct call was given and can
// stall selected calls, so a test can observe how much of the DNS budget a
// lookup actually received.
type budgetRunner struct {
	inner Runner
	delay func(key string) time.Duration
	mu    sync.Mutex
	left  map[string]time.Duration // first observation per call
}

func (b *budgetRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	key := callKey(name, args)
	b.mu.Lock()
	if _, seen := b.left[key]; !seen {
		if dl, ok := ctx.Deadline(); ok {
			b.left[key] = time.Until(dl)
		}
	}
	b.mu.Unlock()
	if d := b.delay(key); d > 0 {
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return nil, nil, fmt.Errorf("%s: %w", name, ctx.Err())
		}
	}
	return b.inner.Run(ctx, name, args...)
}

func (b *budgetRunner) budgetFor(key string) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.left[key]
}

// The dependent wave gets its own budget. A first wave that spends most of
// the allowance must not leave the MX targets and nameserver names with
// only the remainder, because those lookups then all time out at once and
// the report reads as a domain with no nameserver addresses.
func TestRun_DependentWaveHasItsOwnBudget(t *testing.T) {
	s := jschmidtScenario(t)
	s.cfg.TimeoutSec = 1
	b := &budgetRunner{inner: s.r, left: map[string]time.Duration{}, delay: func(key string) time.Duration {
		switch {
		case strings.HasSuffix(key, " jschmidt.org TXT"): // first wave: burns the budget
			return 700 * time.Millisecond
		case strings.Contains(key, "awsdns"): // second wave: needs a real allowance
			return 400 * time.Millisecond
		}
		return 0
	}}
	rep := run(context.Background(), s.cfg, b, s.dialer)

	nsKey := callKey("delv", delvArgs(s.cfg.Resolver, "", "ns-1013.awsdns-62.net", "A"))
	if got := b.budgetFor(nsKey); got < 500*time.Millisecond {
		t.Errorf("second wave got %v of a %v budget, want most of it", got, s.cfg.timeout())
	}
	if rep.Nameservers == nil {
		t.Fatal("nameservers missing")
	}
	check(t, "no name left unresolved", rep.Nameservers.Unresolved, []string{})
	check(t, "none reported absent", rep.Nameservers.Unresolvable, []string{})
	check(t, "all eight audited", len(rep.Nameservers.Servers), 8)
	if rep.Nameservers.SerialsConsistent == nil {
		t.Fatal("serials unknown: no nameserver was reached")
	}
	check(t, "serials compared", *rep.Nameservers.SerialsConsistent, true)
	check(t, "mx resolved", rep.Mail.MX[0].Addresses, 8)
	check(t, "no 'has no address' errors", contains(rep.Errors, "has no address"), false)
}

// A name that cannot receive mail has nothing to configure, so a "no DMARC
// record" warning would be advice nobody could act on. Mail is already
// skipped for a host inside a zone; the same applies to a name outside the
// global DNS and to one that does not exist.
func TestNoMailPossible(t *testing.T) {
	nx := Lookup{Status: StatusNXDomain}
	ok := Lookup{Status: StatusOK, Records: []string{"192.0.2.1"}}
	live := dnsResults{apex: map[string]Lookup{"A": ok, "NS": ok}}

	check(t, "healthy zone keeps mail", noMailPossible(&Report{}, live), false)
	check(t, "host inside a zone", noMailPossible(&Report{NotAZone: true}, live), true)
	check(t, "outside the global DNS", noMailPossible(&Report{ReservedName: "RFC 6761"}, live), true)
	check(t, "name does not exist", noMailPossible(&Report{}, dnsResults{apex: map[string]Lookup{"A": nx, "NS": nx}}), true)
	// One NXDOMAIN is a name-level denial, so either lookup settles it.
	check(t, "nxdomain on NS alone", noMailPossible(&Report{}, dnsResults{apex: map[string]Lookup{"A": ok, "NS": nx}}), true)
}

// A name with a CNAME cannot be a zone apex: RFC 1034 forbids a CNAME
// coexisting with other data, and an apex must carry NS and SOA. The NS
// query follows the CNAME, so records that come back describe the
// target's zone. gist.github.com is a CNAME to github.com, so its NS
// query returns github.com's nameservers; without this the audit asks
// them for a zone they do not have and every one answers REFUSED.
func TestDetectNotAZone_CNAMEIsNeverAnApex(t *testing.T) {
	cnamed := dnsResults{apex: map[string]Lookup{
		"NS":  {Status: StatusOK, CNAME: []string{"github.com."}, Records: []string{"ns-1283.awsdns-32.org."}},
		"SOA": {Status: StatusNXRRSet},
	}}
	got, _ := detectNotAZone("gist.github.com", cnamed, Delegation{})
	check(t, "a CNAME is not an apex", got, true)

	// A real apex answers NS without a CNAME.
	apex := dnsResults{apex: map[string]Lookup{"NS": {Status: StatusOK, Records: []string{"ns1.github.com."}}}}
	got, _ = detectNotAZone("github.com", apex, Delegation{})
	check(t, "a real apex is a zone", got, false)

	// A name the parent actually delegates is a zone whatever else we saw.
	delegated, _ := detectNotAZone("blog.example.com", cnamed, Delegation{ParentNS: []string{"ns1.example.net."}})
	check(t, "parent delegation wins", delegated, false)

	// The existing NXRRSET path still works.
	host := dnsResults{apex: map[string]Lookup{
		"NS": {Status: StatusNXRRSet},
		"A":  {Status: StatusOK, Records: []string{"192.0.2.1"}},
	}}
	got, _ = detectNotAZone("www.example.com", host, Delegation{})
	check(t, "host inside a zone", got, true)
}

// www belongs to a registrable domain. Prefixing it to a name that is
// already a host invents a name nobody configured, and a catch-all answers
// it with a certificate that cannot cover the extra label, which read as a
// hostname mismatch on a healthy site.
func TestProbeWeb_NoWWWForAHostInsideAZone(t *testing.T) {
	host := "aelcs-com.mail.protection.outlook.com"
	s := newScenario(t, host, "")
	s.delv(host, "TXT", "delv/outlook_host_txt_failure.yaml", t)
	s.reach(familyIPv4, "delv/root_ns_v4.yaml", t)
	s.r.on("dig", traceArgs(familyIPv4, 5, host), fakeCall{stdout: fixture(t, "trace/nxdomain.txt")})
	rep := s.run()
	check(t, "detected as a host", rep.NotAZone, true)
	check(t, "no www section", rep.Web.WWW, (*HostWeb)(nil))
	check(t, "no www warnings", contains(notes(rep), "www "), false)

	// An apex still gets the full www treatment.
	apex := jschmidtScenario(t)
	rep = apex.run()
	check(t, "apex is a zone", rep.NotAZone, false)
	check(t, "www still warned about", contains(notes(rep), "www has no A or AAAA records"), true)
}

// A run that reaches its deadline stops, says so, and still returns its
// report: scrape kills a run at 20 s and keeps nothing, so a report cut
// short is worth more than none.
func TestRun_DeadlineCutsTheRunShort(t *testing.T) {
	s := jschmidtScenario(t)
	s.cfg.MaxTimeSec = 1
	b := &budgetRunner{inner: s.r, left: map[string]time.Duration{}, delay: func(string) time.Duration { return time.Minute }}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	rep := run(ctx, s.cfg, b, s.dialer)
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("run took %v after a 300ms deadline", el)
	}
	check(t, "deadline reached", rep.DeadlineReached, true)
	check(t, "said once, as info", findingsWithCode(rep, "run_deadline_reached"), []string{
		"info : the run reached its 1-second deadline; checks still running then were cut short",
	})
}

func TestRun_NoDeadlineNoFinding(t *testing.T) {
	rep := jschmidtScenario(t).run()
	check(t, "deadline not reached", rep.DeadlineReached, false)
	check(t, "no finding", findingsWithCode(rep, "run_deadline_reached"), []string(nil))
}

// When the trace finds the delegated servers silent, the nameserver audit
// runs before the probes and can spend its whole allowance waiting on
// them. The probes after it must still get theirs: sharing one budget left
// QUIC, HTTP and the preload lookup with the scraps.
func TestRun_SilentDelegationAuditHasItsOwnBudget(t *testing.T) {
	g := googleScenario(t)
	s := g.s
	s.cfg.TimeoutSec, s.cfg.TCPTimeoutSec, s.cfg.QuicTimeoutSec = 2, 1, 2
	full := fixture(t, "trace/google.txt")
	cut := full[:strings.Index(full, ";; Received 287 bytes from 192.41.162.30")]
	cut += ";; Received 287 bytes from 192.41.162.30#53(l.gtld-servers.net) in 36 ms\n\n;; communications error to 216.239.32.10#53: timed out\n"
	s.r.on("dig", traceArgs(familyIPv4, s.cfg.TimeoutSec, s.cfg.Domain), fakeCall{stdout: cut})
	s.r.on("dig", authArgs("l.gtld-servers.net", familyIPv4, s.cfg.TimeoutSec, s.cfg.Domain), fakeCall{stdout: fixture(t, "dig/jschmidt_at_org_referral.yaml")})
	s.glue("l.gtld-servers.net", "dig/ns/glue_google_at_gtld.yaml", t)
	var audits atomic.Int32
	b := &budgetRunner{inner: s.r, left: map[string]time.Duration{}, delay: func(key string) time.Duration {
		// One server answers; the rest are silent until their query times out.
		if strings.Contains(key, "+norecurse") && strings.Contains(key, "SOA") && audits.Add(1) > 1 {
			return time.Minute
		}
		return 0
	}}
	rep := run(context.Background(), s.cfg, b, s.dialer)
	check(t, "delegation silent", rep.Delegation.Status, DelegationNoChildAnswer)
	check(t, "zone still answers", zoneUnreachable(rep), false)
	var quic time.Duration
	for _, c := range s.r.called("quicprobe") {
		quic = b.budgetFor(c)
		break
	}
	if quic < time.Duration(s.cfg.QuicTimeoutSec)*time.Second {
		t.Errorf("quicprobe got %v after the audit, want its full allowance", quic)
	}
	check(t, "web probed", rep.Web.Apex != nil && rep.Web.Apex.IPv4[0].HTTPS == PortOpen, true)
}

// peakDialer refuses every connection after a short wait and records how
// many dials to port 443 were in flight at once.
type peakDialer struct {
	mu        sync.Mutex
	open, max int
}

func (d *peakDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if strings.HasSuffix(address, ":443") {
		d.mu.Lock()
		d.open++
		d.max = max(d.max, d.open)
		d.mu.Unlock()
		defer func() { d.mu.Lock(); d.open--; d.mu.Unlock() }()
	}
	select {
	case <-time.After(20 * time.Millisecond):
	case <-ctx.Done():
	}
	return nil, &net.OpError{Op: "dial", Net: network, Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
}

// A zone may publish any number of addresses. Probing them all at once
// opened four sockets and a quicprobe process apiece, past the default
// file-descriptor limit at a few hundred.
func TestProbeWeb_CapsConcurrentAddresses(t *testing.T) {
	var recs []string
	for i := range 40 {
		recs = append(recs, fmt.Sprintf("1.1.%d.1", i))
	}
	cfg := baseConfig("example.com", "")
	r := newFakeRunner()
	r.fallback = func(tool string, _ []string) (fakeCall, bool) {
		return fakeCall{stdout: fixture(t, "quicprobe/example_unsupported.json")}, tool == "quicprobe"
	}
	dns := dnsResults{
		apex: map[string]Lookup{"A": {Status: StatusOK, Records: recs}, "AAAA": {Status: StatusNXRRSet}},
		www:  map[string]Lookup{"A": {Status: StatusNXDomain}, "AAAA": {Status: StatusNXDomain}},
	}
	d := &peakDialer{}
	web := probeWeb(context.Background(), cfg, r, d, dns, &Report{})
	check(t, "every address probed", len(web.Apex.IPv4), 40)
	if d.max > maxAddressProbes || d.max == 0 {
		t.Errorf("%d addresses probed at once, want at most %d", d.max, maxAddressProbes)
	}
}
