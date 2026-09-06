package main

import (
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// scenario wires a fakeRunner with the fixtures for one domain.
type scenario struct {
	r      *fakeRunner
	cfg    config
	dialer *fakeDialer
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

func (s *scenario) run() *Report {
	return run(context.Background(), s.cfg, s.r, s.dialer)
}

func newScenario(t *testing.T, domain, server string) *scenario {
	t.Helper()
	withResolvConf(t, "nameserver 10.12.60.1\n")
	return &scenario{r: newFakeRunner(), cfg: baseConfig(domain, server), dialer: &fakeDialer{open: map[string]bool{}}}
}

func jschmidtScenario(t *testing.T) *scenario {
	s := newScenario(t, "jschmidt.org", "")
	s.delv("jschmidt.org", "A", "delv/jschmidt_a_nxrrset.yaml", t)
	s.delv("jschmidt.org", "AAAA", "delv/jschmidt_aaaa_nxrrset.yaml", t)
	s.delv("jschmidt.org", "MX", "delv/jschmidt_mx.yaml", t)
	s.delv("jschmidt.org", "TXT", "delv/jschmidt_txt.yaml", t)
	s.delv("jschmidt.org", "NS", "delv/jschmidt_ns.yaml", t)
	s.delv("jschmidt.org", "DS", "delv/jschmidt_ds.yaml", t)
	s.delv("jschmidt.org", "DNSKEY", "delv/jschmidt_dnskey.yaml", t)
	s.delv("www.jschmidt.org", "A", "delv/www_jschmidt_a_nxrrset.yaml", t)
	s.delv("www.jschmidt.org", "AAAA", "delv/www_jschmidt_a_nxrrset.yaml", t)
	s.reach(familyIPv4, "delv/root_ns_v4.yaml", t)
	s.trace("trace/jschmidt.txt", t)
	return s
}

func TestRun_SignedDomainWithoutWeb(t *testing.T) {
	s := jschmidtScenario(t)
	rep := s.run()

	check(t, "ok", rep.OK, true)
	check(t, "errors", rep.Errors, []string{})
	check(t, "resolver", rep.Resolver, "system")
	check(t, "timeout", rep.TimeoutSec, 5)
	check(t, "quic timeout", rep.QuicTimeoutSec, 2)
	check(t, "families", rep.Families, []string{familyIPv4, familyIPv6})
	check(t, "dnssec state", rep.DNSSEC.State, DNSSECSecure)
	check(t, "delegation", rep.Delegation.Status, DelegationMatch)
	check(t, "reachability", rep.DNS.ResolverReachable, map[string]string{familyIPv4: ReachYes, familyIPv6: ReachSkipped})
	check(t, "web", rep.Web, WebSection{})
	check(t, "warnings", rep.Warnings, []string{"apex has no A or AAAA records", "www has no A or AAAA records"})
	check(t, "quicprobe calls", len(s.r.called("quicprobe")), 0)
	check(t, "dials", len(s.dialer.seen), 0)
	check(t, "bogus probe calls", len(s.r.called("dig +yaml")), 0)
	check(t, "MX trust", rep.DNS.Apex["MX"].Trust, TrustSecure)
	check(t, "NS count", len(rep.DNS.Apex["NS"].Records), 4)
}

func googleScenario(t *testing.T) *scenario {
	s := newScenario(t, "google.com", "")
	s.delv("google.com", "A", "delv/google_a_unsigned.yaml", t)
	s.delv("google.com", "AAAA", "delv/google_aaaa_unsigned.yaml", t)
	s.delv("google.com", "MX", "delv/google_mx_unsigned.yaml", t)
	s.delv("google.com", "TXT", "delv/google_txt_unsigned.yaml", t)
	s.delv("google.com", "NS", "delv/google_ns_unsigned.yaml", t)
	s.delv("google.com", "DS", "delv/google_ds_nxrrset.yaml", t)
	s.delv("google.com", "DNSKEY", "delv/google_dnskey_nxrrset.yaml", t)
	s.delv("www.google.com", "A", "delv/google_a_unsigned.yaml", t)
	s.delv("www.google.com", "AAAA", "delv/google_aaaa_unsigned.yaml", t)
	s.reach(familyIPv4, "delv/root_ns_v4.yaml", t)
	s.trace("trace/google.txt", t)
	s.r.fallback = func(tool string, args []string) (fakeCall, bool) {
		if tool == "quicprobe" {
			return fakeCall{stdout: fixture(t, "quicprobe/google_supported.json")}, true
		}
		return fakeCall{}, false
	}
	return s
}

// googleAddrs returns the apex IPv4 and IPv6 address from the fixtures.
func googleAddrs(t *testing.T) (netip.Addr, netip.Addr) {
	t.Helper()
	v4 := parseDelvYAML(fixture(t, "delv/google_a_unsigned.yaml"), "A").Addrs()[0]
	v6 := parseDelvYAML(fixture(t, "delv/google_aaaa_unsigned.yaml"), "AAAA").Addrs()[0]
	return v4, v6
}

func TestRun_WebDomainCollapsesWWW(t *testing.T) {
	s := googleScenario(t)
	v4, v6 := googleAddrs(t)
	s.dialer.open[netip.AddrPortFrom(v4, 80).String()] = true
	s.dialer.open[netip.AddrPortFrom(v4, 443).String()] = true
	s.dialer.open[netip.AddrPortFrom(v6, 443).String()] = true

	rep := s.run()
	check(t, "errors", rep.Errors, []string{})
	check(t, "warnings", rep.Warnings, []string{})
	check(t, "dnssec", rep.DNSSEC.State, DNSSECInsecure)
	check(t, "delegation", rep.Delegation.Status, DelegationMatch)
	check(t, "www collapsed", rep.Web.WWW, &HostWeb{SameAsApex: true})
	if rep.Web.Apex == nil {
		t.Fatal("apex web section missing")
	}
	assertAddrWeb(t, "ipv4", rep.Web.Apex.IPv4, v4, PortOpen, PortOpen)
	assertAddrWeb(t, "ipv6", rep.Web.Apex.IPv6, v6, PortRefused, PortOpen)
	// Each (ip, port) dialed once, QUIC once per family, no www probes.
	check(t, "dial count", len(s.dialer.seen), 4)
	calls := s.r.called("quicprobe")
	check(t, "quic call count", len(calls), 2)
	check(t, "quic v4 call", contains(calls, "-ip "+v4.String()+" -t 2 google.com"), true)
	check(t, "quic v6 call", contains(calls, "-ip "+v6.String()+" -t 2 google.com"), true)
}

// assertAddrWeb checks a one-entry family list: address, ports and that the
// QUIC result is attached and positive.
func assertAddrWeb(t *testing.T, label string, list []AddrWeb, ip netip.Addr, http, https PortState) {
	t.Helper()
	if len(list) != 1 {
		t.Fatalf("%s: expected one entry, got %+v", label, list)
	}
	a := list[0]
	check(t, label+" ip", a.IP, ip.String())
	check(t, label+" 80", a.HTTP, http)
	check(t, label+" 443", a.HTTPS, https)
	if a.QUIC == nil {
		t.Fatalf("%s: QUIC result missing", label)
	}
	check(t, label+" quic", a.QUIC.Supported, true)
}

func TestRun_FamilyRestriction(t *testing.T) {
	s := googleScenario(t)
	s.cfg.Families = []string{familyIPv4}
	rep := s.run()
	if rep.Web.Apex == nil {
		t.Fatal("apex web section missing")
	}
	check(t, "ipv6 entries", len(rep.Web.Apex.IPv6), 0)
	check(t, "ipv4 entries", len(rep.Web.Apex.IPv4), 1)
	_, hasV6 := rep.DNS.ResolverReachable[familyIPv6]
	check(t, "ipv6 reachability checked", hasV6, false)
	check(t, "dials", len(s.dialer.seen), 2)
	check(t, "quic calls", len(s.r.called("quicprobe")), 1)
	check(t, "closed-port warning", contains(rep.Warnings, "no listener on 80 or 443"), true)
}

func TestRun_WWWWithDifferentAddresses(t *testing.T) {
	s := googleScenario(t)
	s.delv("www.google.com", "A", "delv/www_isc_a_validated.yaml", t)
	s.delv("www.google.com", "AAAA", "delv/jschmidt_aaaa_nxrrset.yaml", t)
	rep := s.run()
	if rep.Web.WWW == nil {
		t.Fatal("www web section missing")
	}
	check(t, "same_as_apex", rep.Web.WWW.SameAsApex, false)
	check(t, "www ipv4 entries", len(rep.Web.WWW.IPv4), 4)
	calls := s.r.called("quicprobe")
	check(t, "quic calls (apex v4+v6, www v4)", len(calls), 3)
	check(t, "www quic call", contains(calls, "www.google.com"), true)
	check(t, "www AAAA warning", contains(rep.Warnings, "www has no AAAA"), true)
}

func TestRun_BogusZoneViaPublicResolver(t *testing.T) {
	s := newScenario(t, "dnssec-failed.org", "8.8.8.8")
	s.r.fallback = func(tool string, args []string) (fakeCall, bool) {
		if tool == "delv" && strings.Contains(strings.Join(args, " "), "dnssec-failed.org") {
			return fakeCall{stdout: fixture(t, "delv/dnssec_failed_failure.yaml")}, true
		}
		return fakeCall{}, false
	}
	s.delv("dnssec-failed.org", "DS", "delv/dnssec_failed_ds.yaml", t)
	s.reach(familyIPv4, "delv/root_ns_v4_8888.yaml", t)
	s.trace("trace/dnssec_failed_mismatch.txt", t)
	s.r.on("dig", digArgs(resolver{Host: "8.8.8.8"}, true, 5, "dnssec-failed.org", "A"), fakeCall{stdout: fixture(t, "dig/dnssec_failed_cd.yaml")})
	s.r.on("dig", digArgs(resolver{Host: "8.8.8.8"}, false, 5, "dnssec-failed.org", "A"), fakeCall{stdout: fixture(t, "dig/dnssec_failed_nocd.yaml"), err: errFake})

	rep := s.run()
	check(t, "ok", rep.OK, false)
	check(t, "dnssec state", rep.DNSSEC.State, DNSSECBogus)
	check(t, "ds", rep.DNSSEC.DS, true)
	check(t, "ede", strings.Contains(rep.DNSSEC.EDE, "DNSKEY Missing"), true)
	check(t, "delegation", rep.Delegation.Status, DelegationMismatch)
	check(t, "error count", len(rep.Errors), 2)
	check(t, "bogus error", contains(rep.Errors, "bogus"), true)
	check(t, "mismatch error", contains(rep.Errors, "mismatch"), true)
	check(t, "reachability", rep.DNS.ResolverReachable, map[string]string{familyIPv4: ReachYes, familyIPv6: ReachSkipped})
	check(t, "presence warning suppressed", contains(rep.Warnings, "no A or AAAA"), false)
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
	check(t, "elapsed set", rep.ElapsedMs > 0, true)
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
	// DS and DNSKEY are both negative answers: nothing signed at this name.
	check(t, "dnssec", rep.DNSSEC.State, DNSSECInsecure)
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
	for _, key := range []string{"domain", "resolver", "families", "timeout_sec", "tcp_timeout_sec", "quic_timeout_sec", "dns", "dnssec", "delegation", "web", "errors", "warnings", "ok", "elapsed_ms"} {
		if _, ok := generic[key]; !ok {
			t.Errorf("report missing %q", key)
		}
	}
	check(t, "internal rrs hidden", strings.Contains(string(b), `"rrs"`), false)
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

	// TXT-only name (e.g. _dmarc): a positive TXT answer is enough.
	txt := parseDelvYAML(fixture(t, "delv/dmarc_jschmidt_txt.yaml"), "TXT")
	dns := dnsResults{apex: map[string]Lookup{"NS": ns, "TXT": txt}}
	is, _ = detectNotAZone("_dmarc.jschmidt.org", dns, noDeleg)
	check(t, "TXT-only host", is, true)

	// No positive answer at all, but a SOA above the name: still a host.
	dns = dnsResults{apex: map[string]Lookup{"NS": parseDelvYAML(fixture(t, "delv/dmarc_jschmidt_ns.yaml"), "NS")}}
	is, zone = detectNotAZone("_dmarc.jschmidt.org", dns, noDeleg)
	check(t, "SOA above the name", is, true)
	check(t, "zone", zone, "jschmidt.org")

	// A SOA owned by the name itself, and nothing positive: not decided.
	self := Lookup{Status: StatusNXRRSet, rrs: []RR{{Owner: host + ".", Type: "SOA"}}}
	is, _ = detectNotAZone(host, dnsResults{apex: map[string]Lookup{"NS": ns, "AAAA": self}}, noDeleg)
	check(t, "own SOA and no data", is, false)

	// A SOA for an unrelated name is not an enclosing zone.
	other := Lookup{Status: StatusNXRRSet, rrs: []RR{{Owner: "example.net.", Type: "SOA"}}}
	is, _ = detectNotAZone(host, dnsResults{apex: map[string]Lookup{"NS": ns, "AAAA": other}}, noDeleg)
	check(t, "unrelated SOA", is, false)

	// The parent delegates the name: it is a (lame) zone, never a host.
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
	check(t, "detail explains", strings.Contains(rep.DNSSEC.Detail, "not a zone apex"), true)
	check(t, "healthy", rep.Errors, []string{})
	check(t, "ok", rep.OK, true)
	check(t, "warned once about the zone", contains(rep.Warnings, "not a zone apex (inside zone jschmidt.org)"), true)
	check(t, "no bogus probe", len(s.r.called("dig +yaml")), 0)
}

func TestRun_ResolverWithPort(t *testing.T) {
	s := newScenario(t, "jschmidt.org", "127.0.0.1:5353")
	s.r.fallback = func(tool string, args []string) (fakeCall, bool) {
		joined := strings.Join(args, " ")
		if tool == "delv" && strings.Contains(joined, "@127.0.0.1 -p 5353") {
			return fakeCall{stdout: fixture(t, "delv/jschmidt_ns.yaml")}, true
		}
		return fakeCall{}, false
	}
	s.trace("trace/jschmidt.txt", t)
	rep := s.run()
	check(t, "resolver shown with port", rep.Resolver, "127.0.0.1:5353")
	check(t, "every delv call carried the port", len(s.r.called("delv")) > 0, true)
	for _, c := range s.r.called("delv") {
		check(t, "delv call "+c, strings.Contains(c, "@127.0.0.1 -p 5353"), true)
	}
	check(t, "trace still goes to the root, no -p", strings.Contains(s.r.called("dig")[0], "-p"), false)
}

func TestRun_IDNDomainUsesALabel(t *testing.T) {
	cfg, err := parseArgs([]string{"MÜNCHEN.de."})
	if err != nil {
		t.Fatal(err)
	}
	s := newScenario(t, cfg.Domain, "")
	s.cfg.UnicodeDomain = cfg.UnicodeDomain
	s.delv("xn--mnchen-3ya.de", "A", "delv/muenchen_a.yaml", t)
	s.delv("xn--mnchen-3ya.de", "AAAA", "delv/muenchen_aaaa.yaml", t)
	s.delv("xn--mnchen-3ya.de", "NS", "delv/muenchen_ns.yaml", t)
	s.delv("xn--mnchen-3ya.de", "MX", "delv/jschmidt_aaaa_nxrrset.yaml", t)
	s.delv("xn--mnchen-3ya.de", "TXT", "delv/jschmidt_aaaa_nxrrset.yaml", t)
	s.delv("xn--mnchen-3ya.de", "DS", "delv/google_ds_nxrrset.yaml", t)
	s.delv("xn--mnchen-3ya.de", "DNSKEY", "delv/google_dnskey_nxrrset.yaml", t)
	s.delv("www.xn--mnchen-3ya.de", "A", "delv/www_muenchen_a.yaml", t)
	s.delv("www.xn--mnchen-3ya.de", "AAAA", "delv/muenchen_aaaa.yaml", t)
	s.reach(familyIPv4, "delv/root_ns_v4.yaml", t)
	s.trace("trace/muenchen.txt", t)
	s.r.fallback = func(tool string, args []string) (fakeCall, bool) {
		if tool == "quicprobe" {
			return fakeCall{stdout: fixture(t, "quicprobe/example_unsupported.json")}, true
		}
		return fakeCall{}, false
	}
	rep := s.run()
	check(t, "domain is the A-label", rep.Domain, "xn--mnchen-3ya.de")
	check(t, "unicode form reported", rep.UnicodeDomain, "münchen.de")
	check(t, "errors", rep.Errors, []string{})
	check(t, "delegation", rep.Delegation.Status, DelegationMatch)
	check(t, "www collapsed onto apex address", rep.Web.WWW, &HostWeb{SameAsApex: true})
	for _, c := range s.r.called("") {
		check(t, "no U-label reaches a tool: "+c, strings.Contains(c, "ü"), false)
	}
	for _, c := range s.r.called("quicprobe") {
		check(t, "quicprobe SNI is the A-label: "+c, strings.HasSuffix(c, " xn--mnchen-3ya.de"), true)
	}
}

func TestRun_HostInsideZoneIsNotAZone(t *testing.T) {
	host := "aelcs-com.mail.protection.outlook.com"
	s := newScenario(t, host, "")
	s.delv(host, "A", "delv/outlook_host_a.yaml", t)
	s.delv(host, "AAAA", "delv/outlook_host_aaaa.yaml", t)
	s.delv(host, "NS", "delv/outlook_host_ns_nxrrset.yaml", t)
	s.delv(host, "MX", "delv/outlook_host_mx_nxrrset.yaml", t)
	s.delv(host, "TXT", "delv/outlook_host_txt_failure.yaml", t)
	s.delv(host, "DS", "delv/outlook_host_ns_nxrrset.yaml", t)
	s.delv(host, "DNSKEY", "delv/outlook_host_ns_nxrrset.yaml", t)
	s.delv("www."+host, "A", "delv/nxdomain_unsigned.yaml", t)
	s.delv("www."+host, "AAAA", "delv/nxdomain_unsigned.yaml", t)
	s.reach(familyIPv4, "delv/root_ns_v4.yaml", t)
	s.r.on("dig", traceArgs(familyIPv4, 5, host), fakeCall{stdout: fixture(t, "trace/nxdomain.txt")})
	s.r.fallback = func(tool string, args []string) (fakeCall, bool) {
		if tool == "quicprobe" {
			return fakeCall{stdout: fixture(t, "quicprobe/example_unsupported.json")}, true
		}
		return fakeCall{}, false
	}
	rep := s.run()
	check(t, "not_a_zone", rep.NotAZone, true)
	check(t, "delegation", rep.Delegation.Status, DelegationNotAZone)
	check(t, "dnssec from answer trust", rep.DNSSEC.State, DNSSECInsecure)
	check(t, "no bogus probe for a non-zone", len(s.r.called("dig +yaml")), 0)
	check(t, "only the TXT failure remains an error", rep.Errors, []string{"apex TXT lookup failed: delv: resolution failed"})
	check(t, "not-a-zone warning", contains(rep.Warnings, "is not a zone apex"), true)
	check(t, "no 'no NS' error", contains(rep.Errors, "no NS records"), false)
}
