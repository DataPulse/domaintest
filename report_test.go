package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

func healthyReport(t *testing.T) *Report {
	t.Helper()
	apex := lookups(t, map[string]string{
		"A": "delv/google_a_unsigned.yaml", "AAAA": "delv/google_aaaa_unsigned.yaml",
		"MX": "delv/google_mx_unsigned.yaml", "TXT": "delv/google_txt_unsigned.yaml", "NS": "delv/google_ns_unsigned.yaml",
	})
	www := lookups(t, map[string]string{"A": "delv/google_a_unsigned.yaml", "AAAA": "delv/google_aaaa_unsigned.yaml"})
	blocks, _ := parseTrace(fixture(t, "trace/google.txt"))
	v4, v6 := apex["A"].Addrs()[0], apex["AAAA"].Addrs()[0]
	ports := map[portKey]PortState{
		{v4, 80}: PortOpen, {v4, 443}: PortOpen, {v6, 80}: PortOpen, {v6, 443}: PortOpen,
	}
	quic := map[string]*QUICResult{v4.String(): {Supported: true, ALPN: "h3"}, v6.String(): {Supported: true, ALPN: "h3"}}
	return &Report{
		Domain:     "google.com",
		DNS:        DNSSection{Apex: apex, WWW: www, ResolverReachable: map[string]string{familyIPv4: ReachYes, familyIPv6: ReachSkipped}},
		DNSSEC:     DNSSECReport{State: DNSSECInsecure},
		Delegation: compareDelegation(blocks, nil, "google.com"),
		Web:        WebSection{Apex: hostWeb([]netip.Addr{v4, v6}, ports, quic), WWW: &HostWeb{SameAsApex: true}},
	}
}

func TestBuildFindings_Healthy(t *testing.T) {
	rep := healthyReport(t)
	buildFindings(rep)
	if !rep.OK || len(rep.Errors) != 0 || len(rep.Warnings) != 0 {
		t.Errorf("healthy report should be clean: errors %v warnings %v", rep.Errors, rep.Warnings)
	}
	out, _ := json.Marshal(rep)
	if !strings.Contains(string(out), `"errors":[]`) || !strings.Contains(string(out), `"warnings":[]`) {
		t.Errorf("empty lists must serialise as [] not null: %s", out)
	}
}

func TestBuildFindings_DNSWarnings(t *testing.T) {
	rep := healthyReport(t)
	rep.DNS.Apex["AAAA"] = parseDelvYAML(fixture(t, "delv/jschmidt_aaaa_nxrrset.yaml"), "AAAA")
	rep.DNS.Apex["MX"] = parseDelvYAML(fixture(t, "delv/jschmidt_aaaa_nxrrset.yaml"), "MX")
	rep.DNS.Apex["TXT"] = parseDelvYAML(fixture(t, "delv/jschmidt_aaaa_nxrrset.yaml"), "TXT")
	rep.DNS.WWW["A"] = parseDelvYAML(fixture(t, "delv/nxdomain_signed.yaml"), "A")
	rep.DNS.WWW["AAAA"] = parseDelvYAML(fixture(t, "delv/nxdomain_signed.yaml"), "AAAA")
	buildFindings(rep)
	if !rep.OK {
		t.Errorf("warnings only, expected ok: %v", rep.Errors)
	}
	for _, want := range []string{"apex has no AAAA", "www name does not exist", "no MX", "no SPF"} {
		if !contains(rep.Warnings, want) {
			t.Errorf("missing warning %q in %v", want, rep.Warnings)
		}
	}
}

func TestBuildFindings_NXDomainApex(t *testing.T) {
	rep := healthyReport(t)
	for _, tt := range apexTypes {
		rep.DNS.Apex[tt] = parseDelvYAML(fixture(t, "delv/nxdomain_signed.yaml"), tt)
	}
	buildFindings(rep)
	if rep.OK || !contains(rep.Errors, "NXDOMAIN") {
		t.Errorf("expected NXDOMAIN error, got %v", rep.Errors)
	}
	if contains(rep.Warnings, "no A or AAAA") {
		t.Errorf("presence warnings are noise for a missing domain: %v", rep.Warnings)
	}
}

func TestBuildFindings_LookupFailuresAndBogus(t *testing.T) {
	rep := healthyReport(t)
	rep.DNS.Apex["A"] = parseDelvYAML(fixture(t, "delv/timeout.yaml"), "A")
	rep.DNS.Apex["MX"] = parseDelvYAML(fixture(t, "delv/dnssec_failed_failure.yaml"), "MX")
	buildFindings(rep)
	if !contains(rep.Errors, "apex A lookup timed out") || !contains(rep.Errors, "apex MX lookup failed") {
		t.Errorf("expected timeout and failure errors, got %v", rep.Errors)
	}
	if contains(rep.Warnings, "no A or AAAA") {
		t.Errorf("failed lookups must not produce presence warnings: %v", rep.Warnings)
	}

	// With a bogus DNSSEC state the per-lookup failures are folded into one error.
	rep = healthyReport(t)
	rep.DNS.Apex["MX"] = parseDelvYAML(fixture(t, "delv/dnssec_failed_failure.yaml"), "MX")
	rep.DNSSEC = DNSSECReport{State: DNSSECBogus, EDE: "9 (DNSKEY Missing): x"}
	buildFindings(rep)
	if len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0], "bogus") || !strings.Contains(rep.Errors[0], "DNSKEY Missing") {
		t.Errorf("expected a single bogus error, got %v", rep.Errors)
	}
}

func TestBuildFindings_DNSSECStates(t *testing.T) {
	cases := []struct {
		state   DNSSECState
		isError bool
		text    string
	}{
		{DNSSECServfail, true, "SERVFAIL"},
		{DNSSECIsland, false, "DNSSEC"},
		{DNSSECUnknown, false, "unknown"},
		{DNSSECSecure, false, ""},
	}
	for _, c := range cases {
		rep := healthyReport(t)
		rep.DNSSEC = DNSSECReport{State: c.state, Detail: "detail"}
		buildFindings(rep)
		list := rep.Warnings
		if c.isError {
			list = rep.Errors
		}
		if c.text != "" && !contains(list, c.text) {
			t.Errorf("%s: expected %q in %v", c.state, c.text, list)
		}
		if c.text == "" && (len(rep.Errors)+len(rep.Warnings)) != 0 {
			t.Errorf("%s: unexpected findings %v %v", c.state, rep.Errors, rep.Warnings)
		}
	}
}

func TestBuildFindings_Delegation(t *testing.T) {
	blocks, _ := parseTrace(fixture(t, "trace/dnssec_failed_mismatch.txt"))
	rep := healthyReport(t)
	rep.Delegation = compareDelegation(blocks, nil, "dnssec-failed.org")
	buildFindings(rep)
	if rep.OK || !contains(rep.Errors, "NS delegation mismatch") || !contains(rep.Errors, "dns102.comcast.net.") {
		t.Errorf("expected mismatch error naming the extra servers, got %v", rep.Errors)
	}
	rep = healthyReport(t)
	rep.Delegation = Delegation{Status: DelegationSameServers}
	buildFindings(rep)
	check(t, "same_servers is not an error", rep.Errors, []string{})
	for _, st := range []string{DelegationNotDelegated, DelegationNoChildAnswer, DelegationError, DelegationChildNoNS} {
		rep := healthyReport(t)
		rep.Delegation = Delegation{Status: st, Error: "detail"}
		buildFindings(rep)
		if rep.OK || len(rep.Errors) != 1 {
			t.Errorf("%s: expected one error, got %v", st, rep.Errors)
		}
	}
}

func TestBuildFindings_ReachabilityAndWeb(t *testing.T) {
	rep := healthyReport(t)
	rep.DNS.ResolverReachable[familyIPv6] = ReachNo
	buildFindings(rep)
	if !contains(rep.Errors, "not reachable over ipv6") {
		t.Errorf("got %v", rep.Errors)
	}

	rep = healthyReport(t)
	a := &rep.Web.Apex.IPv4[0]
	a.HTTP, a.HTTPS = PortRefused, PortTimeout
	b := &rep.Web.Apex.IPv6[0]
	b.QUIC = &QUICResult{Supported: false, Error: "CRYPTO_ERROR"}
	buildFindings(rep)
	if !rep.OK {
		t.Errorf("web problems are warnings: %v", rep.Errors)
	}
	if !contains(rep.Warnings, "no listener on 80 or 443 (refused/timeout)") || !contains(rep.Warnings, "QUIC/h3 works on another probed address") {
		t.Errorf("got %v", rep.Warnings)
	}

	// No address supports QUIC: that is the common case and not a warning.
	rep = healthyReport(t)
	rep.Web.Apex.IPv4[0].QUIC = &QUICResult{Error: "context deadline exceeded"}
	rep.Web.Apex.IPv6[0].QUIC = &QUICResult{Error: "context deadline exceeded"}
	buildFindings(rep)
	check(t, "no QUIC warnings without asymmetry", rep.Warnings, []string{})

	// www with its own addresses is reported under its own label.
	rep = healthyReport(t)
	ip := netip.MustParseAddr("192.0.2.5")
	rep.Web.WWW = hostWeb([]netip.Addr{ip}, map[portKey]PortState{{ip, 80}: PortRefused, {ip, 443}: PortRefused}, nil)
	buildFindings(rep)
	if !contains(rep.Warnings, "www 192.0.2.5: no listener") {
		t.Errorf("got %v", rep.Warnings)
	}
}

func TestHostWeb(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.1")
	v6 := netip.MustParseAddr("2001:db8::1")
	ports := map[portKey]PortState{{v4, 80}: PortOpen, {v4, 443}: PortRefused, {v6, 80}: PortTimeout, {v6, 443}: PortOpen}
	quic := map[string]*QUICResult{v6.String(): {Supported: true}}
	h := hostWeb([]netip.Addr{v4, v6, v4}, ports, quic)
	if len(h.IPv4) != 1 || len(h.IPv6) != 1 {
		t.Fatalf("duplicates should collapse: %+v", h)
	}
	check(t, "ipv4", h.IPv4[0], AddrWeb{IP: "192.0.2.1", HTTP: PortOpen, HTTPS: PortRefused})
	check(t, "ipv6", h.IPv6[0], AddrWeb{IP: "2001:db8::1", HTTP: PortTimeout, HTTPS: PortOpen, QUIC: quic[v6.String()]})
	check(t, "no addresses", hostWeb(nil, ports, quic), (*HostWeb)(nil))
	out, _ := json.Marshal(h)
	check(t, "80 key", strings.Contains(string(out), `"80":"open"`), true)
	check(t, "443 key", strings.Contains(string(out), `"443":"refused"`), true)
}

func TestSameAddressSet(t *testing.T) {
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("2001:db8::1")
	mapped := netip.MustParseAddr("::ffff:192.0.2.1")
	if !sameAddressSet([]netip.Addr{a, b}, []netip.Addr{b, mapped}) {
		t.Error("order and v4-mapped form should not matter")
	}
	if sameAddressSet([]netip.Addr{a}, []netip.Addr{a, b}) || sameAddressSet([]netip.Addr{a}, []netip.Addr{b}) {
		t.Error("different sets reported equal")
	}
	if !sameAddressSet(nil, nil) {
		t.Error("two empty sets are equal")
	}
}

func TestHelpers(t *testing.T) {
	if firstNonEmpty("", "", "x", "y") != "x" || firstNonEmpty() != "" {
		t.Error("firstNonEmpty")
	}
	if got := sortedKeys(map[string]string{"b": "", "a": ""}); len(got) != 2 || got[0] != "a" {
		t.Errorf("sortedKeys %v", got)
	}
	if !hasSPF([]string{"x", "  V=SPF1 -all"}) || hasSPF([]string{"spf1"}) || hasSPF(nil) {
		t.Error("hasSPF")
	}
}

func TestBuildFindings_HTTPSDownWhileHTTPUp(t *testing.T) {
	rep := healthyReport(t)
	for i := range rep.Web.Apex.IPv4 {
		rep.Web.Apex.IPv4[i].HTTPS = PortTimeout
		rep.Web.Apex.IPv4[i].QUIC = nil
	}
	rep.Web.Apex.IPv6[0].QUIC = nil
	buildFindings(rep)
	check(t, "still ok (warning only)", rep.OK, true)
	check(t, "https warning", contains(rep.Warnings, "HTTP on 80 answers but HTTPS on 443 does not (timeout)"), true)
	check(t, "no both-closed warning", contains(rep.Warnings, "no listener"), false)
	check(t, "single warning", len(rep.Warnings), 1)
}

func TestBuildFindings_LameZoneReportedOnce(t *testing.T) {
	rep := healthyReport(t)
	rep.DNS.Apex["NS"] = parseDelvYAML(fixture(t, "delv/jschmidt_aaaa_nxrrset.yaml"), "NS")
	rep.Delegation = Delegation{Status: DelegationChildNoNS, Error: "zone at ns1.example has a SOA but no NS records"}
	buildFindings(rep)
	check(t, "single lame-delegation error", rep.Errors, []string{"lame delegation: zone at ns1.example has a SOA but no NS records"})
}

func TestBuildFindings_NullMXAndNotAZone(t *testing.T) {
	rep := healthyReport(t)
	rep.DNS.Apex["MX"] = parseDelvYAML(fixture(t, "delv/microsoft_jp_net_null_mx.yaml"), "MX")
	buildFindings(rep)
	check(t, "null MX warning", contains(rep.Warnings, "null MX"), true)
	check(t, "no 'no MX' warning", contains(rep.Warnings, "no MX records"), false)
	check(t, "still ok", rep.OK, true)

	rep = healthyReport(t)
	rep.Domain = "host.example.net"
	rep.NotAZone, rep.EnclosingZone = true, "example.net"
	rep.DNS.Apex["NS"] = parseDelvYAML(fixture(t, "delv/outlook_host_ns_nxrrset.yaml"), "NS")
	rep.Delegation = Delegation{Status: DelegationNotAZone}
	buildFindings(rep)
	check(t, "ok", rep.OK, true)
	check(t, "warning names the zone", contains(rep.Warnings, "not a zone apex (inside zone example.net)"), true)
	check(t, "no NS error", contains(rep.Errors, "no NS"), false)

	rep.EnclosingZone = ""
	buildFindings(rep)
	check(t, "warning without zone", contains(rep.Warnings, "host.example.net is not a zone apex: delegation"), true)
}

func TestTLSFindings_Aggregation(t *testing.T) {
	rep := healthyReport(t)
	v4, v6 := googleAddrs(t)
	valid := &CertInfo{DaysRemaining: 60, CoversApex: true, CoversWWW: false}
	rep.Web.Apex.IPv4[0].TLS = &TLSResult{Chain: ChainValid, Version: "TLS 1.2", TLS10: true, Cert: valid}
	rep.Web.Apex.IPv6[0].TLS = &TLSResult{Chain: ChainValid, Version: "TLS 1.3", TLS11: true, Cert: &CertInfo{DaysRemaining: 10, CoversApex: true, CoversWWW: false}}
	rep.Web.WWW = hostWeb([]netip.Addr{v4, v6}, map[portKey]PortState{{v4, 443}: PortOpen}, nil) // resolves, no cert
	buildFindings(rep)
	check(t, "ok", rep.OK, true)
	for _, want := range []string{
		"apex: TLS 1.0/1.1 still accepted on 1 of 2 addresses",
		"apex: no TLS 1.3 on 1 of 2 addresses",
		"apex: certificate expires in 10 days",
		"apex: certificate does not cover www, which resolves but has no valid certificate",
	} {
		check(t, want, contains(rep.Warnings, want), true)
	}
	// Once www has its own valid certificate the coverage warning goes away.
	rep.Web.WWW.IPv4[0].TLS = &TLSResult{Chain: ChainValid, Version: "TLS 1.3", Cert: &CertInfo{DaysRemaining: 90, CoversWWW: true}}
	buildFindings(rep)
	check(t, "no coverage warning", contains(rep.Warnings, "does not cover"), false)
	// Urgent expiry wording and per-address chain errors.
	rep.Web.Apex.IPv6[0].TLS.Cert.DaysRemaining = 3
	rep.Web.Apex.IPv4[0].TLS = &TLSResult{Chain: ChainSelfSigned, Error: "self-signed certificate", Cert: valid}
	buildFindings(rep)
	check(t, "urgent", contains(rep.Warnings, "certificate expires in 3 days (urgent)"), true)
	check(t, "chain error names the count, not the address", contains(rep.Errors, "apex: certificate self signed on 1 of 2 addresses: self-signed certificate"), true)
	check(t, "not ok", rep.OK, false)
}

func TestHTTPFindings_Aggregation(t *testing.T) {
	rep := healthyReport(t)
	a := &rep.Web.Apex.IPv4[0]
	b := &rep.Web.Apex.IPv6[0]
	a.HTTPRes = &HTTPResult{Status: 200}
	b.HTTPRes = &HTTPResult{Status: 302, Location: "http://www.google.com/"}
	a.HTTPSRes = &HTTPResult{Status: 503, HSTS: &HSTS{MaxAge: 100}}
	b.HTTPSRes = &HTTPResult{Status: 503, HSTS: &HSTS{MaxAge: 99999999}}
	rep.Web.Apex.Redirects = map[string]*RedirectChain{
		familyIPv4: {Hops: []RedirectHop{{"http://google.com/", 302}, {"https://google.com/", 404}}, FinalURL: "https://google.com/"},
		familyIPv6: {Loop: true, Hops: []RedirectHop{{"http://google.com/", 302}, {"http://www.google.com/", 302}}},
	}
	buildFindings(rep)
	check(t, "5xx everywhere is an error", contains(rep.Errors, "apex: every address returns a server error on port 443"), true)
	check(t, "cleartext once", contains(rep.Warnings, "apex: HTTP serves content in the clear instead of redirecting to HTTPS (1 of 2 addresses)"), true)
	check(t, "non-https redirect", contains(rep.Warnings, "apex: HTTP redirects to a non-HTTPS URL (1 of 2 addresses)"), true)
	check(t, "shortest hsts", contains(rep.Warnings, "apex: HSTS max-age 100 is under 180 days"), true)
	check(t, "chain ends 404", contains(rep.Warnings, "apex (ipv4): redirect chain ends in HTTP 404"), true)
	check(t, "loop", contains(rep.Errors, "apex (ipv6): redirect loop http://google.com/ (302) -> http://www.google.com/ (302)"), true)
	rep.Web.Apex.IPv6[0].HTTPSRes.Status = 200
	buildFindings(rep)
	check(t, "partial 5xx is a warning", contains(rep.Warnings, "apex: 1 of 2 addresses return a server error on port 443"), true)
}

func TestServerFindings_AggregatePerName(t *testing.T) {
	var f findings
	f.serverFindings([]NSServer{
		{Name: "a.ns.", IP: "192.0.2.1", AA: false, Error: "not authoritative (REFUSED)"},
		{Name: "a.ns.", IP: "2001:db8::1", AA: false, Error: "not authoritative (REFUSED)"},
		{Name: "a.ns.", IP: "192.0.2.2", AA: true, TCP: true, EDNS: true},
		{Name: "b.ns.", IP: "192.0.2.3", AA: true, TCP: false, EDNS: false},
	})
	check(t, "one error for a.ns.", f.errors, []string{"nameserver a.ns.: not authoritative (REFUSED) on 2 of 3 addresses"})
	check(t, "warnings for b.ns.", f.warnings, []string{"nameserver b.ns. (192.0.2.3): no answer over TCP", "nameserver b.ns. (192.0.2.3): no EDNS support"})
}

// A server that answered and disclaimed authority is proof of lameness at
// any count. A server that never answered proves nothing on its own: one
// silent address behind an authoritative quorum is a flaky node, and only a
// name that is silent on every address is a broken delegation.
func TestServerFindings_SilentIsNotLame(t *testing.T) {
	// One address of two never answers; the other is authoritative.
	var flaky findings
	flaky.serverFindings([]NSServer{
		{Name: "ns01.example.", IP: "192.0.2.1", AA: true, TCP: true, EDNS: true},
		{Name: "ns01.example.", IP: "2001:db8::1", Error: "dig timed out"},
	})
	check(t, "no error for a flaky node", flaky.errors, []string(nil))
	check(t, "warned instead", flaky.warnings, []string{"nameserver ns01.example.: no answer on 1 of 2 addresses, the others are authoritative"})

	// Every address of the name is silent: the name is unreachable.
	var dead findings
	dead.serverFindings([]NSServer{
		{Name: "gone.example.", IP: "192.0.2.1", Error: "dig timed out"},
		{Name: "gone.example.", IP: "192.0.2.2", Error: "no servers could be reached"},
	})
	check(t, "whole name unreachable is an error", dead.errors, []string{"nameserver gone.example.: no answer on 2 of 2 addresses"})
	check(t, "and not also a warning", dead.warnings, []string(nil))

	// Answering REFUSED on one address of nine is still proof.
	var lame findings
	servers := []NSServer{{Name: "ns1.example.", IP: "192.0.2.1", Error: "not authoritative (REFUSED)"}}
	for i := 2; i <= 9; i++ {
		servers = append(servers, NSServer{Name: "ns1.example.", IP: fmt.Sprintf("192.0.2.%d", i), AA: true, TCP: true, EDNS: true})
	}
	lame.serverFindings(servers)
	check(t, "lameness is never demoted", lame.errors, []string{"nameserver ns1.example.: not authoritative (REFUSED) on 1 of 9 addresses"})

	// Both kinds on one name are two distinct facts, reported separately.
	var both findings
	both.serverFindings([]NSServer{
		{Name: "mix.example.", IP: "192.0.2.1", Error: "not authoritative (REFUSED)"},
		{Name: "mix.example.", IP: "192.0.2.2", Error: "dig timed out"},
		{Name: "mix.example.", IP: "192.0.2.3", AA: true, TCP: true, EDNS: true},
	})
	check(t, "lame reported", both.errors, []string{"nameserver mix.example.: not authoritative (REFUSED) on 1 of 3 addresses"})
	check(t, "silent reported too", both.warnings, []string{"nameserver mix.example.: no answer on 1 of 3 addresses, the others are authoritative"})
}

func TestBuildFindings_ServfailFoldsLookupFailures(t *testing.T) {
	rep := healthyReport(t)
	for _, tt := range apexTypes {
		rep.DNS.Apex[tt] = parseDelvYAML(fixture(t, "delv/dnssec_failed_failure.yaml"), tt)
	}
	rep.DNSSEC = DNSSECReport{State: DNSSECServfail, Detail: "resolver failed"}
	buildFindings(rep)
	check(t, "single servfail error", contains(rep.Errors, "resolver returned SERVFAIL"), true)
	check(t, "lookup failures folded", contains(rep.Errors, "lookup failed"), false)
}

func TestConventions_ArraysAndBooleansAlwaysPresent(t *testing.T) {
	lookup := indexLookup(t)
	rep := healthyReport(t)
	rep.Mail = &MailReport{DMARC: parseDMARC(Lookup{}), SPF: evaluateSPF("x", Lookup{}, lookup), MX: checkMX(Lookup{}, lookup), DKIM: probeDKIM("x", lookup), MTASTS: checkMTASTS(context.Background(), "x", Lookup{}, nil, time.Second, lookup)}
	w := assessWildcard(nil, "", Lookup{}, Lookup{})
	rep.Wildcard = &w
	rep.TLSA = assessTLSA(Lookup{}, Lookup{}, rep.Web)
	c := assessCAA(Lookup{}, Lookup{}, servedCert{}, servedCert{})
	rep.CAA = &c
	n := resolveNS(nil, lookup)
	rep.Nameservers = &n
	rep.Families = []string{familyIPv4}
	buildFindings(rep) // sets errors/warnings, as every real run does
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	// Arrays and plain booleans are always present and never null. The
	// only keys allowed to be null are the aggregates computed over a set
	// of examined servers: with nothing examined they are unknown, and
	// null is how they say so rather than reporting a vacuous pass.
	unknownable := map[string]bool{"serials_consistent": true, "ipv4_prefixes_24": true, "ipv6_prefixes_48": true, "consistent": true}
	var seen []string
	for _, m := range regexp.MustCompile(`"([a-z_0-9]+)":null`).FindAllStringSubmatch(out, -1) {
		if !unknownable[m[1]] {
			t.Errorf("unexpected null value for key %q", m[1])
		}
		seen = append(seen, m[1])
	}
	sort.Strings(seen)
	check(t, "empty aggregates report unknown", seen, []string{"consistent", "ipv4_prefixes_24", "ipv6_prefixes_48", "serials_consistent"})
	for _, want := range []string{`"selectors_found":[]`, `"revoked":[]`, `"includes":[]`, `"problems":[]`, `"mx":[]`, `"addresses":[]`, `"www_via_wildcard":false`, `"signed":false`, `"hosts":{`, `"published":[]`, `"effective":[]`, `"servers":[]`, `"ns_cname":[]`, `"unresolvable":[]`, `"unresolved":[]`, `"probes":[]`, `"pct":100`} {
		check(t, "present: "+want, strings.Contains(out, want), true)
	}
	check(t, "glue absent when nothing was checkable", strings.Contains(out, `"glue"`), false)
}

func TestSerialList_NamesTheAddress(t *testing.T) {
	got := serialList([]NSServer{
		{Name: "ns1.example.", IP: "192.0.2.1", AA: true, Serial: 9957},
		{Name: "ns1.example.", IP: "2001:db8::1", AA: true, Serial: 9958},
		{Name: "ns2.example.", IP: "192.0.2.2", AA: false, Serial: 1}, // lame: excluded
	})
	check(t, "one entry per address, with the address", got, "ns1.example.(192.0.2.1)=9957, ns1.example.(2001:db8::1)=9958")
	check(t, "no authoritative servers", serialList([]NSServer{{Name: "x.", AA: false}}), "")
}

// An audit that reached nothing must warn about the gap and must not claim
// the names have no address or that their serials agree.
func TestNSFindings_UnansweredIsAGapNotAFault(t *testing.T) {
	f := &findings{}
	f.nsFindings(&NSReport{Count: 2, Servers: []NSServer{}, Unresolvable: []string{}, Unresolved: []string{"ns1.example.", "ns2.example."}})
	check(t, "no errors", f.errors, []string(nil))
	check(t, "gap reported", contains(f.warnings, "did not complete"), true)
	check(t, "audit gap reported", contains(f.warnings, "none of the per-server checks ran"), true)
	check(t, "no serial claim", contains(f.warnings, "SOA serial"), false)
	check(t, "no diversity claim", contains(f.warnings, "share one"), false)

	// A denial is still an error.
	g := &findings{}
	g.nsFindings(&NSReport{Count: 2, Servers: []NSServer{}, Unresolved: []string{}, Unresolvable: []string{"ns1.example."}})
	check(t, "denial errors", contains(g.errors, "has no address"), true)
}

// A CDN fleet failing the same way is one fact, not one per address. The
// count carries the scale and the web section carries the detail.
func TestChainFindings_OnePerCondition(t *testing.T) {
	f := &findings{}
	fail := func(ip, chain, detail string) AddrWeb {
		return AddrWeb{IP: ip, TLS: &TLSResult{Chain: chain, Error: detail}}
	}
	f.chainFindings("apex", []AddrWeb{
		fail("3.5.88.34", ChainHandshakeFailed, "read: connection reset by peer"),
		fail("3.5.88.64", ChainHandshakeFailed, "read: connection reset by peer"),
		fail("3.5.91.76", ChainHandshakeFailed, "read: connection reset by peer"),
		fail("3.5.92.124", ChainExpired, "certificate has expired"),
		{IP: "3.5.99.1", TLS: &TLSResult{Chain: ChainValid}},
	})
	check(t, "one finding per distinct cause", f.errors, []string{
		"apex: certificate handshake failed on 3 of 5 addresses: read: connection reset by peer",
		"apex: certificate expired on 1 of 5 addresses: certificate has expired",
	})

	// A clean fleet says nothing.
	g := &findings{}
	g.chainFindings("www", []AddrWeb{{IP: "1.2.3.4", TLS: &TLSResult{Chain: ChainValid}}})
	check(t, "silent when valid", g.errors, []string(nil))
}

// NOERROR with an empty answer is an answer. Reporting it as "did not
// respond" sends an operator after a reachability problem that does not
// exist, and the missing apex NS RRset must be counted once, not twice.
func TestDelegationFindings_NoDataIsAnAnswer(t *testing.T) {
	rep := &Report{
		Domain:     "revoked.example",
		Delegation: Delegation{Status: DelegationNoChildAnswer, ParentServer: "a.gtld-servers.net"},
		DNS: DNSSection{
			Apex: map[string]Lookup{"NS": {Status: StatusNXRRSet}},
			WWW:  map[string]Lookup{},
		},
	}
	buildFindings(rep)
	check(t, "says the servers answered", contains(rep.Errors, "answered with no NS records (NODATA)"), true)
	check(t, "not called unresponsive", contains(rep.Errors, "did not answer"), false)
	check(t, "counted once", len(rep.Errors), 1)
	check(t, "not also an apex-NS error", contains(rep.Errors, "apex has no NS records"), false)

	// A genuinely silent server still reads as silent.
	rep.DNS.Apex["NS"] = Lookup{Status: StatusTimeout}
	rep.Delegation.Error = "communications error to 192.0.2.1#53: timed out"
	buildFindings(rep)
	check(t, "silence still reported as silence", contains(rep.Errors, "did not answer the NS query"), true)
}

// A loop provably never resolves. Running out of hops only means the
// follower stopped, so the destination is unknown and asserting a fault
// from it is the vacuous negative in another guise.
func TestRedirectFindings_HopLimitIsNotALoop(t *testing.T) {
	hops := []RedirectHop{{URL: "http://x.example/", Status: 301}, {URL: "http://x.example/a", Status: 301}}

	var limit findings
	limit.redirectFindings("apex", map[string]*RedirectChain{
		familyIPv4: {Hops: hops, Ended: RedirectHopLimit, Error: "more than 10 redirects"},
	})
	check(t, "not an error", limit.errors, []string(nil))
	check(t, "warned as unknown", contains(limit.warnings, "still redirecting after 2 hops, so the destination is unknown"), true)

	var loop findings
	loop.redirectFindings("apex", map[string]*RedirectChain{
		familyIPv4: {Hops: hops, Ended: RedirectLoop, Loop: true},
	})
	check(t, "a loop is still an error", contains(loop.errors, "redirect loop"), true)

	// A chain that reached an external host is finished, and silent.
	var ext findings
	ext.redirectFindings("apex", map[string]*RedirectChain{
		familyIPv4: {Hops: hops, Ended: RedirectExternal, External: "https://elsewhere.example/"},
	})
	check(t, "external is not a finding", []int{len(ext.errors), len(ext.warnings)}, []int{0, 0})
}

// A preloaded domain serving no HSTS header at all is a different fault
// from one serving a header that falls short, and the fixes differ.
func TestPreloadFindings_NoHeaderVersusWeakHeader(t *testing.T) {
	withHSTS := func(h *HSTS) *Report {
		return &Report{
			HSTSPreload: PreloadPreloaded,
			Web:         WebSection{Apex: &HostWeb{IPv4: []AddrWeb{{IP: "192.0.2.1", HTTPSRes: &HTTPResult{Status: 200, HSTS: h}}}}},
		}
	}
	var none findings
	none.preloadFindings(withHSTS(nil))
	check(t, "no header", contains(none.warnings, "serves no HSTS header on this response"), true)
	check(t, "does not imply one was served", contains(none.warnings, "does not meet"), false)

	var weak findings
	weak.preloadFindings(withHSTS(&HSTS{MaxAge: 300}))
	check(t, "weak header", contains(weak.warnings, "the served header does not meet the preload requirements"), true)

	var good findings
	good.preloadFindings(withHSTS(&HSTS{MaxAge: preloadMinAge, IncludeSubdomains: true, Preload: true}))
	check(t, "a compliant header is silent", good.warnings, []string(nil))
}

// A name that does not exist must get the same verdict however its parent
// zone chooses to deny it. Signed zones using compact denial of existence
// answer NODATA rather than admitting a name is absent, so the verdict
// would otherwise follow the phrasing of the denial rather than the fact.
func TestDNSFindings_ComparableDenials(t *testing.T) {
	section := func(st LookupStatus) DNSSection {
		apex := map[string]Lookup{}
		for _, ty := range apexTypes {
			apex[ty] = Lookup{Status: st}
		}
		return DNSSection{Apex: apex, WWW: map[string]Lookup{}}
	}

	nx := &Report{Domain: "nosuchhost.example.com", DNS: section(StatusNXDomain)}
	buildFindings(nx)
	check(t, "nxdomain fails", nx.OK, false)
	check(t, "one fact", nx.Errors, []string{"apex nosuchhost.example.com does not exist (NXDOMAIN)"})

	// The same name behind a zone that answers NODATA for everything.
	nodata := &Report{Domain: "nosuchhost.example.com", NotAZone: true, EnclosingZone: "example.com", DNS: section(StatusNXRRSet)}
	buildFindings(nodata)
	check(t, "compact denial fails too", nodata.OK, false)
	check(t, "and says what it found", nodata.Errors, []string{"apex nosuchhost.example.com has no records of any type"})
	check(t, "without restating it per type", nodata.Warnings, []string{})

	// One record of any type means the name exists and is judged normally.
	live := &Report{Domain: "mail.example.com", NotAZone: true, DNS: section(StatusNXRRSet)}
	live.DNS.Apex["MX"] = Lookup{Status: StatusOK, Records: []string{"10 mx.example.com."}}
	buildFindings(live)
	check(t, "a mail-only host is not empty", contains(live.Errors, "no records of any type"), false)

	// A lookup that never answered must not be read as an empty name.
	unresolved := &Report{Domain: "x.example.com", DNS: section(StatusTimeout)}
	buildFindings(unresolved)
	check(t, "silence is not emptiness", contains(unresolved.Errors, "no records of any type"), false)
}

// A host that served no response on 443 cannot be said to serve no HSTS
// header: there was no response to carry one.
func TestPreloadFindings_NoResponseIsNotAMissingHeader(t *testing.T) {
	var f findings
	f.preloadFindings(&Report{HSTSPreload: PreloadPreloaded, Web: WebSection{}})
	check(t, "silent when nothing answered", f.warnings, []string(nil))

	var g findings
	g.preloadFindings(&Report{HSTSPreload: PreloadPreloaded,
		Web: WebSection{Apex: &HostWeb{IPv4: []AddrWeb{{IP: "192.0.2.1", HTTPSRes: &HTTPResult{Status: 200}}}}}})
	check(t, "reported when a response carried none", contains(g.warnings, "serves no HSTS header"), true)
}
