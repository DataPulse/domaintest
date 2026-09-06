package main

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
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
	check(t, "chain error", contains(rep.Errors, "apex "+v4.String()+": certificate self signed: self-signed certificate"), true)
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
