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
	for _, st := range []string{DelegationNotDelegated, DelegationNoChildAnswer, DelegationError} {
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
	if !contains(rep.Warnings, "no listener on 80 or 443 (refused/timeout)") || !contains(rep.Warnings, "QUIC/h3 works on another address") {
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
