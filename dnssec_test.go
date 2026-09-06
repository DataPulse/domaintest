package main

import (
	"context"
	"strings"
	"testing"
)

func lookups(t *testing.T, files map[string]string) map[string]Lookup {
	t.Helper()
	out := map[string]Lookup{}
	for qtype, file := range files {
		l := parseDelvYAML(fixture(t, file), qtype)
		l.Name = "test"
		out[qtype] = l
	}
	return out
}

func TestClassifyDNSSEC_Secure(t *testing.T) {
	apex := lookups(t, map[string]string{
		"A": "delv/jschmidt_a_nxrrset.yaml", "AAAA": "delv/jschmidt_aaaa_nxrrset.yaml",
		"MX": "delv/jschmidt_mx.yaml", "TXT": "delv/jschmidt_txt.yaml", "NS": "delv/jschmidt_ns.yaml",
	})
	ds := parseDelvYAML(fixture(t, "delv/jschmidt_ds.yaml"), "DS")
	key := parseDelvYAML(fixture(t, "delv/jschmidt_dnskey.yaml"), "DNSKEY")
	rep := classifyDNSSEC(ds, key, apex, func(string, string) (bool, string) {
		t.Fatal("bogus probe must not run for a healthy zone")
		return false, ""
	})
	if rep.State != DNSSECSecure || !rep.DS || !rep.DNSKEY || rep.EDE != "" {
		t.Errorf("unexpected %+v", rep)
	}
}

func TestClassifyDNSSEC_Insecure(t *testing.T) {
	apex := lookups(t, map[string]string{
		"A": "delv/google_a_unsigned.yaml", "AAAA": "delv/google_aaaa_unsigned.yaml",
		"MX": "delv/google_mx_unsigned.yaml", "TXT": "delv/google_txt_unsigned.yaml", "NS": "delv/google_ns_unsigned.yaml",
	})
	ds := parseDelvYAML(fixture(t, "delv/google_ds_nxrrset.yaml"), "DS")
	key := parseDelvYAML(fixture(t, "delv/google_dnskey_nxrrset.yaml"), "DNSKEY")
	rep := classifyDNSSEC(ds, key, apex, nil)
	if rep.State != DNSSECInsecure || rep.DS || rep.DNSKEY {
		t.Errorf("unexpected %+v", rep)
	}
}

func TestClassifyDNSSEC_Island(t *testing.T) {
	apex := lookups(t, map[string]string{"A": "delv/google_a_unsigned.yaml"})
	ds := parseDelvYAML(fixture(t, "delv/google_ds_nxrrset.yaml"), "DS")
	key := parseDelvYAML(fixture(t, "delv/jschmidt_dnskey.yaml"), "DNSKEY")
	rep := classifyDNSSEC(ds, key, apex, nil)
	if rep.State != DNSSECIsland || rep.Detail == "" {
		t.Errorf("unexpected %+v", rep)
	}
}

func TestClassifyDNSSEC_DSWithoutDNSKEY(t *testing.T) {
	apex := lookups(t, map[string]string{"A": "delv/google_a_unsigned.yaml"})
	ds := parseDelvYAML(fixture(t, "delv/jschmidt_ds.yaml"), "DS")
	key := parseDelvYAML(fixture(t, "delv/google_dnskey_nxrrset.yaml"), "DNSKEY")
	rep := classifyDNSSEC(ds, key, apex, nil)
	if rep.State != DNSSECBogus {
		t.Errorf("DS without DNSKEY should be bogus, got %+v", rep)
	}
}

func TestClassifyDNSSEC_BogusViaProbe(t *testing.T) {
	apex := lookups(t, map[string]string{"A": "delv/dnssec_failed_failure.yaml", "NS": "delv/dnssec_failed_failure.yaml"})
	ds := parseDelvYAML(fixture(t, "delv/dnssec_failed_ds.yaml"), "DS")
	key := parseDelvYAML(fixture(t, "delv/dnssec_failed_failure.yaml"), "DNSKEY")
	var probed string
	rep := classifyDNSSEC(ds, key, apex, func(name, qtype string) (bool, string) {
		probed = name + "/" + qtype
		return true, "9 (DNSKEY Missing): No DNSKEY matches DS RRs of dnssec-failed.org"
	})
	if rep.State != DNSSECBogus || !strings.Contains(rep.EDE, "DNSKEY Missing") || !rep.DS {
		t.Errorf("unexpected %+v", rep)
	}
	if probed != "test/A" {
		t.Errorf("probe should use the first failed apex lookup, got %q", probed)
	}
}

func TestClassifyDNSSEC_Servfail(t *testing.T) {
	apex := lookups(t, map[string]string{"A": "delv/dnssec_failed_failure.yaml"})
	fail := parseDelvYAML(fixture(t, "delv/dnssec_failed_failure.yaml"), "DS")
	rep := classifyDNSSEC(fail, fail, apex, func(string, string) (bool, string) { return false, "" })
	if rep.State != DNSSECServfail {
		t.Errorf("unexpected %+v", rep)
	}
	rep = classifyDNSSEC(fail, fail, apex, nil)
	if rep.State != DNSSECServfail {
		t.Errorf("nil probe should classify as servfail, got %+v", rep)
	}
}

func TestClassifyDNSSEC_Unknown(t *testing.T) {
	apex := lookups(t, map[string]string{"A": "delv/google_a_unsigned.yaml"})
	to := parseDelvYAML(fixture(t, "delv/timeout.yaml"), "DS")
	key := parseDelvYAML(fixture(t, "delv/google_dnskey_nxrrset.yaml"), "DNSKEY")
	rep := classifyDNSSEC(to, key, apex, nil)
	if rep.State != DNSSECUnknown {
		t.Errorf("unexpected %+v", rep)
	}
}

func TestDigHasDataAndEDE(t *testing.T) {
	cd := fixture(t, "dig/dnssec_failed_cd.yaml")
	nocd := fixture(t, "dig/dnssec_failed_nocd.yaml")
	if !digHasData(cd) {
		t.Error("+cd response should have data")
	}
	if digHasData(nocd) {
		t.Error("SERVFAIL response must not count as data")
	}
	if digHasData("") || digHasData("status: NOERROR\n") {
		t.Error("incomplete output must not count as data")
	}
	want := "9 (DNSKEY Missing): No DNSKEY matches DS RRs of dnssec-failed.org"
	if got := digEDE(nocd); got != want {
		t.Errorf("EDE %q, want %q", got, want)
	}
	if got := digEDE(cd); got != "" {
		t.Errorf("no EDE expected on +cd output, got %q", got)
	}
	if got := digEDE("      INFO-CODE: 6 (DNSSEC Bogus)\n"); got != "6 (DNSSEC Bogus)" {
		t.Errorf("code-only EDE %q", got)
	}
}

func TestDigArgs(t *testing.T) {
	got := strings.Join(digArgs(resolver{Host: "8.8.8.8"}, true, 3, "dnssec-failed.org", "A"), " ")
	if got != "+yaml +tries=1 +time=3 +cd @8.8.8.8 dnssec-failed.org A" {
		t.Errorf("got %q", got)
	}
	got = strings.Join(digArgs(resolver{}, false, 0, "x.org", "NS"), " ")
	if got != "+yaml +tries=1 +time=1 x.org NS" {
		t.Errorf("got %q", got)
	}
	got = strings.Join(digArgs(resolver{Host: "::1", Port: 5353}, true, 2, "x.org", "A"), " ")
	check(t, "port form", got, "+yaml +tries=1 +time=2 +cd @::1 -p 5353 x.org A")
}

func TestNewBogusProbe(t *testing.T) {
	r := newFakeRunner()
	r.on("dig", digArgs(resolver{Host: "8.8.8.8"}, true, 5, "dnssec-failed.org", "A"), fakeCall{stdout: fixture(t, "dig/dnssec_failed_cd.yaml")})
	r.on("dig", digArgs(resolver{Host: "8.8.8.8"}, false, 5, "dnssec-failed.org", "A"), fakeCall{stdout: fixture(t, "dig/dnssec_failed_nocd.yaml"), err: errFake})
	probe := newBogusProbe(context.Background(), r, "dig", resolver{Host: "8.8.8.8"}, 5)
	has, ede := probe("dnssec-failed.org", "A")
	if !has || !strings.Contains(ede, "DNSKEY Missing") {
		t.Errorf("got %v %q", has, ede)
	}
	if len(r.called("dig")) != 2 {
		t.Errorf("expected two dig calls, got %v", r.calls)
	}
	// Unknown call: no data, no EDE, no panic.
	has, ede = probe("other.org", "A")
	if has || ede != "" {
		t.Errorf("unexpected %v %q", has, ede)
	}
}

func TestClassifyDNSSEC_ExplicitValidationFailure(t *testing.T) {
	// delv names the validation problem itself ("broken trust chain"), so the
	// zone is bogus even though dig +cd finds no data for the name.
	broken := parseDelvYAML(fixture(t, "delv/invalid_broken_trust_chain.yaml"), "A")
	broken.Name = "nosuch.invalid"
	apex := map[string]Lookup{"A": broken}
	probed := false
	rep := classifyDNSSEC(broken, broken, apex, func(string, string) (bool, string) {
		probed = true
		return false, ""
	})
	if rep.State != DNSSECBogus || !strings.Contains(rep.Detail, "broken trust chain") {
		t.Errorf("unexpected %+v", rep)
	}
	if !probed {
		t.Error("probe should still run to harvest an EDE")
	}
	if rep := classifyDNSSEC(broken, broken, apex, nil); rep.State != DNSSECBogus {
		t.Errorf("nil probe: %+v", rep)
	}
	if isValidationFailure(Lookup{Error: "delv: resolution failed"}) {
		t.Error("generic failure is not a validation failure")
	}
}

func TestClassifyByTrust(t *testing.T) {
	apex := lookups(t, map[string]string{"A": "delv/outlook_host_a.yaml", "NS": "delv/outlook_host_ns_nxrrset.yaml", "TXT": "delv/outlook_host_txt_failure.yaml"})
	rep := classifyByTrust(apex)
	check(t, "insecure host", rep.State, DNSSECInsecure)
	check(t, "no DS/DNSKEY claimed", rep.DS || rep.DNSKEY, false)
	secure := lookups(t, map[string]string{"A": "delv/www_isc_a_validated.yaml"})
	check(t, "validated host", classifyByTrust(secure).State, DNSSECSecure)
	mixed := lookups(t, map[string]string{"A": "delv/www_isc_a_validated.yaml", "TXT": "delv/google_txt_unsigned.yaml"})
	check(t, "any unsigned answer wins", classifyByTrust(mixed).State, DNSSECInsecure)
	failed := lookups(t, map[string]string{"A": "delv/timeout.yaml"})
	check(t, "nothing answered", classifyByTrust(failed).State, DNSSECUnknown)
}
