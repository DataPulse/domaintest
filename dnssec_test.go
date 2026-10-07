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
		l := dogFixture(t, file, qtype)
		l.Name = "test"
		out[qtype] = l
	}
	return out
}

func TestClassifyDNSSEC_Secure(t *testing.T) {
	apex := lookups(t, map[string]string{
		"A": "dog/jschmidt_a_nxrrset.json", "AAAA": "dog/jschmidt_aaaa_nxrrset.json",
		"MX": "dog/jschmidt_mx.json", "TXT": "dog/jschmidt_txt.json", "NS": "dog/jschmidt_ns.json",
	})
	ds := dogFixture(t, "dog/jschmidt_ds.json", "DS")
	key := dogFixture(t, "dog/jschmidt_dnskey.json", "DNSKEY")
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
		"A": "dog/google_a_unsigned.json", "AAAA": "dog/google_aaaa_unsigned.json",
		"MX": "dog/google_mx_unsigned.json", "TXT": "dog/google_txt_unsigned.json", "NS": "dog/google_ns_unsigned.json",
	})
	ds := dogFixture(t, "dog/google_ds_nxrrset.json", "DS")
	key := dogFixture(t, "dog/google_dnskey_nxrrset.json", "DNSKEY")
	rep := classifyDNSSEC(ds, key, apex, nil)
	if rep.State != DNSSECInsecure || rep.DS || rep.DNSKEY {
		t.Errorf("unexpected %+v", rep)
	}
}

// A .com name that does not exist (dog captures, 2026-10-07): .com denies
// with an NSEC3 opt-out span, so the resolver withholds AD (RFC 5155 §9.2).
// The state is "nonexistent", not a verdict on a zone, and the detail says
// the denial did not validate. The same name in .se is denied with NSEC,
// and that denial did validate.
func TestClassifyDNSSEC_Nonexistent(t *testing.T) {
	apex := lookups(t, map[string]string{"A": "dog/nxdomain_com_a.json", "NS": "dog/nxdomain_com_ns.json"})
	key := dogFixture(t, "dog/nxdomain_com_dnskey.json", "DNSKEY")
	noProbe := func(string, string) (bool, string) {
		t.Fatal("bogus probe must not run for a denial")
		return false, ""
	}
	ds := dogFixture(t, "dog/nxdomain_com_ds.json", "DS")
	rep := classifyDNSSEC(ds, key, apex, noProbe)
	if rep.State != DNSSECNonexistent || rep.DS || rep.DNSKEY || !strings.Contains(rep.Detail, "was not validated") {
		t.Errorf("opt-out denial: %+v", rep)
	}
	ds = dogFixture(t, "dog/nxdomain_se_ds.json", "DS")
	rep = classifyDNSSEC(ds, key, apex, noProbe)
	if rep.State != DNSSECNonexistent || !strings.Contains(rep.Detail, "was DNSSEC-validated") {
		t.Errorf("NSEC denial: %+v", rep)
	}
	// The unsigned capture: the same state, the denial not validated.
	un := dogFixture(t, "dog/nxdomain_unsigned.json", "A")
	rep = classifyDNSSEC(un, un, map[string]Lookup{"A": un, "NS": un}, nil)
	if rep.State != DNSSECNonexistent || !strings.Contains(rep.Detail, "not validated") {
		t.Errorf("unsigned denial: %+v", rep)
	}
}

func TestClassifyDNSSEC_Island(t *testing.T) {
	apex := lookups(t, map[string]string{"A": "dog/google_a_unsigned.json"})
	ds := dogFixture(t, "dog/google_ds_nxrrset.json", "DS")
	key := dogFixture(t, "dog/jschmidt_dnskey.json", "DNSKEY")
	rep := classifyDNSSEC(ds, key, apex, nil)
	if rep.State != DNSSECIsland || rep.Detail == "" {
		t.Errorf("unexpected %+v", rep)
	}
}

func TestClassifyDNSSEC_DSWithoutDNSKEY(t *testing.T) {
	apex := lookups(t, map[string]string{"A": "dog/google_a_unsigned.json"})
	ds := dogFixture(t, "dog/jschmidt_ds.json", "DS")
	key := dogFixture(t, "dog/google_dnskey_nxrrset.json", "DNSKEY")
	rep := classifyDNSSEC(ds, key, apex, nil)
	if rep.State != DNSSECBogus {
		t.Errorf("DS without DNSKEY should be bogus, got %+v", rep)
	}
}

func TestClassifyDNSSEC_BogusViaProbe(t *testing.T) {
	apex := lookups(t, map[string]string{"A": "dog/dnssec_failed_failure.json", "NS": "dog/dnssec_failed_failure.json"})
	ds := dogFixture(t, "dog/dnssec_failed_ds.json", "DS")
	key := dogFixture(t, "dog/dnssec_failed_failure.json", "DNSKEY")
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
	apex := lookups(t, map[string]string{"A": "dog/dnssec_failed_failure.json"})
	fail := dogFixture(t, "dog/dnssec_failed_failure.json", "DS")
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
	apex := lookups(t, map[string]string{"A": "dog/google_a_unsigned.json"})
	to := dogFixture(t, "dog/timeout.json", "DS")
	key := dogFixture(t, "dog/google_dnskey_nxrrset.json", "DNSKEY")
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

func TestClassifyByTrust(t *testing.T) {
	apex := lookups(t, map[string]string{"A": "dog/outlook_host_a.json", "NS": "dog/outlook_host_ns_nxrrset.json", "TXT": "dog/outlook_host_txt_failure.json"})
	rep := classifyByTrust(apex)
	check(t, "insecure host", rep.State, DNSSECInsecure)
	check(t, "no DS/DNSKEY claimed", rep.DS || rep.DNSKEY, false)
	secure := lookups(t, map[string]string{"A": "dog/www_isc_a_validated.json"})
	check(t, "validated host", classifyByTrust(secure).State, DNSSECSecure)
	mixed := lookups(t, map[string]string{"A": "dog/www_isc_a_validated.json", "TXT": "dog/google_txt_unsigned.json"})
	check(t, "any unsigned answer wins", classifyByTrust(mixed).State, DNSSECInsecure)
	failed := lookups(t, map[string]string{"A": "dog/timeout.json"})
	check(t, "nothing answered", classifyByTrust(failed).State, DNSSECUnknown)
}

// DS and DNSKEY both present does not make a zone secure: a DS whose
// algorithm or digest the validator does not support makes it treat the
// zone as unsigned, and the resolver then leaves AD off the DNSKEY answer.
// The state follows what the validator did, not what is published. The
// unvalidated answer is the jschmidt.org capture with AD cleared.
func TestClassifyDNSSEC_PublishedButNotValidated(t *testing.T) {
	apex := lookups(t, map[string]string{
		"A": "dog/jschmidt_a_nxrrset.json", "AAAA": "dog/jschmidt_aaaa_nxrrset.json",
		"MX": "dog/jschmidt_mx.json", "TXT": "dog/jschmidt_txt.json", "NS": "dog/jschmidt_ns.json",
	})
	ds := dogFixture(t, "dog/jschmidt_ds.json", "DS")
	raw := fixture(t, "dog/jschmidt_dnskey.json")
	unsigned := parseDog(strings.Replace(raw, `"ad":true`, `"ad":false`, 1), "DNSKEY")
	rep := classifyDNSSEC(ds, unsigned, apex, nil)
	check(t, "insecure", rep.State, DNSSECInsecure)
	check(t, "published", []bool{rep.DS, rep.DNSKEY}, []bool{true, true})
	check(t, "says why", rep.Detail, "DS and DNSKEY are published, but the validator treated the zone as unsigned")

	unlabelled := parseDog(raw, "DNSKEY")
	unlabelled.Trust = "" // no verdict, as from a resolver that does not validate
	rep = classifyDNSSEC(ds, unlabelled, apex, nil)
	check(t, "no status is unknown, not secure", rep.State, DNSSECUnknown)
}

// jd.com (2026-10-07): the MX lookup SERVFAILed on a slow nameserver and
// the +cd re-query answered. The parent has no DS for jd.com, so nothing
// there is validated and the failure cannot be a validation failure.
func TestClassifyDNSSEC_UnsignedZoneTransientFailure(t *testing.T) {
	apex := lookups(t, map[string]string{"A": "dog/google_a_unsigned.json"})
	apex["MX"] = dogFixture(t, "dog/dnssec_failed_failure.json", "MX")
	ds := dogFixture(t, "dog/jd_ds_nxrrset.json", "DS")
	key := dogFixture(t, "dog/google_dnskey_nxrrset.json", "DNSKEY")
	rep := classifyDNSSEC(ds, key, apex, func(string, string) (bool, string) { return true, "" })
	if rep.State != DNSSECServfail || !strings.Contains(rep.Detail, "not a validation failure") {
		t.Errorf("unsigned zone called %+v", rep)
	}
	// The same failure under a parent that publishes a DS is still bogus.
	signedDS := dogFixture(t, "dog/dnssec_failed_ds.json", "DS")
	if rep := classifyDNSSEC(signedDS, key, apex, func(string, string) (bool, string) { return true, "" }); rep.State != DNSSECBogus {
		t.Errorf("signed zone: %+v", rep)
	}
}
