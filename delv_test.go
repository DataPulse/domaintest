package main

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseDelvYAML_Fixtures(t *testing.T) {
	cases := []struct {
		file    string
		qtype   string
		status  LookupStatus
		trust   Trust
		records int
		cname   []string
	}{
		{"delv/jschmidt_mx.yaml", "MX", StatusOK, TrustSecure, 1, nil},
		{"delv/jschmidt_txt.yaml", "TXT", StatusOK, TrustSecure, 2, nil},
		{"delv/jschmidt_ns.yaml", "NS", StatusOK, TrustSecure, 4, nil},
		{"delv/jschmidt_a_nxrrset.yaml", "A", StatusNXRRSet, TrustSecure, 0, nil},
		{"delv/jschmidt_aaaa_nxrrset.yaml", "AAAA", StatusNXRRSet, TrustSecure, 0, nil},
		{"delv/jschmidt_ds.yaml", "DS", StatusOK, TrustSecure, 1, nil},
		{"delv/jschmidt_dnskey.yaml", "DNSKEY", StatusOK, TrustSecure, 3, nil},
		{"delv/www_jschmidt_a_nxrrset.yaml", "A", StatusNXRRSet, TrustSecure, 0, nil},
		{"delv/google_a_unsigned.yaml", "A", StatusOK, TrustInsecure, 1, nil},
		{"delv/google_aaaa_unsigned.yaml", "AAAA", StatusOK, TrustInsecure, 1, nil},
		{"delv/google_ds_nxrrset.yaml", "DS", StatusNXRRSet, TrustSecure, 0, nil},
		{"delv/google_dnskey_nxrrset.yaml", "DNSKEY", StatusNXRRSet, TrustInsecure, 0, nil},
		{"delv/google_ns_unsigned.yaml", "NS", StatusOK, TrustInsecure, 4, nil},
		{"delv/google_txt_unsigned.yaml", "TXT", StatusOK, TrustInsecure, 17, nil},
		{"delv/google_mx_unsigned.yaml", "MX", StatusOK, TrustInsecure, 1, nil},
		{"delv/nxdomain_signed.yaml", "A", StatusNXDomain, TrustSecure, 0, nil},
		{"delv/nxdomain_unsigned.yaml", "A", StatusNXDomain, TrustInsecure, 0, nil},
		{"delv/www_github_cname.yaml", "A", StatusOK, TrustInsecure, 1, []string{"github.com."}},
		{"delv/www_isc_a_validated.yaml", "A", StatusOK, TrustSecure, 4, nil},
		{"delv/dnssec_failed_failure.yaml", "A", StatusFailure, "", 0, nil},
		{"delv/dnssec_failed_ds.yaml", "DS", StatusOK, TrustSecure, 1, nil},
		{"delv/timeout.yaml", "A", StatusTimeout, "", 0, nil},
		{"delv/invalid_broken_trust_chain.yaml", "A", StatusFailure, "", 0, nil},
		{"delv/root_ns_v4.yaml", "NS", StatusOK, TrustSecure, 13, nil},
		{"delv/root_ns_v6_refused.yaml", "NS", StatusFailure, "", 0, nil},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			l := parseDelvYAML(fixture(t, c.file), c.qtype)
			if l.Status != c.status {
				t.Errorf("status %q, want %q (error %q)", l.Status, c.status, l.Error)
			}
			if l.Trust != c.trust {
				t.Errorf("trust %q, want %q", l.Trust, c.trust)
			}
			if len(l.Records) != c.records {
				t.Errorf("records %d, want %d: %v", len(l.Records), c.records, l.Records)
			}
			if !reflect.DeepEqual(l.CNAME, c.cname) {
				t.Errorf("cname %v, want %v", l.CNAME, c.cname)
			}
			if (c.status == StatusFailure || c.status == StatusTimeout) && l.Error == "" {
				t.Error("expected an error message for a failed lookup")
			}
		})
	}
}

func TestParseDelvYAML_RecordContents(t *testing.T) {
	mx := parseDelvYAML(fixture(t, "delv/jschmidt_mx.yaml"), "MX")
	check(t, "MX rdata", mx.Records, []string{"0 jschmidt-org.mail.protection.outlook.com."})
	// RRSIG lines in a positive answer are kept internally but not reported.
	check(t, "rr count", len(mx.rrs), 2)
	check(t, "second rr type", mx.rrs[1].Type, "RRSIG")

	txt := parseDelvYAML(fixture(t, "delv/jschmidt_txt.yaml"), "TXT")
	check(t, "TXT records unquoted", txt.Records, []string{"MS=ms54628650", "v=spf1 include:outlook.com include:amazonses.com ~all"})
	check(t, "SPF detected", hasSPF(txt.Records), true)

	a := parseDelvYAML(fixture(t, "delv/www_isc_a_validated.yaml"), "A")
	check(t, "A addr count", len(a.Addrs()), 4)
	check(t, "A is v4", a.Addrs()[0].Is4(), true)

	aaaa := parseDelvYAML(fixture(t, "delv/google_aaaa_unsigned.yaml"), "AAAA")
	check(t, "AAAA addr count", len(aaaa.Addrs()), 1)
	check(t, "AAAA is v6", aaaa.Addrs()[0].Is6(), true)
}

func TestParseDelvYAML_NegativeMarkersAndProofs(t *testing.T) {
	l := parseDelvYAML(fixture(t, "delv/nxdomain_signed.yaml"), "A")
	var negative, nsec3 int
	for _, rr := range l.rrs {
		if rr.Negative {
			negative++
		}
		if rr.Type == "NSEC3" {
			nsec3++
		}
	}
	if negative != 1 || nsec3 != 3 {
		t.Errorf("expected 1 negative marker and 3 NSEC3 proofs, got %d/%d", negative, nsec3)
	}
	if len(l.Records) != 0 {
		t.Errorf("negative answer must not yield records: %v", l.Records)
	}
}

func TestParseDelvYAML_Garbage(t *testing.T) {
	for _, in := range []string{"", "not yaml at all\n", "records:\n  - fully_validated:\n"} {
		l := parseDelvYAML(in, "A")
		if l.Status != StatusFailure || l.Error == "" {
			t.Errorf("%q: expected failure with error, got %+v", in, l)
		}
	}
}

func TestParseRR(t *testing.T) {
	cases := []struct {
		in   string
		want RR
		ok   bool
	}{
		{"jschmidt.org. 3020 IN MX 0 mail.example.", RR{Owner: "jschmidt.org.", TTL: 3020, Type: "MX", RData: "0 mail.example."}, true},
		{"org. RRSIG SOA ...", RR{Owner: "org.", Type: "RRSIG", RData: "SOA ..."}, true},
		{"jschmidt.org. SOA ns1. host. 1 2 3 4 5", RR{Owner: "jschmidt.org.", Type: "SOA", RData: "ns1. host. 1 2 3 4 5"}, true},
		{`jschmidt.org. 3600 IN \-AAAA ;-$NXRRSET`, RR{Owner: "jschmidt.org.", TTL: 3600, Type: "AAAA", RData: ";-$NXRRSET", Negative: true}, true},
		{`Example.COM. 60 IN TXT "v=spf1" " -all"`, RR{Owner: "example.com.", TTL: 60, Type: "TXT", RData: "v=spf1 -all"}, true},
		{"x.", RR{}, false},
		{"", RR{}, false},
		{"x. 300 IN", RR{}, false},
	}
	for _, c := range cases {
		got, ok := parseRR(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("parseRR(%q) = %+v,%v; want %+v,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestJoinTXT(t *testing.T) {
	cases := map[string]string{
		`"v=spf1 include:outlook.com ~all"`: "v=spf1 include:outlook.com ~all",
		`"abc" "def"`:                       "abcdef",
		`"say \"hi\" \\ done"`:              `say "hi" \ done`,
		`unquoted`:                          "unquoted",
		`""`:                                "",
	}
	for in, want := range cases {
		if got := joinTXT(in); got != want {
			t.Errorf("joinTXT(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUnquoteYAML(t *testing.T) {
	if got := unquoteYAML(`'it''s "x"'`); got != `it's "x"` {
		t.Errorf("got %q", got)
	}
	if got := unquoteYAML("plain"); got != "plain" {
		t.Errorf("got %q", got)
	}
}

func TestDelvArgs(t *testing.T) {
	cases := []struct {
		server, family, name, qtype string
		want                        string
	}{
		{"", "", "jschmidt.org", "MX", "+yaml jschmidt.org MX"},
		{"8.8.8.8", "", "jschmidt.org", "A", "+yaml @8.8.8.8 jschmidt.org A"},
		{"", familyIPv4, ".", "NS", "+yaml -4 . NS"},
		{"2001:4860:4860::8888", familyIPv6, "x.org", "NS", "+yaml -6 @2001:4860:4860::8888 x.org NS"},
	}
	for _, c := range cases {
		if got := strings.Join(delvArgs(c.server, c.family, c.name, c.qtype), " "); got != c.want {
			t.Errorf("delvArgs = %q, want %q", got, c.want)
		}
	}
}

func TestDelvLookup_FakeRunner(t *testing.T) {
	r := newFakeRunner()
	r.on("delv", delvArgs("", "", "jschmidt.org", "MX"), fakeCall{stdout: fixture(t, "delv/jschmidt_mx.yaml")})
	r.on("delv", delvArgs("", "", "jschmidt.org", "A"), fakeCall{stderr: "delv: exploded", err: errFake})
	r.on("delv", delvArgs("", "", "slow.org", "A"), fakeCall{delay: 2 * time.Second, stdout: fixture(t, "delv/google_a_unsigned.yaml")})

	l := delvLookup(context.Background(), r, "delv", "", "", "jschmidt.org", "MX")
	if l.Name != "jschmidt.org" || l.Type != "MX" || !l.HasRecords() {
		t.Errorf("unexpected lookup %+v", l)
	}

	l = delvLookup(context.Background(), r, "delv", "", "", "jschmidt.org", "A")
	if l.Status != StatusFailure || !strings.Contains(l.Error, "exploded") {
		t.Errorf("expected failure with stderr, got %+v", l)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	l = delvLookup(ctx, r, "delv", "", "", "slow.org", "A")
	if l.Status != StatusTimeout {
		t.Errorf("expected timeout, got %+v", l)
	}
	if time.Since(start) > time.Second {
		t.Errorf("timeout not enforced, took %v", time.Since(start))
	}
}

func TestLookupPredicates(t *testing.T) {
	ok := Lookup{Status: StatusOK, Records: []string{"x"}}
	empty := Lookup{Status: StatusOK}
	neg := Lookup{Status: StatusNXRRSet}
	fail := Lookup{Status: StatusFailure}
	if !ok.HasRecords() || empty.HasRecords() || neg.HasRecords() {
		t.Error("HasRecords wrong")
	}
	if !ok.Answered() || !neg.Answered() || fail.Answered() || (Lookup{}).Answered() {
		t.Error("Answered wrong")
	}
	if len((Lookup{Records: []string{"not-an-ip", "::ffff:1.2.3.4"}}).Addrs()) != 1 {
		t.Error("Addrs should skip non-IP rdata and unmap v4-mapped")
	}
}
