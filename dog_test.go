package main

import (
	"context"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Captures from testdata/dog (README there). Trust is the resolver's AD bit:
// .com and .org deny with NSEC3 opt-out and an unsigned delegation's DS
// denial is opt-out too, so those negatives are insecure; a signed CNAME
// into an unsigned CDN is insecure as a whole.
func TestParseDogJSON_Fixtures(t *testing.T) {
	cases := []struct {
		file    string
		qtype   string
		status  LookupStatus
		trust   Trust
		records int
		cname   []string
	}{
		{"dog/jschmidt_mx.json", "MX", StatusOK, TrustSecure, 1, nil},
		{"dog/jschmidt_txt.json", "TXT", StatusOK, TrustSecure, 2, nil},
		{"dog/jschmidt_ns.json", "NS", StatusOK, TrustSecure, 4, nil},
		{"dog/jschmidt_a_nxrrset.json", "A", StatusNXRRSet, TrustSecure, 0, nil},
		{"dog/jschmidt_aaaa_nxrrset.json", "AAAA", StatusNXRRSet, TrustSecure, 0, nil},
		{"dog/jschmidt_ds.json", "DS", StatusOK, TrustSecure, 1, nil},
		{"dog/jschmidt_dnskey.json", "DNSKEY", StatusOK, TrustSecure, 3, nil},
		{"dog/www_jschmidt_a_nxrrset.json", "A", StatusNXRRSet, TrustSecure, 0, nil},
		{"dog/google_a_unsigned.json", "A", StatusOK, TrustInsecure, 1, nil},
		{"dog/google_aaaa_unsigned.json", "AAAA", StatusOK, TrustInsecure, 1, nil},
		{"dog/google_ds_nxrrset.json", "DS", StatusNXRRSet, TrustInsecure, 0, nil},
		{"dog/google_dnskey_nxrrset.json", "DNSKEY", StatusNXRRSet, TrustInsecure, 0, nil},
		{"dog/google_ns_unsigned.json", "NS", StatusOK, TrustInsecure, 4, nil},
		{"dog/google_txt_unsigned.json", "TXT", StatusOK, TrustInsecure, 17, nil},
		{"dog/google_mx_unsigned.json", "MX", StatusOK, TrustInsecure, 1, nil},
		{"dog/nxdomain_signed.json", "A", StatusNXDomain, TrustInsecure, 0, nil},
		{"dog/nxdomain_se_ds.json", "DS", StatusNXDomain, TrustSecure, 0, nil},
		{"dog/nxdomain_unsigned.json", "A", StatusNXDomain, TrustInsecure, 0, nil},
		{"dog/www_github_cname.json", "A", StatusOK, TrustInsecure, 1, []string{"github.com."}},
		{"dog/www_isc_a_validated.json", "A", StatusOK, TrustSecure, 4, nil},
		{"dog/www_ubs_cname_to_unsigned_cdn.json", "A", StatusOK, TrustInsecure, 1, []string{"www.ubs.com.edgekey.net.", "e14741.dsca.akamaiedge.net."}},
		{"dog/dnssec_failed_failure.json", "A", StatusFailure, "", 0, nil},
		{"dog/dnssec_failed_ds.json", "DS", StatusOK, TrustSecure, 1, nil},
		{"dog/timeout.json", "A", StatusTimeout, "", 0, nil},
		{"dog/root_ns_v4.json", "NS", StatusOK, TrustSecure, 13, nil},
		{"dog/root_ns_v6_refused.json", "NS", StatusFailure, "", 0, nil},
		{"dog/outlook_host_ns_nxrrset.json", "NS", StatusNXRRSet, TrustInsecure, 0, nil},
		{"dog/outlook_host_a.json", "A", StatusOK, TrustInsecure, 4, nil},
		{"dog/outlook_host_txt_failure.json", "TXT", StatusFailure, "", 0, nil},
		{"dog/microsoft_jp_net_null_mx.json", "MX", StatusOK, TrustInsecure, 1, nil},
		{"dog/muenchen_a.json", "A", StatusOK, TrustInsecure, 1, nil},
		{"dog/muenchen_ns.json", "NS", StatusOK, TrustInsecure, 4, nil},
		{"dog/www_muenchen_a.json", "A", StatusOK, TrustInsecure, 1, nil},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			l := dogFixture(t, c.file, c.qtype)
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

// Each record type is rendered in BIND's presentation form, which the report
// has always carried and the CAA, TLSA and mail checks parse.
func TestParseDogJSON_RecordContents(t *testing.T) {
	mx := dogFixture(t, "dog/jschmidt_mx.json", "MX")
	check(t, "MX rdata", mx.Records, []string{"0 jschmidt-org.mail.protection.outlook.com."})

	txt := dogFixture(t, "dog/jschmidt_txt.json", "TXT")
	check(t, "SPF detected", hasSPF(txt.Records), true)

	a := dogFixture(t, "dog/www_isc_a_validated.json", "A")
	check(t, "A addr count", len(a.Addrs()), 4)
	check(t, "A is v4", a.Addrs()[0].Is4(), true)
	aaaa := dogFixture(t, "dog/google_aaaa_unsigned.json", "AAAA")
	check(t, "AAAA is v6", aaaa.Addrs()[0].Is6(), true)

	caa := dogFixture(t, "dog/caa/google.json", "CAA")
	check(t, "CAA rdata", caa.Records, []string{`0 issue "pki.goog"`})
	check(t, "CAA parses back", parseCAA(caa.Records), []caaRecord{{Flags: 0, Tag: "issue", Value: "pki.goog"}})

	ds := dogFixture(t, "dog/jschmidt_ds.json", "DS")
	f := strings.Fields(ds.Records[0])
	check(t, "DS fields", len(f), 4)
	check(t, "DS digest upper-case hex", f[3], strings.ToUpper(f[3]))

	ns := dogFixture(t, "dog/jschmidt_ns.json", "NS")
	for _, r := range ns.Records {
		check(t, "NS is a fully qualified name: "+r, strings.HasSuffix(r, "."), true)
	}
}

// TLSA data is upper-case hex, as BIND prints it, and parses back into
// the bytes the matcher compares.
func TestParseDogJSON_TLSA(t *testing.T) {
	l := dogFixture(t, "dog/tlsa/sys4_mail_25.json", "TLSA")
	check(t, "rdata", l.Records, []string{"3 1 1 236831AEEAB41E7BD10DC14320600B245C791B338121383D5A2916F7EF97B49B"})
	rec, ok := parseTLSA(l.Records[0])
	check(t, "parses", ok, true)
	check(t, "32 data bytes", len(rec.Data), 32)
	check(t, "validated", l.Trust, TrustSecure)
}

// TXT character-strings are joined for the checks, and the wire length
// counts one length octet per string: amazonses.com's SPF is two strings.
func TestParseDogJSON_TXTStrings(t *testing.T) {
	l := dogFixture(t, "dog/mail/spf_amazonses_com.json", "TXT")
	var spf *RR
	for i := range l.rrs {
		if strings.HasPrefix(l.rrs[i].RData, "v=spf1") {
			spf = &l.rrs[i]
		}
	}
	if spf == nil {
		t.Fatal("no SPF record in the capture")
	}
	check(t, "joined has no quotes", strings.Contains(spf.RData, `"`), false)
	check(t, "rdlen is the strings plus a length octet each", spf.RDLen > len(spf.RData), true)
}

func TestParseDogJSON_Garbage(t *testing.T) {
	for _, in := range []string{"", "not json at all\n", `{"responses":[]}`} {
		l := parseDog(in, "A")
		if l.Status != StatusFailure || l.Error == "" {
			t.Errorf("%q: expected failure with error, got %+v", in, l)
		}
	}
	// A rcode other than NOERROR and NXDOMAIN is a failure naming the rcode.
	refused := strings.Replace(fixture(t, "dog/dnssec_failed_failure.json"), "SERVFAIL", "REFUSED", 1)
	l := parseDog(refused, "A")
	check(t, "refused", []string{string(l.Status), l.Error}, []string{string(StatusFailure), "resolver answered REFUSED"})
	check(t, "no trust for a failure", l.Trust, Trust(""))
}

func TestDogArgs(t *testing.T) {
	check(t, "system resolver", strings.Join(dogArgs("", 3, "jschmidt.org", "MX"), " "), "-J -Z ad --timeout 3 -q jschmidt.org -t MX")
	check(t, "server", strings.Join(dogArgs("127.0.0.1:8053", 3, ".", "NS"), " "), "-J -Z ad --timeout 3 -n 127.0.0.1:8053 -q . -t NS")
	check(t, "timeout floor", dogArgs("", 0, "x.org", "A")[4], "1")
	for _, c := range []struct{ in, want string }{
		{"8.8.8.8", "8.8.8.8"},
		{"127.0.0.1:8053", "127.0.0.1:8053"},
		{"[::1]:5353", "[::1]:5353"},
		{"2001:4860:4860::8888", "2001:4860:4860::8888"},
		{"dns.example", "dns.example"},
	} {
		res, err := parseResolver(c.in)
		if err != nil {
			t.Fatal(err)
		}
		check(t, "dogServer "+c.in, res.dogServer(), c.want)
	}
	check(t, "system dogServer", resolver{}.dogServer(), "")
}

func TestDNSLookup_FakeRunner(t *testing.T) {
	r := newFakeRunner()
	r.on("dog", dogArgs("", 3, "jschmidt.org", "MX"), fakeCall{stdout: fixture(t, "dog/jschmidt_mx.json")})
	r.on("dog", dogArgs("", 3, "jschmidt.org", "A"), fakeCall{stderr: "dog: exploded", err: errFake})
	r.on("dog", dogArgs("", 3, "slow.org", "A"), fakeCall{delay: 2 * time.Second, stdout: fixture(t, "dog/google_a_unsigned.json")})
	gone := dogCall(t, "dog/timeout.json")
	gone.err = errFake // dog exits 1 when no response came
	r.on("dog", dogArgs("", 3, "gone.org", "A"), gone)

	l := dnsLookup(context.Background(), r, "dog", "", 3, "jschmidt.org", "MX")
	if l.Name != "jschmidt.org" || l.Type != "MX" || !l.HasRecords() {
		t.Errorf("unexpected lookup %+v", l)
	}
	l = dnsLookup(context.Background(), r, "dog", "", 3, "jschmidt.org", "A")
	if l.Status != StatusFailure || !strings.Contains(l.Error, "exploded") {
		t.Errorf("expected failure with stderr, got %+v", l)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	l = dnsLookup(ctx, r, "dog", "", 3, "slow.org", "A")
	if l.Status != StatusTimeout || time.Since(start) > time.Second {
		t.Errorf("expected a prompt timeout, got %+v after %v", l, time.Since(start))
	}
	// dog's own timeout (exit 1, an error document) is a timeout too, and is
	// retried once like a killed attempt.
	l = dnsLookup(context.Background(), r, "dog", "", 3, "gone.org", "A")
	check(t, "dog timeout", l.Status, StatusTimeout)
	check(t, "retried", l.Retries, 1)
}

func TestDNSLookup_RetriesOnceAfterTimeout(t *testing.T) {
	r := newFakeRunner()
	args := dogArgs("", 3, "flaky.org", "A")
	r.onSeq("dog", args,
		fakeCall{delay: 10 * time.Second}, // dropped query
		fakeCall{stdout: fixture(t, "dog/google_a_unsigned.json")},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	l := dnsLookup(ctx, r, "dog", "", 3, "flaky.org", "A")
	elapsed := time.Since(start)
	check(t, "status", l.Status, StatusOK)
	check(t, "retries", l.Retries, 1)
	check(t, "calls", len(r.called("dog")), 2)
	if elapsed < 1200*time.Millisecond || elapsed > 2500*time.Millisecond {
		t.Errorf("first attempt should be cut at half the budget (~1.5s), took %v", elapsed)
	}
	r.onSeq("dog", args, fakeCall{delay: 10 * time.Second}, fakeCall{delay: 10 * time.Second})
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel2()
	start = time.Now()
	l = dnsLookup(ctx2, r, "dog", "", 3, "flaky.org", "A")
	check(t, "status", l.Status, StatusTimeout)
	check(t, "retries", l.Retries, 1)
	if time.Since(start) > 3500*time.Millisecond {
		t.Errorf("overall budget not honoured: %v", time.Since(start))
	}
}

func TestFirstAttemptContext(t *testing.T) {
	ctx, cancel := firstAttemptContext(context.Background())
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Error("no parent deadline should mean no attempt deadline")
	}
	parent, pc := context.WithTimeout(context.Background(), 4*time.Second)
	defer pc()
	first, fc := firstAttemptContext(parent)
	defer fc()
	d, _ := first.Deadline()
	if left := time.Until(d); left < 1500*time.Millisecond || left > 2100*time.Millisecond {
		t.Errorf("first attempt should get about half of 4s, got %v", left)
	}
}

func TestLookup_SOAOwnerAndNullMX(t *testing.T) {
	neg := dogFixture(t, "dog/jschmidt_aaaa_nxrrset.json", "AAAA")
	check(t, "SOA owner from negative answer", neg.SOAOwner(), "jschmidt.org.")
	nx := dogFixture(t, "dog/nxdomain_signed.json", "A")
	check(t, "SOA owner is the enclosing zone", nx.SOAOwner(), "org.")
	pos := dogFixture(t, "dog/jschmidt_mx.json", "MX")
	check(t, "no SOA in positive answer", pos.SOAOwner(), "")

	null := dogFixture(t, "dog/microsoft_jp_net_null_mx.json", "MX")
	check(t, "null MX record kept", null.Records, []string{"0 ."})
	check(t, "null MX detected", null.IsNullMX(), true)
	check(t, "real MX is not null", pos.IsNullMX(), false)
	check(t, "no MX is not null", neg.IsNullMX(), false)
}

// A type domaintest never reads is skipped, not misparsed. The .台湾 TLD
// (xn--kprw13d) is a DNAME to .台灣; dog prints the DNAME as raw bytes next
// to the CNAME the resolver synthesised from it.
func TestParseDogJSON_SkipsUnreadTypes(t *testing.T) {
	l := dogFixture(t, "dog/dname_www_nic_xn--kprw13d_a.json", "A")
	check(t, "status", l.Status, StatusNXDomain)
	check(t, "cname", l.CNAME, []string{"www.nic.xn--kpry57d."})
	for _, rr := range l.rrs {
		if rr.Type == "DNAME" {
			t.Errorf("DNAME kept as a record: %+v", rr)
		}
	}
}

// exitError returns a real *exec.ExitError with the given status.
func exitError(t *testing.T, code int) error {
	t.Helper()
	err := exec.Command("sh", "-c", "exit "+strconv.Itoa(code)).Run()
	if err == nil {
		t.Fatal("sh exited 0")
	}
	return err
}

// dog refuses to encode a label that is not a valid IDN (xn--bad is
// punycode for two control characters) and exits 3 without querying.
// dpdomain now refuses that name at input, so the capture stands in for
// any name the two judge differently.
// That is reported as such, never as a resolver failure, and the DNSSEC
// state is unknown rather than a servfail verdict on the resolver.
func TestDNSLookup_NameDogCannotEncode(t *testing.T) {
	r := newFakeRunner()
	call := dogCall(t, "dog/unqueryable_xn--bad_com_a.json")
	call.err = exitError(t, dogOptionsError)
	r.on("dog", dogArgs("", 3, "xn--bad.com", "A"), call)
	l := dnsLookup(context.Background(), r, "dog", "", 3, "xn--bad.com", "A")
	check(t, "status", l.Status, StatusFailure)
	check(t, "unqueryable", l.unqueryable, true)
	check(t, "error", l.Error, `dog cannot query the name: Invalid options: Invalid domain "xn--bad.com": its label "xn--bad" is not a valid internationalised name`)
	check(t, "not retried", len(r.called("dog")), 1)

	rep := classifyDNSSEC(l, l, map[string]Lookup{"A": l}, func(string, string) (bool, string) {
		t.Fatal("no checking-disabled probe for a name that was never queried")
		return false, ""
	})
	check(t, "dnssec", []string{string(rep.State), rep.Detail}, []string{string(DNSSECUnknown), l.Error})

	// Any other exit is not a refusal.
	other := dogCall(t, "dog/timeout.json")
	other.err = exitError(t, 1)
	r.on("dog", dogArgs("", 3, "gone.org", "A"), other)
	check(t, "network error is not unqueryable", dnsLookup(context.Background(), r, "dog", "", 3, "gone.org", "A").unqueryable, false)
}
