package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// fixtureLookup serves dog fixtures by name/type from a table; unknown
// names get a negative answer.
func fixtureLookup(t *testing.T, table map[string]string) lookupFn {
	t.Helper()
	return func(name, qtype string) Lookup {
		name = bareName(name)
		if file, ok := table[name+"/"+qtype]; ok {
			l := dogFixture(t, file, qtype)
			l.Name = name
			return l
		}
		l := dogFixture(t, "dog/jschmidt_aaaa_nxrrset.json", qtype)
		l.Name = name
		return l
	}
}

func TestParseDMARC(t *testing.T) {
	d := parseDMARC(dogFixture(t, "dog/mail/dmarc_jschmidt.json", "TXT"))
	check(t, "present", d.Present, true)
	check(t, "policy", d.Policy, "quarantine")
	check(t, "rua", d.RUA, true)
	check(t, "pct default", d.Pct, 100)
	check(t, "problems", len(d.Problems), 0)

	g := parseDMARC(dogFixture(t, "dog/mail/dmarc_google.json", "TXT"))
	check(t, "google reject", g.Policy, "reject")

	w := parseDMARC(dogFixture(t, "dog/mail/dmarc_wikipedia.json", "TXT"))
	check(t, "wikipedia present", w.Present, true)

	none := parseDMARC(dogFixture(t, "dog/mail/mta_sts_jschmidt_missing.json", "TXT"))
	check(t, "missing", none.Present, false)

	multi := parseDMARC(Lookup{Status: StatusOK, Records: []string{"v=DMARC1; p=none; pct=50", "v=DMARC1; p=reject"}})
	check(t, "multiple", multi.Records, 2)
	check(t, "multiple problem", contains(multi.Problems, "multiple DMARC records"), true)
	check(t, "pct", multi.Pct, 50)
	bad := parseDMARC(Lookup{Status: StatusOK, Records: []string{"v=DMARC1; sp=none"}})
	check(t, "missing p", contains(bad.Problems, "missing p= tag"), true)
	odd := parseDMARC(Lookup{Status: StatusOK, Records: []string{"v=DMARC1; p=maybe"}})
	check(t, "unknown p", contains(odd.Problems, "unknown policy"), true)
}

func TestParseSPFTerms(t *testing.T) {
	terms := parseSPFTerms("v=spf1 ip4:1.2.3.0/24 include:_spf.example.com -a mx:mail.example.com/24 redirect=other.example ~all")
	want := []spfTerm{
		{"+", "ip4", ":1.2.3.0/24", false},
		{"+", "include", ":_spf.example.com", false},
		{"-", "a", "", false},
		{"+", "mx", ":mail.example.com/24", false},
		{"+", "redirect", "other.example", true},
		{"~", "all", "", false},
	}
	check(t, "terms", terms, want)
}

func TestEvaluateSPF_Fixtures(t *testing.T) {
	lookup := indexLookup(t)

	j := evaluateSPF("jschmidt.org", lookup("jschmidt.org", "TXT"), lookup)
	check(t, "one record", j.Records, 1)
	check(t, "softfail", j.All, "~all")
	check(t, "first include", j.Includes[0], "outlook.com")
	check(t, "outlook chain followed", contains(j.Includes, "spf2.outlook.com"), true)
	check(t, "amazonses included", contains(j.Includes, "amazonses.com"), true)
	check(t, "lookups within limit", j.Lookups <= spfLookupLimit && j.Lookups >= 3, true)
	// The only problem is inherited from amazonses.com, whose TXT answer
	// (four records, one of them split) is 523 octets on the wire.
	check(t, "amazonses size warning only", j.Problems, []string{"include:amazonses.com TXT answer is 523 octets, over the 512-octet UDP limit (RFC 7208 §3.4)"})
	// jschmidt.org: 12 header + 18 question + 26 (MS=...) + 66 (SPF).
	check(t, "apex answer octets", j.AnswerOctets, 122)

	// Google now inlines its netblocks: one include, one lookup.
	g := evaluateSPF("google.com", lookup("google.com", "TXT"), lookup)
	check(t, "google softfail", g.All, "~all")
	check(t, "google lookups", g.Lookups, 1)
	check(t, "google includes", g.Includes, []string{"_spf.google.com"})

	none := evaluateSPF("x.org", Lookup{Status: StatusNXRRSet}, lookup)
	check(t, "no spf", none.Records, 0)
}

func TestEvaluateSPF_Problems(t *testing.T) {
	// Real included records, assembled into a record that exceeds the limit.
	lookup := indexLookup(t)
	over := Lookup{Status: StatusOK, Records: []string{"v=spf1 include:outlook.com include:_spf.google.com include:amazonses.com include:spf1.osu.edu a mx mx:mail.example.com exists:%{i}.x.example a:h1.example a:h2.example a:h3.example ~all"}}
	r := evaluateSPF("big.example", over, lookup)
	check(t, "over the limit", r.Lookups > spfLookupLimit, true)
	check(t, "permerror", contains(r.Problems, "exceed the limit of 10 (permerror"), true)

	multi := Lookup{Status: StatusOK, Records: []string{"v=spf1 -all", "v=spf1 include:outlook.com ~all"}}
	r = evaluateSPF("x.example", multi, lookup)
	check(t, "multiple records", contains(r.Problems, "multiple SPF records (permerror"), true)

	r = evaluateSPF("x.example", Lookup{Status: StatusOK, Records: []string{"v=spf1 +all"}}, lookup)
	check(t, "+all", contains(r.Problems, "+all authorises every sender"), true)
	r = evaluateSPF("x.example", Lookup{Status: StatusOK, Records: []string{"v=spf1 ip4:1.2.3.4 ?all"}}, lookup)
	check(t, "?all", contains(r.Problems, "?all is neutral"), true)
	r = evaluateSPF("x.example", Lookup{Status: StatusOK, Records: []string{"v=spf1 ptr -all"}}, lookup)
	check(t, "ptr", contains(r.Problems, "ptr mechanism is deprecated"), true)
	r = evaluateSPF("x.example", Lookup{Status: StatusOK, Records: []string{"v=spf1 ip4:1.2.3.4"}}, lookup)
	check(t, "no all", contains(r.Problems, "no all mechanism"), true)
	r = evaluateSPF("x.example", Lookup{Status: StatusOK, Records: []string{"v=spf1 bogus:thing -all"}}, lookup)
	check(t, "unknown mechanism", contains(r.Problems, "unknown mechanism bogus"), true)
	r = evaluateSPF("x.example", Lookup{Status: StatusOK, Records: []string{"v=spf1 include:nospf1.example include:nospf2.example include:nospf3.example -all"}}, lookup)
	check(t, "void lookups", r.VoidLookups, 3)
	check(t, "void problem", contains(r.Problems, "void lookups exceed"), true)
	check(t, "include without spf", contains(r.Problems, "include:nospf1.example has no SPF record"), true)
	r = evaluateSPF("x.example", Lookup{Status: StatusOK, Records: []string{"v=spf1 redirect=_spf.google.com"}}, lookup)
	check(t, "redirect followed", r.Includes[0], "_spf.google.com")
	check(t, "redirect counts as all", contains(r.Problems, "no all mechanism"), false)
	// A loop between includes terminates, and is permerror: a receiver
	// following it runs out of lookups.
	loopy := fixtureLookup(t, map[string]string{})
	r = evaluateSPF("loop.example", Lookup{Status: StatusOK, Records: []string{"v=spf1 include:loop.example -all"}}, loopy)
	check(t, "self include stops", r.Lookups, 1)
	check(t, "loop reported", r.Problems, []string{"include loop loop.example -> loop.example (permerror: SPF fails entirely)"})
}

// txtLookup serves SPF records from a table; a name not in it is NODATA,
// and one mapped to nil timed out.
func txtLookup(records map[string][]string) lookupFn {
	return func(name, qtype string) Lookup {
		recs, ok := records[name]
		switch {
		case !ok:
			return Lookup{Name: name, Type: qtype, Status: StatusNXRRSet}
		case recs == nil:
			return Lookup{Name: name, Type: qtype, Status: StatusTimeout}
		}
		return Lookup{Name: name, Type: qtype, Status: StatusOK, Records: recs}
	}
}

func spfApex(record string) Lookup {
	return Lookup{Status: StatusOK, Records: []string{record}}
}

// RFC 7208 §4.6.4 charges every evaluation. Two includes that share a
// subtree pay for it twice, so a record can be over the limit while each
// branch looks small; counting the shared part once said it was within.
func TestEvaluateSPF_SharedSubtreeCountsEveryTime(t *testing.T) {
	lookup := txtLookup(map[string][]string{
		"a.example":      {"v=spf1 include:shared.example -all"},
		"b.example":      {"v=spf1 include:shared.example -all"},
		"shared.example": {"v=spf1 a mx include:deep.example -all"},
		"deep.example":   {"v=spf1 ip4:192.0.2.1 -all"},
	})
	r := evaluateSPF("x.example", spfApex("v=spf1 a include:a.example include:b.example -all"), lookup)
	check(t, "lookups", r.Lookups, 11)
	check(t, "over the limit", contains(r.Problems, "11 DNS lookups exceed the limit of 10 (permerror"), true)
	check(t, "each include listed once", r.Includes, []string{"a.example", "shared.example", "deep.example", "b.example"})
}

// RFC 7208 §6.1: a record with an all mechanism ignores its redirect.
func TestEvaluateSPF_RedirectIgnoredWhenAllPresent(t *testing.T) {
	lookup := txtLookup(map[string][]string{"big.example": {"v=spf1 a a a a a a a a a a a -all"}})
	r := evaluateSPF("x.example", spfApex("v=spf1 ip4:192.0.2.1 -all redirect=big.example"), lookup)
	check(t, "no lookups", r.Lookups, 0)
	check(t, "not followed", r.Includes, []string{})
	check(t, "all", r.All, "-all")
	check(t, "no problems", r.Problems, []string{})
}

// The all a redirect target ends with is the domain's: +all there opens
// the domain to every sender exactly as if the apex said it.
func TestEvaluateSPF_AllThroughRedirect(t *testing.T) {
	lookup := txtLookup(map[string][]string{
		"open.example":    {"v=spf1 +all"},
		"neutral.example": {"v=spf1 ?all"},
	})
	r := evaluateSPF("x.example", spfApex("v=spf1 redirect=open.example"), lookup)
	check(t, "effective all", r.All, "+all")
	check(t, "pass all", r.Problems, []string{"+all authorises every sender (no protection), reached through redirect=open.example"})
	code, sev := spfProblemClass(r.Problems[0])
	check(t, "still spf_pass_all", code+"/"+sev, "spf_pass_all/fail")

	r = evaluateSPF("x.example", spfApex("v=spf1 redirect=neutral.example"), lookup)
	check(t, "neutral", r.Problems, []string{"?all is neutral (no protection), reached through redirect=neutral.example"})

	// An include that passes everyone matches every sender.
	r = evaluateSPF("x.example", spfApex("v=spf1 include:open.example -all"), lookup)
	check(t, "include of +all", r.Problems, []string{"+all authorises every sender (no protection), reached through include:open.example"})
	// An include's ?all only fails to match; it opens nothing.
	r = evaluateSPF("x.example", spfApex("v=spf1 include:neutral.example -all"), lookup)
	check(t, "include of ?all", r.Problems, []string{})
}

// A void lookup is an answer with nothing in it. A lookup that never
// completed is not one: three slow includes are not three empty ones.
func TestEvaluateSPF_TimeoutIsNotVoid(t *testing.T) {
	lookup := txtLookup(map[string][]string{"slow1.example": nil, "slow2.example": nil, "slow3.example": nil})
	r := evaluateSPF("x.example", spfApex("v=spf1 include:slow1.example include:slow2.example include:slow3.example -all"), lookup)
	check(t, "no void lookups", r.VoidLookups, 0)
	check(t, "no void finding", contains(r.Problems, "void lookups"), false)
	check(t, "said unchecked", contains(r.Problems, "include:slow1.example could not be checked: its TXT lookup did not complete"), true)
	code, _ := spfProblemClass(r.Problems[0])
	check(t, "unchecked is a warning", code, "spf_include_unchecked")

	// A TXT answer without SPF in it is not void either: records came back.
	lookup = txtLookup(map[string][]string{"tokens.example": {"google-site-verification=x"}})
	r = evaluateSPF("x.example", spfApex("v=spf1 include:tokens.example -all"), lookup)
	check(t, "answered without spf", []any{r.VoidLookups, r.Problems}, []any{0, []string{"include:tokens.example has no SPF record"}})
}

// "v=spf1" must be followed by a space or nothing. A record split into
// strings without one concatenates to "v=spf1include:...", which receivers
// do not recognise as SPF.
func TestIsSPFRecord(t *testing.T) {
	for r, want := range map[string]bool{
		"v=spf1 -all":            true,
		"V=SPF1 include:x -all":  true,
		"v=spf1":                 true,
		" v=spf1 -all":           true,
		"v=spf1include:x -all":   false,
		"v=spf10 -all":           false,
		"spf2.0/pra include:x":   false,
		"google-site-verify=abc": false,
	} {
		check(t, r, isSPFRecord(r), want)
	}
	r := evaluateSPF("x.example", spfApex("v=spf1include:x.example -all"), txtLookup(nil))
	check(t, "not an SPF record", r.Records, 0)
}

func TestEvaluateSPF_AnswerSize(t *testing.T) {
	lookup := indexLookup(t)

	// datapulse.global: five TXT records, 413 octets (dig +noedns agrees),
	// under the 450 warning line; amazonses.com is over the limit.
	d := evaluateSPF("datapulse.global", lookup("datapulse.global", "TXT"), lookup)
	check(t, "datapulse octets", d.AnswerOctets, 413)
	check(t, "datapulse lookups", d.Lookups, 9)
	check(t, "datapulse problems", d.Problems, []string{"include:amazonses.com TXT answer is 523 octets, over the 512-octet UDP limit (RFC 7208 §3.4)"})

	// jasadvisors.com: three TXT records, 250 octets.
	j := evaluateSPF("jasadvisors.com", lookup("jasadvisors.com", "TXT"), lookup)
	check(t, "jasadvisors octets", j.AnswerOctets, 250)
	check(t, "jasadvisors problems", j.Problems, []string{"include:amazonses.com TXT answer is 523 octets, over the 512-octet UDP limit (RFC 7208 §3.4)"})

	// amazonses.com as the domain under test: its own apex is over the limit.
	a := evaluateSPF("amazonses.com", lookup("amazonses.com", "TXT"), lookup)
	check(t, "amazonses octets", a.AnswerOctets, 523)
	check(t, "amazonses apex problem", contains(a.Problems, "apex TXT answer is 523 octets, over the 512-octet UDP limit"), true)

	// datapulse.global with one more verification token (a real 81-octet
	// google-site-verification record) lands at 494: close to the limit.
	extra := strings.Replace(fixture(t, "dog/mail/spf_datapulse_global.json"), `"answers":[`,
		`"answers":[{"name":"datapulse.global.","class":"IN","ttl":2493,"type":"TXT","data":{"messages":["google-site-verification=aOJq8aXEtCO23r176f6iOTGt-RVuPv81XPtBuIzRTx0"]}},`, 1)
	near := parseDog(extra, "TXT")
	near.Name = "datapulse.global"
	check(t, "six records", len(near.Records), 6)
	n := evaluateSPF("datapulse.global", near, lookup)
	check(t, "near octets", n.AnswerOctets, 494)
	check(t, "near problem", contains(n.Problems, "apex TXT answer is 494 octets, close to the 512-octet UDP limit"), true)

	// No SPF record: nothing to size.
	none := evaluateSPF("x.org", Lookup{Status: StatusNXRRSet}, lookup)
	check(t, "no spf, no octets", none.AnswerOctets, 0)
}

func TestCheckMX(t *testing.T) {
	table := map[string]string{
		"jschmidt-org.mail.protection.outlook.com/A":    "dog/mail/mx_target_jschmidt_a.json",
		"jschmidt-org.mail.protection.outlook.com/AAAA": "dog/mail/mx_target_jschmidt_aaaa.json",
		"www.github.com/A":    "dog/www_github_cname.json",
		"nosuch.example/A":    "dog/nxdomain_unsigned.json",
		"nosuch.example/AAAA": "dog/nxdomain_unsigned.json",
	}
	lookup := fixtureLookup(t, table)
	mx := checkMX(dogFixture(t, "dog/jschmidt_mx.json", "MX"), lookup)
	check(t, "one exchange", len(mx), 1)
	check(t, "host", mx[0].Host, "jschmidt-org.mail.protection.outlook.com.")
	check(t, "addresses", mx[0].Addresses, 8)
	check(t, "clean", len(mx[0].Problems), 0)

	bad := Lookup{Status: StatusOK, Records: []string{"10 www.github.com.", "20 192.0.2.1", "30 nosuch.example.", "40 empty.example."}}
	mx = checkMX(bad, lookup)
	check(t, "cname flagged", mx[0].CNAME, true)
	check(t, "cname problem", contains(mx[0].Problems, "CNAME"), true)
	check(t, "ip literal", mx[1].IPLiteral, true)
	check(t, "nxdomain", contains(mx[2].Problems, "does not exist"), true)
	check(t, "no address", contains(mx[3].Problems, "no address"), true)

	check(t, "none of these are gaps", []bool{mx[0].Unresolved, mx[2].Unresolved, mx[3].Unresolved}, []bool{false, false, false})

	null := checkMX(dogFixture(t, "dog/microsoft_jp_net_null_mx.json", "MX"), lookup)
	check(t, "lone null MX is fine", len(null[0].Problems), 0)
	mixed := checkMX(Lookup{Status: StatusOK, Records: []string{"0 .", "10 www.github.com."}}, lookup)
	check(t, "null MX mixed", contains(mixed[0].Problems, "null MX mixed"), true)
}

func TestProbeDKIM(t *testing.T) {
	table := map[string]string{
		"selector1._domainkey.jschmidt.org/TXT": "dog/mail/dkim_selector1_jschmidt.json",
		"selector2._domainkey.jschmidt.org/TXT": "dog/mail/dkim_selector2_jschmidt.json",
	}
	res := probeDKIM("jschmidt.org", fixtureLookup(t, table))
	check(t, "selectors", res.SelectorsFound, []string{"selector1", "selector2"})
	check(t, "none revoked", len(res.Revoked), 0)
	revoked := func(name, qtype string) Lookup {
		if strings.HasPrefix(name, "k1.") {
			return Lookup{Status: StatusOK, Records: []string{"v=DKIM1; k=rsa; p="}}
		}
		return Lookup{Status: StatusNXRRSet}
	}
	res = probeDKIM("x.example", revoked)
	check(t, "revoked selector", res.Revoked, []string{"k1"})
	check(t, "still found", res.SelectorsFound, []string{"k1"})
}

func TestMTASTS(t *testing.T) {
	rec := parseMTASTSRecord(dogFixture(t, "dog/mail/mta_sts_gmail.json", "TXT"))
	check(t, "record", rec.Record, true)
	check(t, "id", rec.ID, "20190429T010101")
	check(t, "missing", parseMTASTSRecord(dogFixture(t, "dog/mail/mta_sts_jschmidt_missing.json", "TXT")).Record, false)
	check(t, "tls-rpt", hasTLSRPT(dogFixture(t, "dog/mail/tls_rpt_gmail.json", "TXT")), true)
	check(t, "no tls-rpt", hasTLSRPT(Lookup{}), false)

	policy := "version: STSv1\nmode: enforce\nmx: gmail-smtp-in.l.google.com\nmx: *.gmail-smtp-in.l.google.com\nmax_age: 86400\n"
	var m MTASTS
	parseMTASTSPolicy(policy, &m)
	check(t, "policy ok", m.PolicyOK, true)
	check(t, "mode", m.Mode, "enforce")
	check(t, "max_age", m.MaxAge, 86400)
	check(t, "covers", mtaSTSCovers(m.MXPattern, []string{"gmail-smtp-in.l.google.com.", "alt1.gmail-smtp-in.l.google.com."}), true)
	check(t, "does not cover", mtaSTSCovers(m.MXPattern, []string{"mx.other.example."}), false)
	check(t, "wildcard one label only", mtaSTSCovers([]string{"*.example.com"}, []string{"a.b.example.com"}), false)
	var bad MTASTS
	parseMTASTSPolicy("version: STSv1\nmode: weird\n", &bad)
	check(t, "bad mode", bad.PolicyOK, false)

	old := policyFetcher
	t.Cleanup(func() { policyFetcher = old })
	lookup := indexLookup(t)
	policyFetcher = func(context.Context, string, time.Duration, lookupFn) (string, error) { return policy, nil }
	got := checkMTASTS(context.Background(), "gmail.com", dogFixture(t, "dog/mail/mta_sts_gmail.json", "TXT"), []string{"gmail-smtp-in.l.google.com."}, time.Second, lookup)
	check(t, "fetched and covered", got.MXCovered, true)
	policyFetcher = func(context.Context, string, time.Duration, lookupFn) (string, error) {
		return "", errors.New("Get https://mta-sts.gmail.com/: dial tcp: lookup mta-sts.gmail.com on 10.0.0.2:53: no such host")
	}
	got = checkMTASTS(context.Background(), "gmail.com", dogFixture(t, "dog/mail/mta_sts_gmail.json", "TXT"), nil, time.Second, lookup)
	check(t, "fetch error kept", strings.Contains(got.Error, "no such host"), true)
	check(t, "resolver address scrubbed", strings.Contains(got.Error, "10.0.0.2"), false)
	got = checkMTASTS(context.Background(), "x.org", Lookup{}, nil, time.Second, lookup)
	check(t, "no record no fetch", got.Record, false)
	check(t, "mx list present even without record", got.MXPattern, []string{})

	// The real fetcher resolves the policy host through the tool's lookups
	// and refuses to fall back to the system resolver.
	policyFetcher = old
	_, err := fetchMTASTSPolicy(context.Background(), "nosuch.example", time.Second, lookup)
	check(t, "unresolvable policy host", err != nil && strings.Contains(err.Error(), "mta-sts.nosuch.example has no address"), true)
}

func TestMXHosts(t *testing.T) {
	check(t, "hosts", mxHosts(Lookup{Records: []string{"10 b.example.", "5 a.example.", "0 ."}}), []string{"a.example.", "b.example."})
}

func TestScrubResolver(t *testing.T) {
	check(t, "ipv4", scrubResolver("lookup x on 10.0.0.2:53: no such host"), "lookup x: no such host")
	check(t, "ipv6", scrubResolver("lookup x on [::1]:5353: read udp"), "lookup x: read udp")
	check(t, "untouched", scrubResolver("connection refused"), "connection refused")
}

// Real error text captured from batch runs. The socket preamble names our
// own address and a fresh ephemeral port every run, which would publish
// the vantage point and make identical findings differ between runs.
func TestScrubProbeError(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"read tcp4 10.12.60.35:46962->80.245.156.34:443: i/o timeout", "i/o timeout"},
		{"read tcp4 10.12.60.35:37028->91.195.240.94:443: read: connection reset by peer", "read: connection reset by peer"},
		{"dial tcp 3.5.88.34:443: connect: connection refused", "connect: connection refused"},
		{"dial tcp [2606:4700:4700::1111]:1: i/o timeout", "i/o timeout"},
		{"read tcp [2001:db8::1]:5->[2001:db8::2]:443: i/o timeout", "i/o timeout"},
		{"remote error: tls: handshake failure", "remote error: tls: handshake failure"},
		{"x509: certificate is valid for example.net, not example.com", "x509: certificate is valid for example.net, not example.com"},
		{"Get \"https://mta-sts.x/\": lookup mta-sts.x on 10.0.0.2:53: no such host", "Get \"https://mta-sts.x/\": lookup mta-sts.x: no such host"},
	} {
		check(t, "scrubbed: "+c.in, scrubProbeError(c.in), c.want)
	}

	// The same failure on two addresses must produce the same text, so
	// that findings can be compared between runs and grouped within one.
	a := scrubProbeError("read tcp4 10.12.60.35:46962->80.245.156.34:443: i/o timeout")
	b := scrubProbeError("read tcp4 10.12.60.35:50696->80.245.156.34:443: i/o timeout")
	check(t, "stable across runs", a, b)
}

func TestMailConventions(t *testing.T) {
	lookup := indexLookup(t)
	none := checkMX(Lookup{Status: StatusNXRRSet}, lookup)
	check(t, "mx list not null", none != nil && len(none) == 0, true)
	d := probeDKIM("nothing.example", lookup)
	check(t, "dkim lists not null", d.SelectorsFound != nil && d.Revoked != nil, true)
	dm := parseDMARC(Lookup{Status: StatusNXRRSet})
	check(t, "dmarc problems not null", dm.Problems != nil, true)
	check(t, "pct present", dm.Pct, 100)
	spf := evaluateSPF("x", Lookup{Status: StatusNXRRSet}, lookup)
	check(t, "spf lists not null", spf.Includes != nil && spf.Problems != nil, true)
}

// A target whose lookup never completed is a gap in the check, not a
// domain without a mail host: it must not be reported as absent, and it
// must not fail the domain.
func TestCheckMX_UnansweredIsNotAbsent(t *testing.T) {
	timedOut := func(name, qtype string) Lookup {
		l := dogFixture(t, "dog/timeout.json", qtype)
		l.Name, l.Status = name, StatusTimeout
		return l
	}
	mx := checkMX(Lookup{Status: StatusOK, Records: []string{"10 mx.example."}}, timedOut)
	check(t, "marked unresolved", mx[0].Unresolved, true)
	check(t, "says so plainly", mx[0].Problems, []string{mxUnresolvedProblem})
	check(t, "not called absent", contains(mx[0].Problems, "no address"), false)

	f := &findings{}
	f.mailFindings(&MailReport{DMARC: DMARC{}, MX: mx}, false)
	check(t, "no error", f.errors, []string(nil))
	check(t, "warned instead", contains(f.warnings, "did not complete"), true)

	// A real denial still fails the domain.
	denied := checkMX(Lookup{Status: StatusOK, Records: []string{"10 mx.example."}}, fixtureLookup(t, map[string]string{
		"mx.example/A":    "dog/nxdomain_unsigned.json",
		"mx.example/AAAA": "dog/nxdomain_unsigned.json",
	}))
	check(t, "denial is not a gap", denied[0].Unresolved, false)
	g := &findings{}
	g.mailFindings(&MailReport{DMARC: DMARC{}, MX: denied}, false)
	check(t, "still an error", contains(g.errors, "does not exist"), true)
}

// Selectors cannot be enumerated, so the probe is a guess, and a zone that
// answers every guess makes the guesses worthless. example.com returns a
// valid revoked key for any selector, which reported all eight as found and
// revoked; gov.uk returns SPF and DMARC strings for any selector, so
// checking that the record parses as DKIM catches the second and not the
// first. Only a random selector catches both.
func TestProbeDKIM_WildcardControl(t *testing.T) {
	// Every name under _domainkey answers with a valid revoked key.
	wild := func(name, qtype string) Lookup {
		if strings.Contains(name, "_domainkey") {
			return Lookup{Status: StatusOK, Records: []string{"v=DKIM1; p="}}
		}
		return Lookup{Status: StatusNXRRSet}
	}
	res := probeDKIM("example.com", wild)
	check(t, "wildcard detected", res.Wildcard, true)
	check(t, "no selector claimed", res.SelectorsFound, []string{})
	check(t, "none called revoked", res.Revoked, []string{})

	f := &findings{}
	f.mailFindings(&MailReport{DMARC: DMARC{}, MX: []MXCheck{}, DKIM: res}, false)
	var dkim []string
	for _, w := range f.warnings {
		if strings.Contains(w, "DKIM") || strings.Contains(w, "_domainkey") {
			dkim = append(dkim, w)
		}
	}
	check(t, "one finding, not eight", dkim, []string{"the zone answers every _domainkey selector (wildcard), so no selector could be verified"})

	// A zone that wildcards _domainkey with non-DKIM content is caught by
	// the same control, where parsing the record would also have worked.
	spf := func(name, qtype string) Lookup {
		if strings.Contains(name, "_domainkey") {
			return Lookup{Status: StatusOK, Records: []string{"v=spf1 ?all"}}
		}
		return Lookup{Status: StatusNXRRSet}
	}
	check(t, "non-DKIM wildcard is not a selector", probeDKIM("gov.uk", spf).SelectorsFound, []string{})

	// A real deployment: the control is denied, so the selectors count.
	real := func(name, qtype string) Lookup {
		switch {
		case strings.HasPrefix(name, "selector1."):
			return Lookup{Status: StatusOK, Records: []string{"v=DKIM1; k=rsa; p=MIGf"}}
		case strings.HasPrefix(name, "selector2."):
			return Lookup{Status: StatusOK, Records: []string{"v=DKIM1; p="}}
		}
		return Lookup{Status: StatusNXDomain}
	}
	res = probeDKIM("jschmidt.org", real)
	check(t, "no wildcard", res.Wildcard, false)
	check(t, "both selectors found", res.SelectorsFound, []string{"selector1", "selector2"})
	check(t, "only the empty one is revoked", res.Revoked, []string{"selector2"})
}

// Absence has to be observed. A _dmarc lookup that never answered must not
// produce "no DMARC record", the same rule already applied to the MX and
// SPF presence warnings beside it.
func TestParseDMARC_UnansweredIsNotAbsence(t *testing.T) {
	for _, st := range []LookupStatus{StatusTimeout, StatusFailure} {
		d := parseDMARC(Lookup{Status: st})
		check(t, "unresolved: "+string(st), d.Unresolved, true)
		check(t, "not asserted present", d.Present, false)
		f := &findings{}
		f.dmarcFindings(d)
		check(t, "says the lookup did not complete", contains(f.warnings, "the DMARC lookup did not complete"), true)
		check(t, "does not claim absence", contains(f.warnings, "no DMARC record"), false)
	}
	// A definite denial is still absence.
	denied := parseDMARC(Lookup{Status: StatusNXRRSet})
	check(t, "denial is not unresolved", denied.Unresolved, false)
	g := &findings{}
	g.dmarcFindings(denied)
	check(t, "absence reported", contains(g.warnings, "no DMARC record"), true)
}

// Tag values are case-insensitive; a malformed pct or sp is reported, as a
// warning, since the record's policy still applies.
func TestParseDMARC_CaseAndValidation(t *testing.T) {
	rec := func(r string) Lookup { return Lookup{Status: StatusOK, Records: []string{r}} }
	d := parseDMARC(rec("v=DMARC1; p=Reject; sp=Quarantine; rua=mailto:x@example.com"))
	check(t, "policy folded", []string{d.Policy, d.SubdomainPolicy}, []string{"reject", "quarantine"})
	check(t, "no problems", d.Problems, []string{})

	d = parseDMARC(rec("v=DMARC1; p=reject; pct=abc"))
	check(t, "bad pct defaults", d.Pct, 100)
	check(t, "bad pct", d.Problems, []string{"invalid pct=abc (not a whole number from 0 to 100)"})
	d = parseDMARC(rec("v=DMARC1; p=reject; pct=150"))
	check(t, "out of range pct", d.Problems, []string{"invalid pct=150 (not a whole number from 0 to 100)"})
	d = parseDMARC(rec("v=DMARC1; p=reject; pct=0"))
	check(t, "pct 0 is valid", []any{d.Pct, d.Problems}, []any{0, []string{}})

	d = parseDMARC(rec("v=DMARC1; p=reject; sp=deny"))
	check(t, "bad sp", d.Problems, []string{"unknown subdomain policy sp=deny"})

	for p, want := range map[string]string{
		"invalid pct=abc (not a whole number from 0 to 100)": "dmarc_pct_invalid/warn",
		"unknown subdomain policy sp=deny":                   "dmarc_subdomain_policy_unknown/warn",
		"unknown policy p=deny":                              "dmarc_policy_unknown/fail",
	} {
		code, sev := dmarcProblemClass(p)
		check(t, p, code+"/"+sev, want)
	}
}

// The policy host may publish several addresses. One that is down must
// not make the policy unreachable when another serves it.
func TestFetchMTASTSPolicy_TriesEveryAddress(t *testing.T) {
	ca := newTestCA(t, "Policy Test CA")
	withRoots(t, ca.pool)
	leaf, key := ca.issue(t, certSpec{sans: []string{"mta-sts.example.com"}, issuer: ca})
	srv := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 86400\n")
	}), []*x509.Certificate{leaf, ca.cert}, key, tls.VersionTLS12, tls.VersionTLS13)
	d := newMappedDialer()
	d.mapTarget("1.0.0.1", 443, srv) // the second address serves; the first refuses
	old := mtaSTSDialer
	mtaSTSDialer = d
	t.Cleanup(func() { mtaSTSDialer = old })

	lookup := func(name, qtype string) Lookup {
		if qtype == "A" {
			return Lookup{Name: name, Type: qtype, Status: StatusOK, Records: []string{"1.1.1.1", "1.0.0.1"}}
		}
		return Lookup{Name: name, Type: qtype, Status: StatusNXRRSet}
	}
	body, err := fetchMTASTSPolicy(context.Background(), "example.com", 2*time.Second, lookup)
	check(t, "fetched", err, nil)
	check(t, "policy", strings.Contains(body, "mode: enforce"), true)
}

// A policy host that resolves only to reserved addresses is not contacted.
func TestFetchMTASTSPolicy_ReservedOnly(t *testing.T) {
	lookup := func(name, qtype string) Lookup {
		if qtype == "A" {
			return Lookup{Name: name, Type: qtype, Status: StatusOK, Records: []string{"169.254.169.254"}}
		}
		return Lookup{Name: name, Type: qtype, Status: StatusNXRRSet}
	}
	_, err := fetchMTASTSPolicy(context.Background(), "example.com", time.Second, lookup)
	check(t, "refused", err != nil && strings.Contains(err.Error(), "mta-sts.example.com has only reserved addresses (169.254.169.254"), true)
}

func TestDialFirst(t *testing.T) {
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	d := &fakeDialer{open: map[string]bool{"192.0.2.2:443": true}, hang: map[string]bool{"192.0.2.1:443": true}}
	start := time.Now()
	c, err := dialFirst(context.Background(), d, []netip.Addr{a, b}, 443)
	check(t, "connected", err == nil && c != nil, true)
	check(t, "did not wait for the hung address", time.Since(start) < time.Second, true)
	if c != nil {
		_ = c.Close()
	}
	_, err = dialFirst(context.Background(), &fakeDialer{}, []netip.Addr{a, b}, 443)
	check(t, "all refused", err != nil, true)
}

// mode none withdraws a policy, so its mx lines are not judged.
func TestMTASTSFindings_ModeNone(t *testing.T) {
	var f findings
	f.mtaSTSFindings(&MTASTS{Record: true, Mode: "none", PolicyOK: true, MXCovered: false})
	check(t, "no finding", len(f.list), 0)
	f.mtaSTSFindings(&MTASTS{Record: true, Mode: "testing", PolicyOK: true, MXCovered: false})
	check(t, "testing still judged", findingCodes(&f), []string{"warn:mta_sts_mx_uncovered"})
}

// osu.edu's Microsoft 365 selectors (captures of 2026-10-07): selector1 is a
// CNAME to an RSA-1024 key, selector2 a CNAME to a name that does not exist.
func TestProbeDKIM_KeyStrengthAndDangling(t *testing.T) {
	lookup := fixtureLookup(t, map[string]string{
		"selector1._domainkey.osu.edu/TXT": "dog/mail/dkim_selector1_osu_edu.json",
		"selector2._domainkey.osu.edu/TXT": "dog/mail/dkim_selector2_osu_edu_dangling.json",
	})
	d := probeDKIM("osu.edu", lookup)
	check(t, "found", d.SelectorsFound, []string{"selector1"})
	check(t, "keys", d.Keys, []DKIMKey{{Selector: "selector1", Type: "rsa", Bits: 1024}})
	check(t, "dangling", d.Dangling, []string{"selector2"})

	var f findings
	f.dkimKeyFindings(d)
	var codes []string
	for _, x := range f.list {
		codes = append(codes, x.Code+":"+x.Severity)
	}
	check(t, "findings", codes, []string{"dkim_key_weak:info", "dkim_selector_dangling:warn"})
}

func TestDKIMKeyInfo(t *testing.T) {
	gh := dogFixture(t, "dog/mail/dkim_s1_github_com.json", "TXT")
	tags := parseTags(gh.Records[0])
	check(t, "github s1 is RSA-2048", dkimKeyInfo("s1", tags), DKIMKey{Selector: "s1", Type: "rsa", Bits: 2048})

	osu := dogFixture(t, "dog/mail/dkim_selector1_osu_edu.json", "TXT")
	tags = parseTags(osu.Records[0])
	// The same key with its last 40 base64 characters cut off: a record
	// someone truncated while pasting.
	tags["p"] = tags["p"][:len(tags["p"])-40]
	check(t, "truncated key", dkimKeyInfo("selector1", tags).Error != "", true)
	check(t, "not base64", dkimKeyInfo("x", map[string]string{"p": "!!!"}).Error, "p= is not base64")
	check(t, "ed25519 wrong size", dkimKeyInfo("x", map[string]string{"k": "ed25519", "p": "AAAA"}).Error, "p= is not a 32-byte Ed25519 key")
	// The Ed25519 key from RFC 8463 §A.2 (brisbane._domainkey.football.example.com).
	check(t, "ed25519 ok", dkimKeyInfo("x", map[string]string{"k": "ed25519", "p": "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="}), DKIMKey{Selector: "x", Type: "ed25519"})

	var f findings
	f.dkimKeyFindings(DKIMResult{Keys: []DKIMKey{{Selector: "old", Type: "rsa", Bits: 512}, {Selector: "s1", Type: "rsa", Bits: 2048}}})
	check(t, "512-bit fails, 2048 is clean", len(f.list) == 1 && f.list[0].Code == "dkim_key_too_short" && f.list[0].Severity == SeverityFail, true)
}

// osu.edu's SPF record (capture of 2026-10-07) lists 128.146.163.14, .18 and
// .21 beside 128.146.163.0/26, which already covers them. Its 2813-octet
// TXT answer is over the 512-octet limit and the 1232-octet EDNS buffer.
func TestEvaluateSPF_OSUReview(t *testing.T) {
	txt := dogFixture(t, "dog/mail/txt_osu_edu.json", "TXT")
	txt.Name = "osu.edu"
	s := evaluateSPF("osu.edu", txt, fixtureLookup(t, nil))
	var redundant []string
	for _, p := range s.Problems {
		if strings.Contains(p, " is already covered by ") {
			redundant = append(redundant, p)
		}
	}
	check(t, "redundant", redundant, []string{
		"ip4:128.146.163.14 is already covered by ip4:128.146.163.0/26 in osu.edu",
		"ip4:128.146.163.18 is already covered by ip4:128.146.163.0/26 in osu.edu",
		"ip4:128.146.163.21 is already covered by ip4:128.146.163.0/26 in osu.edu",
	})
	check(t, "octets", s.AnswerOctets, 2813)
	check(t, "EDNS buffer named", contains(s.Problems, "also exceeds the 1232-octet EDNS buffer"), true)

	var f findings
	f.spfFindings(s)
	hosts := map[string]string{}
	for _, x := range f.list {
		hosts[x.Code] = x.Host + "/" + x.Severity
	}
	check(t, "size finding is the apex's", hosts["spf_txt_over_udp_limit"], "apex/info")
	check(t, "redundancy is info", hosts["spf_redundant_ip"], "/info")
}

func TestRedundantIPs(t *testing.T) {
	cases := []struct {
		record string
		want   []string
	}{
		{"v=spf1 ip4:192.0.2.0/24 ip4:192.0.2.7 -all", []string{"ip4:192.0.2.7 is already covered by ip4:192.0.2.0/24 in x.org"}},
		{"v=spf1 ip4:192.0.2.7 ip4:192.0.2.7 -all", []string{"ip4:192.0.2.7 is already covered by ip4:192.0.2.7 in x.org"}},
		{"v=spf1 ip4:192.0.2.0/24 -ip4:192.0.2.7 ~all", nil}, // an exception, not a repeat
		{"v=spf1 ip6:2001:db8::/32 ip6:2001:db8:1::1 ip4:198.51.100.0/24 -all", []string{"ip6:2001:db8:1::1 is already covered by ip6:2001:db8::/32 in x.org"}},
		{"v=spf1 ip4:192.0.2.0/25 ip4:192.0.2.128/25 -all", nil},
		{"v=spf1 ip4:not-an-ip ip4:192.0.2.1 -all", nil},
	}
	for _, c := range cases {
		check(t, c.record, redundantIPs(parseSPFTerms(c.record), "x.org"), c.want)
	}
}

// Absence facts are stated only when the lookup answered that nothing is
// there; a lookup that failed says nothing.
func TestAbsenceFacts(t *testing.T) {
	none := dogFixture(t, "dog/caa/osu_edu_none.json", "CAA")
	failed := dogFixture(t, "dog/timeout.json", "CAA")
	present := dogFixture(t, "dog/caa/google.json", "CAA")
	for _, c := range []struct {
		name string
		apex Lookup
		want bool
	}{{"no CAA", none, true}, {"lookup failed", failed, false}, {"CAA published", present, false}} {
		r := assessCAA(c.apex, c.apex, servedCert{}, servedCert{})
		var f findings
		f.caaFindings(&r)
		got := len(f.list) == 1 && f.list[0].Code == "caa_absent" && f.list[0].Severity == SeverityInfo
		check(t, c.name, got, c.want)
	}

	var f findings
	f.mailAbsenceFindings(&MailReport{mtaSTSAbsent: true, tlsRPTAbsent: true})
	check(t, "mail absences", []string{f.list[0].Code, f.list[1].Code}, []string{"mta_sts_absent", "tls_rpt_absent"})
	f = findings{}
	f.dnssecFindings(DNSSECReport{State: DNSSECInsecure})
	check(t, "unsigned", f.list[0].Code+"/"+f.list[0].Severity, "dnssec_unsigned/info")
	f = findings{}
	f.dnssecFindings(DNSSECReport{State: DNSSECSecure})
	check(t, "signed says nothing", len(f.list), 0)
}
