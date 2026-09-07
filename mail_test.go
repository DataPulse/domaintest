package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fixtureLookup serves delv fixtures by name/type from a table; unknown
// names get a negative answer.
func fixtureLookup(t *testing.T, table map[string]string) lookupFn {
	t.Helper()
	return func(name, qtype string) Lookup {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		if file, ok := table[name+"/"+qtype]; ok {
			l := parseDelvYAML(fixture(t, file), qtype)
			l.Name = name
			return l
		}
		l := parseDelvYAML(fixture(t, "delv/jschmidt_aaaa_nxrrset.yaml"), qtype)
		l.Name = name
		return l
	}
}

func TestParseDMARC(t *testing.T) {
	d := parseDMARC(parseDelvYAML(fixture(t, "delv/mail/dmarc_jschmidt.yaml"), "TXT"))
	check(t, "present", d.Present, true)
	check(t, "policy", d.Policy, "quarantine")
	check(t, "rua", d.RUA, true)
	check(t, "pct default", d.Pct, 100)
	check(t, "problems", len(d.Problems), 0)

	g := parseDMARC(parseDelvYAML(fixture(t, "delv/mail/dmarc_google.yaml"), "TXT"))
	check(t, "google reject", g.Policy, "reject")

	w := parseDMARC(parseDelvYAML(fixture(t, "delv/mail/dmarc_wikipedia.yaml"), "TXT"))
	check(t, "wikipedia present", w.Present, true)

	none := parseDMARC(parseDelvYAML(fixture(t, "delv/mail/mta_sts_jschmidt_missing.yaml"), "TXT"))
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
	check(t, "no problems", j.Problems, []string{})

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
	// A loop between includes terminates.
	loopy := fixtureLookup(t, map[string]string{})
	r = evaluateSPF("loop.example", Lookup{Status: StatusOK, Records: []string{"v=spf1 include:loop.example -all"}}, loopy)
	check(t, "self include ignored", r.Lookups, 1)
}

func TestCheckMX(t *testing.T) {
	table := map[string]string{
		"jschmidt-org.mail.protection.outlook.com/A":    "delv/mail/mx_target_jschmidt_a.yaml",
		"jschmidt-org.mail.protection.outlook.com/AAAA": "delv/mail/mx_target_jschmidt_aaaa.yaml",
		"www.github.com/A":    "delv/www_github_cname.yaml",
		"nosuch.example/A":    "delv/nxdomain_unsigned.yaml",
		"nosuch.example/AAAA": "delv/nxdomain_unsigned.yaml",
	}
	lookup := fixtureLookup(t, table)
	mx := checkMX(parseDelvYAML(fixture(t, "delv/jschmidt_mx.yaml"), "MX"), lookup)
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

	null := checkMX(parseDelvYAML(fixture(t, "delv/microsoft_jp_net_null_mx.yaml"), "MX"), lookup)
	check(t, "lone null MX is fine", len(null[0].Problems), 0)
	mixed := checkMX(Lookup{Status: StatusOK, Records: []string{"0 .", "10 www.github.com."}}, lookup)
	check(t, "null MX mixed", contains(mixed[0].Problems, "null MX mixed"), true)
}

func TestProbeDKIM(t *testing.T) {
	table := map[string]string{
		"selector1._domainkey.jschmidt.org/TXT": "delv/mail/dkim_selector1_jschmidt.yaml",
		"selector2._domainkey.jschmidt.org/TXT": "delv/mail/dkim_selector2_jschmidt.yaml",
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
	rec := parseMTASTSRecord(parseDelvYAML(fixture(t, "delv/mail/mta_sts_gmail.yaml"), "TXT"))
	check(t, "record", rec.Record, true)
	check(t, "id", rec.ID, "20190429T010101")
	check(t, "missing", parseMTASTSRecord(parseDelvYAML(fixture(t, "delv/mail/mta_sts_jschmidt_missing.yaml"), "TXT")).Record, false)
	check(t, "tls-rpt", hasTLSRPT(parseDelvYAML(fixture(t, "delv/mail/tls_rpt_gmail.yaml"), "TXT")), true)
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
	got := checkMTASTS(context.Background(), "gmail.com", parseDelvYAML(fixture(t, "delv/mail/mta_sts_gmail.yaml"), "TXT"), []string{"gmail-smtp-in.l.google.com."}, time.Second, lookup)
	check(t, "fetched and covered", got.MXCovered, true)
	policyFetcher = func(context.Context, string, time.Duration, lookupFn) (string, error) {
		return "", errors.New("Get https://mta-sts.gmail.com/: dial tcp: lookup mta-sts.gmail.com on 10.0.0.2:53: no such host")
	}
	got = checkMTASTS(context.Background(), "gmail.com", parseDelvYAML(fixture(t, "delv/mail/mta_sts_gmail.yaml"), "TXT"), nil, time.Second, lookup)
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
		l := parseDelvYAML(fixture(t, "delv/timeout.yaml"), qtype)
		l.Name, l.Status = name, StatusTimeout
		return l
	}
	mx := checkMX(Lookup{Status: StatusOK, Records: []string{"10 mx.example."}}, timedOut)
	check(t, "marked unresolved", mx[0].Unresolved, true)
	check(t, "says so plainly", mx[0].Problems, []string{mxUnresolvedProblem})
	check(t, "not called absent", contains(mx[0].Problems, "no address"), false)

	f := &findings{}
	f.mailFindings(&MailReport{DMARC: DMARC{}, MX: mx})
	check(t, "no error", f.errors, []string(nil))
	check(t, "warned instead", contains(f.warnings, "did not complete"), true)

	// A real denial still fails the domain.
	denied := checkMX(Lookup{Status: StatusOK, Records: []string{"10 mx.example."}}, fixtureLookup(t, map[string]string{
		"mx.example/A":    "delv/nxdomain_unsigned.yaml",
		"mx.example/AAAA": "delv/nxdomain_unsigned.yaml",
	}))
	check(t, "denial is not a gap", denied[0].Unresolved, false)
	g := &findings{}
	g.mailFindings(&MailReport{DMARC: DMARC{}, MX: denied})
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
	f.mailFindings(&MailReport{DMARC: DMARC{}, MX: []MXCheck{}, DKIM: res})
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
