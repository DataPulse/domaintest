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
	check(t, "no problems", j.Problems, []string(nil))

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
	policyFetcher = func(context.Context, string, time.Duration) (string, error) { return policy, nil }
	got := checkMTASTS(context.Background(), "gmail.com", parseDelvYAML(fixture(t, "delv/mail/mta_sts_gmail.yaml"), "TXT"), []string{"gmail-smtp-in.l.google.com."}, time.Second)
	check(t, "fetched and covered", got.MXCovered, true)
	policyFetcher = func(context.Context, string, time.Duration) (string, error) { return "", errors.New("boom") }
	got = checkMTASTS(context.Background(), "gmail.com", parseDelvYAML(fixture(t, "delv/mail/mta_sts_gmail.yaml"), "TXT"), nil, time.Second)
	check(t, "fetch error", strings.Contains(got.Error, "boom"), true)
	got = checkMTASTS(context.Background(), "x.org", Lookup{}, nil, time.Second)
	check(t, "no record no fetch", got.Record, false)
}

func TestMXHosts(t *testing.T) {
	check(t, "hosts", mxHosts(Lookup{Records: []string{"10 b.example.", "5 a.example.", "0 ."}}), []string{"a.example.", "b.example."})
}
