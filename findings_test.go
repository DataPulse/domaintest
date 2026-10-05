package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// replayFixture loads a captured report and rebuilds its findings from the
// report's own sections, returning the report and the errors and warnings
// it was captured with.
func replayFixture(t *testing.T, path string) (rep *Report, oldErrors, oldWarnings []string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	rep = &Report{}
	if err := json.Unmarshal(b, rep); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	oldErrors, oldWarnings = rep.Errors, rep.Warnings
	buildFindings(rep)
	return rep, oldErrors, oldWarnings
}

var codeShape = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)

// A code is a promise about severity as well as meaning: a consumer that
// learns apex_nxdomain is a fail must never meet it as info. Every code
// literal in report.go is checked against every other use of it.
func TestFindings_OneSeverityPerCode(t *testing.T) {
	src, err := os.ReadFile("report.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	use := regexp.MustCompile(`f\.(fail|warn|info)\("([a-z0-9_]+)"`)
	for _, m := range use.FindAllStringSubmatch(string(src), -1) {
		if prev, ok := seen[m[2]]; ok && prev != m[1] {
			t.Errorf("code %s is both %s and %s", m[2], prev, m[1])
		}
		seen[m[2]] = m[1]
	}
	for _, c := range spfClasses {
		if prev, ok := seen[c.code]; ok && prev != c.sev {
			t.Errorf("code %s is both %s and %s", c.code, prev, c.sev)
		}
		seen[c.code] = c.sev
	}
	if len(seen) < 60 {
		t.Errorf("found only %d codes; the scan has stopped matching the source", len(seen))
	}
}

// The contract consumers hold us to: fail is exactly errors and warn is
// exactly warnings, in order, ok is "no fail", and info appears in
// findings only. Every captured report is replayed. None may gain or lose
// an error, because a consumer turns a row red on errors alone, and every
// warning still emitted must be one the report was captured with: the
// arrays only shrink, by the info entries and the fixed false positives.
func TestFindings_ParityWithLegacyArrays(t *testing.T) {
	paths, _ := filepath.Glob("testdata/reports/*.json")
	if len(paths) < 10 {
		t.Fatalf("expected the captured reports, found %d", len(paths))
	}
	// A zone no delegated server answers for is reported as that one fact.
	collapsed := map[string]bool{"skvr.site.json": true, "login-microsoft-virtualperu.com.json": true}
	for _, p := range paths {
		name := filepath.Base(p)
		rep, oldErrors, oldWarnings := replayFixture(t, p)
		if collapsed[name] {
			check(t, name+": was already red", len(oldErrors) > 0, true)
			check(t, name+": one error", len(rep.Errors), 1)
			check(t, name+": no warnings", rep.Warnings, []string{})
		} else {
			check(t, name+": errors unchanged", rep.Errors, oldErrors)
			check(t, name+": warnings only shrink", isSubsequence(rep.Warnings, oldWarnings), true)
		}
		var fails, warns []string
		anyFail := false
		for _, f := range rep.Findings {
			switch f.Severity {
			case SeverityFail:
				fails = append(fails, f.Message)
				anyFail = true
			case SeverityWarn:
				warns = append(warns, f.Message)
			case SeverityInfo:
				if contains(rep.Warnings, f.Message) {
					t.Errorf("%s: info %s is listed in warnings", name, f.Code)
				}
			default:
				t.Errorf("%s: severity %q outside the closed set", name, f.Severity)
			}
			if !codeShape.MatchString(f.Code) {
				t.Errorf("%s: code %q is not snake_case", name, f.Code)
			}
		}
		check(t, name+": fail is errors", nonNil(fails), rep.Errors)
		check(t, name+": warn is warnings", nonNil(warns), rep.Warnings)
		check(t, name+": ok is no fail", rep.OK, !anyFail)
	}
}

// isSubsequence reports whether every element of sub appears in seq, in
// order.
func isSubsequence(sub, seq []string) bool {
	i := 0
	for _, s := range seq {
		if i < len(sub) && sub[i] == s {
			i++
		}
	}
	return i == len(sub)
}

// warnCodes is the sorted set of warn-severity codes in a report: what
// turns a consumer's dot yellow once it reads severities.
func warnCodes(rep *Report) []string {
	set := map[string]bool{}
	for _, f := range rep.Findings {
		if f.Severity == SeverityWarn {
			set[f.Code] = true
		}
	}
	out := []string{}
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Calibration against live reports of well-run domains captured on
// 2026-10-05, and of parked defensive registrations from a real portfolio.
// A flagship keeps a warning only for a defect we would tell its operator
// about; configuration choices they make deliberately are info.
func TestFindings_FlagshipCalibration(t *testing.T) {
	cases := []struct {
		file string
		warn []string
	}{
		{"wikipedia.org.json", []string{}}, // 90-day ACME cert at 29 days is info
		{"nic.cz.json", []string{}},
		{"oracle.com.json", []string{}}, // WAF 403s, no TLS 1.3, SPF size: all info
		{"sap.com.json", []string{}},
		{"icann.org.json", []string{}},       // p=none and WAF 403s are info
		{"docs.github.com.json", []string{}}, // covered by github.com's preload entry
		{"app.slack.com.json", []string{}},   // www.app.slack.com is nobody's name
		{"microsoft.com.json", []string{"http_cleartext"}},
		{"google.com.json", []string{"http_cleartext", "http_redirect_insecure"}},
		{"facebook.com.json", []string{"dkim_selector_revoked"}},
		{"microsoft.ar.json", []string{"apex_no_address", "spf_absent"}},
		{"microsoft.org.json", []string{"dmarc_absent"}},
		{"nikonic.net.json", []string{"apex_no_address", "dmarc_absent", "spf_absent"}},
		{"microsoftdrive.com.json", []string{"dmarc_absent", "spf_absent"}},
	}
	for _, c := range cases {
		rep, _, _ := replayFixture(t, filepath.Join("testdata/reports", c.file))
		check(t, c.file+": warn codes", warnCodes(rep), c.warn)
	}
}

// Messages are technical facts only: advice and citations belong to the
// consumer, which maps codes to whatever guidance it shows. A parked
// domain's missing SPF and DMARC are warn, in the same words as anywhere.
func TestFindings_ParkedMailAuthIsAPlainFact(t *testing.T) {
	for _, file := range []string{"microsoft.ar.json", "microsoft.org.json", "nikonic.net.json", "microsoftdrive.com.json"} {
		rep, _, oldWarnings := replayFixture(t, filepath.Join("testdata/reports", file))
		for _, f := range rep.Findings {
			switch f.Code {
			case "spf_absent":
				check(t, file+": spf text", f.Message, "no SPF (v=spf1) record in apex TXT")
			case "dmarc_absent":
				check(t, file+": dmarc text", f.Message, "no DMARC record")
			default:
				continue
			}
			check(t, file+": "+f.Code+" is warn", f.Severity, SeverityWarn)
			check(t, file+": text unchanged from capture", contains(oldWarnings, f.Message), true)
		}
	}
}

func TestProbeRefused(t *testing.T) {
	for _, s := range []int{401, 403, 407, 417, 429} {
		check(t, "refused", probeRefused(s), true)
	}
	for _, s := range []int{200, 301, 400, 404, 410, 421, 500, 503} {
		check(t, "not a refusal", probeRefused(s), false)
	}
}

func findingCodes(f *findings) []string {
	out := []string{}
	for _, x := range f.list {
		out = append(out, x.Severity+":"+x.Code)
	}
	return out
}

// A WAF answering the probe's User-Agent with 403 says nothing about the
// site. A 404 is broken for every client, so it still warns, and a mix of
// the two is still a client error on every address.
func TestStatusFindings_RefusalIsNotBreakage(t *testing.T) {
	at := func(statuses ...int) []AddrWeb {
		var out []AddrWeb
		for i, s := range statuses {
			out = append(out, AddrWeb{IP: "192.0.2." + string(rune('1'+i)), HTTPSRes: &HTTPResult{Status: s}})
		}
		return out
	}
	pick := func(a AddrWeb) *HTTPResult { return a.HTTPSRes }
	cases := []struct {
		statuses []int
		want     []string
	}{
		{[]int{403, 403}, []string{"info:http_probe_refused"}},
		{[]int{429}, []string{"info:http_probe_refused"}},
		{[]int{404, 404}, []string{"warn:http_client_error"}},
		{[]int{403, 404}, []string{"warn:http_client_error"}},
		{[]int{403, 200}, []string{}},
		{[]int{503, 503}, []string{"fail:http_server_error"}},
		{[]int{503, 403}, []string{"warn:http_server_error_partial"}},
	}
	for _, c := range cases {
		f := &findings{}
		f.statusFindings("www", "443", at(c.statuses...), pick)
		check(t, "statuses", findingCodes(f), c.want)
	}
	f := &findings{}
	f.statusFindings("www", "443", at(429, 403, 403), pick)
	check(t, "names the statuses seen", f.list[0].Message, "www: every address refuses the probe on port 443 (HTTP 403/429), so the content was not verified")
	check(t, "info is not a warning", f.warnings, []string(nil))
}

func TestRedirectFindings_RefusedDestination(t *testing.T) {
	chain := func(final int) map[string]*RedirectChain {
		return map[string]*RedirectChain{familyIPv4: {
			Hops:     []RedirectHop{{URL: "http://example.com/", Status: 301}, {URL: "https://www.example.com/", Status: final}},
			FinalURL: "https://www.example.com/",
		}}
	}
	f := &findings{}
	f.redirectFindings("apex", chain(403))
	check(t, "403 is the probe refused", findingCodes(f), []string{"info:http_probe_refused"})
	check(t, "and says so", strings.Contains(f.list[0].Message, "the server refused the probe"), true)
	g := &findings{}
	g.redirectFindings("apex", chain(404))
	check(t, "404 is a broken destination", findingCodes(g), []string{"warn:redirect_ends_error"})
}

// ACME certificates live 90 days and renew with 30 left, so "under 30
// days" is a third of every healthy certificate's life. Only the last week
// is a warning.
func TestExpiryFindings_Boundary(t *testing.T) {
	for _, c := range []struct {
		days int
		want []string
	}{
		{6, []string{"warn:cert_expiry_urgent"}},
		{7, []string{"info:cert_expiry_soon"}},
		{8, []string{"info:cert_expiry_soon"}},
		{29, []string{"info:cert_expiry_soon"}},
		{30, []string{}},
	} {
		f := &findings{}
		f.expiryFindings("apex", []AddrWeb{{IP: "192.0.2.1", TLS: &TLSResult{Chain: ChainValid, Cert: &CertInfo{DaysRemaining: c.days}}}})
		check(t, "expiry", findingCodes(f), c.want)
	}
}

func TestWildcardFindings_OnlyBesideARegistrableDomain(t *testing.T) {
	wild := &WildcardReport{WWWViaWildcard: true}
	f := &findings{}
	f.wildcardFindings(&Report{Domain: "slack.com", Wildcard: wild})
	check(t, "registrable domain", findingCodes(f), []string{"info:www_wildcard"})
	for _, host := range []string{"app.slack.com", "s3.amazonaws.com"} {
		g := &findings{}
		g.wildcardFindings(&Report{Domain: host, Wildcard: wild})
		check(t, "not registrable: "+host, findingCodes(g), []string{})
	}
}

// The header requirement belongs to the preload entry. A name covered by
// an ancestor's include_subdomains owes nothing on its own response.
func TestPreloadFindings_CoveredSubdomainOwesNoHeader(t *testing.T) {
	rep := &Report{
		Domain:               "docs.github.com",
		HSTSPreload:          PreloadPreloaded,
		HSTSPreloadCoveredBy: "github.com",
		HSTSPreloadPolicy:    "bulk-18-weeks",
		Web: WebSection{Apex: &HostWeb{IPv4: []AddrWeb{{IP: "192.0.2.1",
			HTTPSRes: &HTTPResult{Status: 200, HSTS: &HSTS{MaxAge: 31536000}}}}}},
	}
	f := &findings{}
	f.preloadFindings(rep)
	check(t, "covered subdomain", findingCodes(f), []string{})
	rep.HSTSPreloadCoveredBy = ""
	g := &findings{}
	g.preloadFindings(rep)
	check(t, "the entry itself", findingCodes(g), []string{"warn:hsts_preload_header_weak"})
}

// Port 80 on a preloaded host is never reached by a browser, so serving
// it in the clear is a fact. www is known covered only through an
// ancestor entry.
func TestCleartextFindings_PreloadDecides(t *testing.T) {
	open80 := []AddrWeb{{IP: "192.0.2.1", HTTPRes: &HTTPResult{Status: 200}}}
	for _, c := range []struct {
		preload, coveredBy string
		apex, www          string
	}{
		{PreloadAbsent, "", "warn", "warn"},
		{PreloadUnknown, "", "warn", "warn"},
		{PreloadPreloaded, "", "info", "warn"},
		{PreloadPreloaded, "google.com", "info", "info"},
	} {
		apex, www := preloadCovers(&Report{HSTSPreload: c.preload, HSTSPreloadCoveredBy: c.coveredBy})
		f := &findings{}
		f.cleartextFindings("apex", open80, apex)
		f.cleartextFindings("www", open80, www)
		code := func(sev string) string {
			if sev == SeverityInfo {
				return "info:http_cleartext_preloaded"
			}
			return "warn:http_cleartext"
		}
		check(t, c.preload+"/"+c.coveredBy, findingCodes(f), []string{code(c.apex), code(c.www)})
	}
}

// problemTemplates pulls every problem sentence mail.go can emit for one
// collection, so a new problem added there without a code fails here
// instead of shipping under a catch-all.
func problemTemplates(t *testing.T, target string) []string {
	t.Helper()
	src, err := os.ReadFile("mail.go")
	if err != nil {
		t.Fatal(err)
	}
	line := regexp.MustCompile(regexp.QuoteMeta(target) + ` = append\(` + regexp.QuoteMeta(target) + `, (.*)\)$`)
	literal := regexp.MustCompile(`"([^"]*)"`)
	fill := strings.NewReplacer("%d", "600", "%s", "x.example", "%v", "bad label", "%%", "%")
	var out []string
	for _, l := range strings.Split(string(src), "\n") {
		m := line.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		// "include:"+target+" has no SPF record": the pieces between
		// literals are names, so the sentence is the literals joined by one.
		var parts []string
		for _, lit := range literal.FindAllStringSubmatch(m[1], -1) {
			parts = append(parts, lit[1])
		}
		if len(parts) == 0 {
			continue // a named constant, such as mxUnresolvedProblem, coded at its use
		}
		out = append(out, fill.Replace(strings.Join(parts, "x.example")))
	}
	if len(out) == 0 {
		t.Fatalf("no templates found for %s", target)
	}
	return out
}

func TestProblemCodes_EveryTemplateClassified(t *testing.T) {
	for _, p := range problemTemplates(t, "e.problems") {
		code, sev := spfProblemClass(p)
		if code == "spf_problem" || code == "spf_invalid" {
			t.Errorf("SPF problem has no code of its own: %q", p)
		}
		if strings.Contains(p, "permerror") && sev != SeverityFail {
			t.Errorf("permerror must fail: %q is %s", p, sev)
		}
	}
	for _, p := range problemTemplates(t, "c.Problems") {
		if mxProblemCode(p) == "mx_invalid" {
			t.Errorf("MX problem has no code of its own: %q", p)
		}
	}
	for _, p := range problemTemplates(t, "d.Problems") {
		if dmarcProblemCode(p) == "dmarc_invalid" {
			t.Errorf("DMARC problem has no code of its own: %q", p)
		}
	}
}

func TestSPFProblemClass(t *testing.T) {
	for _, c := range []struct{ problem, code, sev string }{
		{"multiple SPF records (permerror: SPF fails entirely)", "spf_multiple", SeverityFail},
		{"12 DNS lookups exceed the limit of 10 (permerror: SPF fails entirely)", "spf_lookup_limit", SeverityFail},
		{"3 void lookups exceed the limit of 2", "spf_void_limit", SeverityWarn},
		{"+all authorises every sender (no protection)", "spf_pass_all", SeverityFail},
		{"?all is neutral (no protection)", "spf_neutral_all", SeverityWarn},
		{"apex TXT answer is 4633 octets, over the 512-octet UDP limit (RFC 7208 §3.4): resolvers without EDNS get a truncated reply and must retry over TCP", "spf_txt_over_udp_limit", SeverityInfo},
		{"apex TXT answer is 480 octets, close to the 512-octet UDP limit (RFC 7208 §3.4): one more TXT record may push it over", "spf_txt_near_udp_limit", SeverityInfo},
		{"include:stspg-customer.com TXT answer is 617 octets, over the 512-octet UDP limit (RFC 7208 §3.4)", "spf_include_txt_over_udp_limit", SeverityInfo},
		{"include:_spf.example.com has no SPF record", "spf_include_missing", SeverityWarn},
		{"something new (permerror)", "spf_invalid", SeverityFail},
		{"something new", "spf_problem", SeverityWarn},
	} {
		code, sev := spfProblemClass(c.problem)
		check(t, c.problem, code+"/"+sev, c.code+"/"+c.sev)
	}
}

// The JSON shape consumers parse: the key is always present, and an empty
// report says [] rather than null.
func TestFindings_SerialisedShape(t *testing.T) {
	rep := healthyReport(t)
	buildFindings(rep)
	out, _ := json.Marshal(rep)
	check(t, "empty findings is []", strings.Contains(string(out), `"findings":[]`), true)

	rep, _, _ = replayFixture(t, "testdata/reports/microsoft.com.json")
	out, _ = json.Marshal(rep.Findings[0])
	check(t, "finding shape", string(out), `{"code":"http_cleartext","severity":"warn","host":"www","message":"www: HTTP serves content in the clear instead of redirecting to HTTPS (4 of 4 addresses)"}`)
}

// A zone whose delegated servers all refuse or stay silent cannot answer
// any other question, so the report is that one fact and not a dozen
// restatements of it (skvr.site carried six errors and two warnings, every
// one a symptom). Captured from a real portfolio, 2026-09/10.
func TestZoneUnreachable_OneFinding(t *testing.T) {
	rep, _, _ := replayFixture(t, "testdata/reports/skvr.site.json")
	check(t, "refusing zone", findingCodes(&findings{list: rep.Findings}), []string{"fail:zone_unreachable"})
	check(t, "names what each server did", rep.Errors, []string{"no delegated nameserver answers for the zone: " +
		"ns-1119.awsdns-11.org. not authoritative (REFUSED) on 2 of 2 addresses; " +
		"ns-1720.awsdns-23.co.uk. not authoritative (REFUSED) on 2 of 2 addresses; " +
		"ns-316.awsdns-39.com. not authoritative (REFUSED) on 2 of 2 addresses; " +
		"ns-840.awsdns-41.net. not authoritative (REFUSED) on 2 of 2 addresses"})
	check(t, "ok is false", rep.OK, false)

	rep, _, _ = replayFixture(t, "testdata/reports/login-microsoft-virtualperu.com.json")
	check(t, "silent zone", findingCodes(&findings{list: rep.Findings}), []string{"fail:zone_unreachable"})
	check(t, "says silent", contains(rep.Errors, "no answer on"), true)
}

// One authoritative server is enough for the zone to work, and a zone that
// answers with no NS records answered: neither collapses.
func TestZoneUnreachable_NotWhenAnythingAnswers(t *testing.T) {
	for _, file := range []string{"oraclehealth.com.json", "iboracle.com.json"} {
		rep, oldErrors, _ := replayFixture(t, filepath.Join("testdata/reports", file))
		check(t, file+": not collapsed", zoneUnreachable(rep), false)
		check(t, file+": errors unchanged", rep.Errors, oldErrors)
	}
}

func TestZoneUnreachable_Guards(t *testing.T) {
	silent := Delegation{Status: DelegationNoChildAnswer, ParentServer: "a.gtld-servers.net"}
	failed := Lookup{Status: StatusTimeout}
	check(t, "silent delegation", delegationSilent(silent, failed), true)
	check(t, "no referral: our network, not theirs", delegationSilent(Delegation{Status: DelegationNoChildAnswer}, failed), false)
	check(t, "NODATA is an answer", delegationSilent(silent, Lookup{Status: StatusNXRRSet}), false)

	refused := NSServer{Name: "ns1.example.", IP: "192.0.2.1", Error: "not authoritative (REFUSED)"}
	check(t, "all refusing", noServerAnswers(&NSReport{Servers: []NSServer{refused}}), true)
	check(t, "no address counts", noServerAnswers(&NSReport{Unresolvable: []string{"ns1.example."}}), true)
	check(t, "one answers", noServerAnswers(&NSReport{Servers: []NSServer{refused, {Name: "ns2.example.", AA: true}}}), false)
	check(t, "an unfinished lookup leaves it open", noServerAnswers(&NSReport{Servers: []NSServer{refused}, Unresolved: []string{"ns2.example."}}), false)
	check(t, "nothing examined", noServerAnswers(&NSReport{}), false)
	check(t, "no audit", noServerAnswers(nil), false)
}

// A TLSA lookup that did not complete saw no record, so there is nothing
// to call unsigned. All 794 portfolio reports carrying the unsigned-zone
// finding were this case.
func TestTLSAFindings_UnknownSaysNothing(t *testing.T) {
	f := &findings{}
	f.tlsaFindings(&TLSAReport{Apex: []string{}, WWW: []string{}, Result: TLSAUnknown})
	check(t, "unknown", findingCodes(f), []string{})
	g := &findings{}
	g.tlsaFindings(&TLSAReport{Apex: []string{"3 1 1 ab"}, WWW: []string{}, Result: "unverified"})
	check(t, "records in an unsigned zone", findingCodes(g), []string{"info:tlsa_unsigned_zone"})
}
