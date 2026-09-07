package main

import "testing"

func TestParseCAA(t *testing.T) {
	recs := parseCAA(parseDelvYAML(fixture(t, "delv/caa/cloudflare.yaml"), "CAA").Records)
	check(t, "eleven records", len(recs), 11)
	var issue, issuewild, iodef int
	for _, r := range recs {
		switch r.Tag {
		case "issue":
			issue++
		case "issuewild":
			issuewild++
		case "iodef":
			iodef++
		}
		check(t, "flags", r.Flags, 0)
	}
	check(t, "tag mix", []int{issue, issuewild, iodef}, []int{5, 5, 1})
	g := parseCAA(parseDelvYAML(fixture(t, "delv/caa/google.yaml"), "CAA").Records)
	check(t, "google", g, []caaRecord{{Flags: 0, Tag: "issue", Value: "pki.goog"}})
	check(t, "garbage ignored", len(parseCAA([]string{"0 issue", "", "x"})), 0)
	check(t, "parameters kept in value", parseCAA([]string{`0 issue "digicert.com; cansignhttpexchanges=yes"`})[0].Value, "digicert.com; cansignhttpexchanges=yes")
}

func TestCAAIDsFor(t *testing.T) {
	check(t, "Let's Encrypt", caaIDsFor("Let's Encrypt"), []string{"letsencrypt.org"})
	check(t, "Google", caaIDsFor("Google Trust Services LLC"), []string{"pki.goog"})
	check(t, "Sectigo", caaIDsFor("Sectigo Limited"), []string{"sectigo.com", "comodoca.com"})
	// DigiCert issues under the brands it acquired and honours each one's
	// CAA identifier, so all of them permit a DigiCert certificate.
	check(t, "DigiCert", caaIDsFor("DigiCert Inc"),
		[]string{"digicert.com", "digicert.ne.jp", "geotrust.com", "rapidssl.com", "symantec.com", "thawte.com"})
	check(t, "unknown", caaIDsFor("Example Private CA"), []string(nil))
	// cisco.com is issued by IdenTrust's HydrantID service: "entrust" must
	// not match inside "IdenTrust".
	check(t, "IdenTrust", caaIDsFor("IdenTrust"), []string{"identrust.com"})
	check(t, "Entrust", caaIDsFor("Entrust, Inc."), []string{"entrust.net"})
	check(t, "Amazon", caaIDsFor("Amazon"), []string{"amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com"})
	check(t, "Let's Encrypt with suffix", caaIDsFor("Let's Encrypt"), []string{"letsencrypt.org"})
	check(t, "GoDaddy with punctuation", caaIDsFor("GoDaddy.com, Inc."), []string{"godaddy.com"})
	check(t, "Starfield", caaIDsFor("Starfield Technologies, Inc."), []string{"godaddy.com", "starfieldtech.com"})
	check(t, "SSL Corp", caaIDsFor("SSL Corporation"), []string{"ssl.com"})
	check(t, "ISRG", caaIDsFor("Internet Security Research Group"), []string{"letsencrypt.org"})
}

func TestCAAPermits(t *testing.T) {
	cf := parseCAA(parseDelvYAML(fixture(t, "delv/caa/cloudflare.yaml"), "CAA").Records)
	check(t, "digicert allowed at cloudflare.com", caaPermits(cf, caaIDsFor("DigiCert Inc"), false), true)
	check(t, "sectigo (comodoca) allowed", caaPermits(cf, caaIDsFor("Sectigo Limited"), false), true)
	check(t, "amazon not allowed", caaPermits(cf, caaIDsFor("Amazon"), false), false)
	check(t, "wildcard uses issuewild", caaPermits(cf, caaIDsFor("Let's Encrypt"), true), true)

	g := parseCAA([]string{`0 issue "pki.goog"`})
	check(t, "google ok", caaPermits(g, []string{"pki.goog"}, false), true)
	check(t, "letsencrypt blocked", caaPermits(g, []string{"letsencrypt.org"}, false), false)
	check(t, "wildcard falls back to issue without issuewild", caaPermits(g, []string{"pki.goog"}, true), true)
	check(t, "issue ; forbids everyone", caaPermits(parseCAA([]string{`0 issue ";"`}), []string{"pki.goog"}, false), false)
	check(t, "iodef only is unrestricted", caaPermits(parseCAA([]string{`0 iodef "mailto:a@b"`}), []string{"pki.goog"}, false), true)
	check(t, "parameters stripped", caaPermits(parseCAA([]string{`0 issue "digicert.com; cansignhttpexchanges=yes"`}), []string{"digicert.com"}, false), true)
}

func TestAssessCAA(t *testing.T) {
	apex := parseDelvYAML(fixture(t, "delv/caa/google.yaml"), "CAA")
	www := parseDelvYAML(fixture(t, "delv/caa/www_google.yaml"), "CAA") // NXRRSET: nothing published
	gts := servedCert{issuer: "Google Trust Services LLC"}

	rep := assessCAA(apex, www, gts, gts)
	check(t, "one verdict per host", len(rep.Hosts), 2)
	a, w := rep.Hosts["apex"], rep.Hosts["www"]
	check(t, "apex published", a.Published, []string{`0 issue "pki.goog"`})
	check(t, "apex effective is its own set", a.Effective, a.Published)
	check(t, "apex permitted", *a.Permitted, true)
	// www publishes nothing but is governed by the apex set.
	check(t, "www publishes nothing", w.Published, []string{})
	check(t, "www effective climbs to the apex", w.Effective, []string{`0 issue "pki.goog"`})
	check(t, "www permitted", *w.Permitted, true)

	// Per-host issuers: the apex is fine, www serves a certificate the
	// records forbid.
	rep = assessCAA(apex, www, gts, servedCert{issuer: "Let's Encrypt"})
	check(t, "apex still permitted", *rep.Hosts["apex"].Permitted, true)
	check(t, "www forbidden", *rep.Hosts["www"].Permitted, false)
	check(t, "www issuer", rep.Hosts["www"].Issuer, "Let's Encrypt")

	// Unjudgeable cases carry a note and no verdict.
	rep = assessCAA(apex, www, servedCert{issuer: "Example Private CA"}, servedCert{})
	check(t, "unmapped issuer", rep.Hosts["apex"].Permitted, (*bool)(nil))
	check(t, "note", rep.Hosts["apex"].Note, "issuer not in the CAA mapping table")
	check(t, "www without a certificate", rep.Hosts["www"].Note, "no certificate observed")
	check(t, "www permitted absent", rep.Hosts["www"].Permitted, (*bool)(nil))

	// No CAA anywhere: any CA may issue.
	none := parseDelvYAML(fixture(t, "delv/caa/www_google.yaml"), "CAA")
	rep = assessCAA(none, none, servedCert{issuer: "Let's Encrypt"}, servedCert{issuer: "Let's Encrypt"})
	check(t, "permitted without records", *rep.Hosts["apex"].Permitted, true)
	check(t, "note", rep.Hosts["apex"].Note, "no CAA records; any CA may issue")
	check(t, "empty lists, not null", []bool{rep.Hosts["www"].Published != nil, rep.Hosts["www"].Effective != nil}, []bool{true, true})

	// www with its own records is governed by them, not by the apex.
	cf := parseDelvYAML(fixture(t, "delv/caa/cloudflare.yaml"), "CAA")
	rep = assessCAA(apex, cf, gts, servedCert{issuer: "DigiCert Inc"})
	check(t, "www published is its own", len(rep.Hosts["www"].Published), 11)
	check(t, "www effective equals published", rep.Hosts["www"].Effective, rep.Hosts["www"].Published)
	check(t, "www policy permits digicert", *rep.Hosts["www"].Permitted, true)
	rep = assessCAA(apex, cf, gts, servedCert{issuer: "Amazon"})
	check(t, "www policy forbids amazon", *rep.Hosts["www"].Permitted, false)
	// A wildcard leaf consults issuewild.
	rep = assessCAA(apex, cf, gts, servedCert{issuer: "Let's Encrypt", wildcard: true})
	check(t, "issuewild honoured", *rep.Hosts["www"].Permitted, true)
}

// A wildcard certificate must satisfy issuewild, not issue: apache.org
// permits Let's Encrypt to issue but restricts wildcards to ssl.com, and
// serves a Let's Encrypt wildcard on www.
func TestAssessCAA_WildcardUsesIssuewild(t *testing.T) {
	records := Lookup{Status: StatusOK, Records: []string{
		`0 issue "letsencrypt.org"`, `0 issue "ssl.com"`, `0 issuewild "ssl.com"`,
	}}
	none := Lookup{Status: StatusNXRRSet}
	rep := assessCAA(records, none, servedCert{issuer: "Let's Encrypt"}, servedCert{issuer: "Let's Encrypt", wildcard: true})
	check(t, "apex non-wildcard permitted", *rep.Hosts["apex"].Permitted, true)
	check(t, "www wildcard forbidden", *rep.Hosts["www"].Permitted, false)
}

// "Any CA may issue" is a security-relevant all-clear and must come from a
// zone that answered, never from a query that failed.
func TestAssessCAA_UnansweredIsNotUnrestricted(t *testing.T) {
	cert := servedCert{issuer: "Let's Encrypt"}
	rep := assessCAA(Lookup{Status: StatusTimeout}, Lookup{Status: StatusTimeout}, cert, cert)
	for _, host := range []string{"apex", "www"} {
		v := rep.Hosts[host]
		check(t, host+": no verdict", v.Permitted == nil, true)
		check(t, host+": says why", v.Note, "the CAA lookup did not complete, so no restriction can be ruled out")
	}

	// A zone that answered with no CAA really is unrestricted.
	answered := assessCAA(Lookup{Status: StatusNXRRSet}, Lookup{Status: StatusNXRRSet}, cert, cert)
	check(t, "answered absence permits", *answered.Hosts["apex"].Permitted, true)
	check(t, "and says so", answered.Hosts["apex"].Note, "no CAA records; any CA may issue")

	// www must not inherit the apex policy on the strength of a failed
	// lookup: we do not know what www publishes.
	apex := Lookup{Status: StatusOK, Records: []string{`0 issue "ssl.com"`}}
	mixed := assessCAA(apex, Lookup{Status: StatusTimeout}, cert, cert)
	check(t, "no climb from a failed lookup", mixed.Hosts["www"].Effective, []string{})
	check(t, "www unknown", mixed.Hosts["www"].Permitted == nil, true)
	check(t, "apex still judged", *mixed.Hosts["apex"].Permitted, false)
}

// A CA that issues under several brands honours each brand's CAA
// identifier. posteo.de permits geotrust.com and is served a certificate
// whose organisation reads DigiCert Inc, which is a legitimate GeoTrust
// issuance and was reported as a CAA violation.
func TestCAAIssuers_BrandIdentifiers(t *testing.T) {
	permitted := func(org string, records []string) *bool {
		v := caaVerdict(Lookup{Status: StatusOK, Records: records}, records, servedCert{issuer: org})
		return v.Permitted
	}
	for _, c := range []struct {
		org, id string
	}{
		{"DigiCert Inc", "geotrust.com"},
		{"DigiCert Inc", "thawte.com"},
		{"DigiCert Inc", "rapidssl.com"},
		{"DigiCert Inc", "digicert.com"},
		{"GeoTrust Inc.", "geotrust.com"},
		{"GeoTrust Inc.", "digicert.com"},
		{"Thawte", "thawte.com"},
	} {
		p := permitted(c.org, []string{`0 issue "` + c.id + `"`})
		if p == nil || !*p {
			t.Errorf("%s issuing under %q reported as forbidden", c.org, c.id)
		}
	}

	// A brand the CA does not operate is still forbidden.
	p := permitted("DigiCert Inc", []string{`0 issue "letsencrypt.org"`})
	check(t, "an unrelated CA is still refused", p != nil && !*p, true)
}
