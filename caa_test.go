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
	check(t, "DigiCert", caaIDsFor("DigiCert Inc"), []string{"digicert.com"})
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
