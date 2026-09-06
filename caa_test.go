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
	www := parseDelvYAML(fixture(t, "delv/caa/www_google.yaml"), "CAA")
	rep := assessCAA(apex, www, "Google Trust Services LLC", false)
	check(t, "permitted", *rep.Permitted, true)
	check(t, "issuer", rep.Issuer, "Google Trust Services LLC")
	rep = assessCAA(apex, www, "Let's Encrypt", false)
	check(t, "not permitted", *rep.Permitted, false)
	rep = assessCAA(apex, www, "Example Private CA", false)
	check(t, "unmapped issuer", rep.Permitted, (*bool)(nil))
	check(t, "note", rep.Note, "issuer not in the CAA mapping table")
	none := parseDelvYAML(fixture(t, "delv/caa/www_google.yaml"), "CAA") // NXRRSET
	rep = assessCAA(none, none, "Let's Encrypt", false)
	check(t, "no CAA", rep.Permitted, (*bool)(nil))
	check(t, "no CAA note", rep.Note, "no CAA records; any CA may issue")
	rep = assessCAA(apex, www, "", false)
	check(t, "no cert", rep.Note, "no certificate observed")
	// www with its own CAA overrides the apex policy.
	rep = assessCAA(apex, parseDelvYAML(fixture(t, "delv/caa/cloudflare.yaml"), "CAA"), "DigiCert Inc", false)
	check(t, "www policy wins", *rep.Permitted, true)
}
