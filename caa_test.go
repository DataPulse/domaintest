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
	www := parseDelvYAML(fixture(t, "delv/caa/www_google.yaml"), "CAA") // NXRRSET: apex records apply
	gts := servedCert{issuer: "Google Trust Services LLC"}
	rep := assessCAA(apex, www, gts, gts)
	check(t, "apex permitted", *rep.Permitted, true)
	check(t, "issuer", rep.Issuer, "Google Trust Services LLC")
	check(t, "www inherits apex records", rep.Hosts["www"].Records, []string{`0 issue "pki.goog"`})
	check(t, "www permitted", *rep.Hosts["www"].Permitted, true)
	check(t, "top level mirrors apex", rep.Hosts["apex"].Permitted, rep.Permitted)

	// Per-host issuers: the apex is fine, www serves a certificate from a CA
	// the records forbid.
	rep = assessCAA(apex, www, gts, servedCert{issuer: "Let's Encrypt"})
	check(t, "apex still permitted", *rep.Permitted, true)
	check(t, "www forbidden", *rep.Hosts["www"].Permitted, false)
	check(t, "www issuer", rep.Hosts["www"].Issuer, "Let's Encrypt")

	rep = assessCAA(apex, www, servedCert{issuer: "Example Private CA"}, servedCert{})
	check(t, "unmapped issuer", rep.Permitted, (*bool)(nil))
	check(t, "note", rep.Note, "issuer not in the CAA mapping table")
	check(t, "www without certificate", rep.Hosts["www"].Note, "no certificate observed")
	check(t, "www permitted absent", rep.Hosts["www"].Permitted, (*bool)(nil))

	none := parseDelvYAML(fixture(t, "delv/caa/www_google.yaml"), "CAA")
	rep = assessCAA(none, none, servedCert{issuer: "Let's Encrypt"}, servedCert{issuer: "Let's Encrypt"})
	check(t, "no CAA means any CA may issue", *rep.Permitted, true)
	check(t, "no CAA note", rep.Note, "no CAA records; any CA may issue")
	check(t, "empty record lists, not null", []int{len(rep.Apex), len(rep.WWW)}, []int{0, 0})
	check(t, "apex list non-nil", rep.Apex != nil, true)

	// www with its own CAA overrides the apex policy.
	rep = assessCAA(apex, parseDelvYAML(fixture(t, "delv/caa/cloudflare.yaml"), "CAA"), gts, servedCert{issuer: "DigiCert Inc"})
	check(t, "www policy wins", *rep.Hosts["www"].Permitted, true)
	rep = assessCAA(apex, parseDelvYAML(fixture(t, "delv/caa/cloudflare.yaml"), "CAA"), gts, servedCert{issuer: "Amazon"})
	check(t, "www policy forbids amazon", *rep.Hosts["www"].Permitted, false)
	// Wildcard leaf on www consults issuewild.
	rep = assessCAA(apex, parseDelvYAML(fixture(t, "delv/caa/cloudflare.yaml"), "CAA"), gts, servedCert{issuer: "Let's Encrypt", wildcard: true})
	check(t, "issuewild honoured", *rep.Hosts["www"].Permitted, true)
}
