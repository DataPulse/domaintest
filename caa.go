package main

import (
	"strconv"
	"strings"
)

// caaRecord is one parsed CAA RR.
type caaRecord struct {
	Flags int
	Tag   string
	Value string
}

// parseCAA parses rdata of the form `0 issue "letsencrypt.org"`.
func parseCAA(records []string) []caaRecord {
	var out []caaRecord
	for _, r := range records {
		f := strings.Fields(r)
		if len(f) < 3 {
			continue
		}
		flags, _ := strconv.Atoi(f[0])
		value := strings.Trim(strings.Join(f[2:], " "), `"`)
		out = append(out, caaRecord{Flags: flags, Tag: strings.ToLower(f[1]), Value: value})
	}
	return out
}

// caaIssuers maps a lower-cased fragment of the certificate issuer's
// organisation to the CAA identifiers that CA honours.
var caaIssuers = []struct {
	match string
	ids   []string
}{
	{"let's encrypt", []string{"letsencrypt.org"}},
	{"internet security research group", []string{"letsencrypt.org"}},
	{"digicert", []string{"digicert.com"}},
	{"sectigo", []string{"sectigo.com", "comodoca.com"}},
	{"comodo", []string{"sectigo.com", "comodoca.com"}},
	{"zerossl", []string{"sectigo.com", "comodoca.com"}},
	{"globalsign", []string{"globalsign.com"}},
	{"google trust services", []string{"pki.goog"}},
	{"amazon", []string{"amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com"}},
	{"godaddy", []string{"godaddy.com"}},
	{"starfield", []string{"godaddy.com", "starfieldtech.com"}},
	{"entrust", []string{"entrust.net"}},
	{"identrust", []string{"identrust.com"}},
	{"ssl.com", []string{"ssl.com"}},
	{"ssl corporation", []string{"ssl.com"}},
	{"buypass", []string{"buypass.com"}},
	{"actalis", []string{"actalis.it"}},
	{"microsoft", []string{"microsoft.com"}},
	{"cloudflare", []string{"pki.goog", "letsencrypt.org", "digicert.com", "sectigo.com"}},
}

// caaIDsFor returns the CAA identifiers for an issuer organisation, or nil
// when the issuer is not in the table. Matching is on whole words so that
// "entrust" does not match inside "IdenTrust".
func caaIDsFor(issuerOrg string) []string {
	org := " " + normalizeOrg(issuerOrg) + " "
	for _, e := range caaIssuers {
		if strings.Contains(org, " "+normalizeOrg(e.match)+" ") {
			return e.ids
		}
	}
	return nil
}

// normalizeOrg lower-cases and turns punctuation into word separators so
// that "GoDaddy.com, Inc." matches "godaddy".
func normalizeOrg(s string) string {
	s = strings.ToLower(s)
	s = strings.NewReplacer(".", " ", ",", " ", "-", " ").Replace(s)
	return strings.Join(strings.Fields(s), " ")
}

// CAAVerdict is the cross-check for one hostname. Permitted is absent
// only when nothing could be judged: no certificate was observed or the
// issuer is not in the mapping table (the note says which).
type CAAVerdict struct {
	Records   []string `json:"records"`
	Issuer    string   `json:"issuer,omitempty"`
	Permitted *bool    `json:"permitted,omitempty"`
	Note      string   `json:"note,omitempty"`
}

// CAAReport is the caa section of the report. issuer, permitted and note
// are the apex verdict; hosts carries the verdict for apex and www.
type CAAReport struct {
	Apex      []string               `json:"apex"`
	WWW       []string               `json:"www"`
	Issuer    string                 `json:"issuer,omitempty"`
	Permitted *bool                  `json:"permitted,omitempty"`
	Note      string                 `json:"note,omitempty"`
	Hosts     map[string]*CAAVerdict `json:"hosts"`
}

// caaPermits decides whether a CA (by its identifiers) may issue for a
// name under the given records; wildcard leaves consult issuewild when any
// issuewild record exists (RFC 8659 §4.3).
func caaPermits(records []caaRecord, ids []string, wildcard bool) bool {
	tag := "issue"
	if wildcard && hasTag(records, "issuewild") {
		tag = "issuewild"
	}
	allowed := false
	seenTag := false
	for _, r := range records {
		if r.Tag != tag {
			continue
		}
		seenTag = true
		domain := strings.TrimSpace(strings.SplitN(r.Value, ";", 2)[0])
		if domain == "" {
			continue // "issue ;" forbids everyone
		}
		for _, id := range ids {
			if strings.EqualFold(domain, id) {
				allowed = true
			}
		}
	}
	if !seenTag {
		// No issue records at all: only iodef etc. present; issuance unrestricted.
		return true
	}
	return allowed
}

func hasTag(records []caaRecord, tag string) bool {
	for _, r := range records {
		if r.Tag == tag {
			return true
		}
	}
	return false
}

// servedCert is what a host presented: issuer organisation and whether the
// leaf is a wildcard certificate. A zero value means no certificate.
type servedCert struct {
	issuer   string
	wildcard bool
}

// caaVerdict judges one served certificate against the CAA records that
// apply to its host. Without CAA records any CA may issue (permitted
// true, RFC 8659 §4).
func caaVerdict(records []string, cert servedCert) *CAAVerdict {
	v := &CAAVerdict{Records: nonNil(records), Issuer: cert.issuer}
	parsed := parseCAA(records)
	switch {
	case cert.issuer == "":
		v.Note = "no certificate observed"
	case len(parsed) == 0:
		v.Note = "no CAA records; any CA may issue"
		v.Permitted = boolPtr(true)
	default:
		ids := caaIDsFor(cert.issuer)
		if ids == nil {
			v.Note = "issuer not in the CAA mapping table"
			return v
		}
		v.Permitted = boolPtr(caaPermits(parsed, ids, cert.wildcard))
	}
	return v
}

func boolPtr(b bool) *bool { return &b }

// assessCAA builds the CAA report with one verdict per host. The www name
// uses its own records when it has any, otherwise the apex records apply
// (RFC 8659 climbs to the closest ancestor with a CAA set).
func assessCAA(apexRec, wwwRec Lookup, apexCert, wwwCert servedCert) CAAReport {
	wwwRecords := wwwRec.Records
	if len(wwwRecords) == 0 {
		wwwRecords = apexRec.Records
	}
	hosts := map[string]*CAAVerdict{
		"apex": caaVerdict(apexRec.Records, apexCert),
		"www":  caaVerdict(wwwRecords, wwwCert),
	}
	a := hosts["apex"]
	return CAAReport{Apex: nonNil(apexRec.Records), WWW: nonNil(wwwRec.Records), Issuer: a.Issuer, Permitted: a.Permitted, Note: a.Note, Hosts: hosts}
}
