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
	{"buypass", []string{"buypass.com"}},
	{"actalis", []string{"actalis.it"}},
	{"microsoft", []string{"microsoft.com"}},
	{"cloudflare", []string{"pki.goog", "letsencrypt.org", "digicert.com", "sectigo.com"}},
}

// caaIDsFor returns the CAA identifiers for an issuer organisation, or nil
// when the issuer is not in the table.
func caaIDsFor(issuerOrg string) []string {
	org := strings.ToLower(issuerOrg)
	for _, e := range caaIssuers {
		if strings.Contains(org, e.match) {
			return e.ids
		}
	}
	return nil
}

// CAAReport is the caa section of the report.
type CAAReport struct {
	Apex      []string `json:"apex,omitempty"`
	WWW       []string `json:"www,omitempty"`
	Issuer    string   `json:"issuer,omitempty"`
	Permitted *bool    `json:"permitted,omitempty"`
	Note      string   `json:"note,omitempty"`
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

// assessCAA builds the CAA report from the two lookups and the certificate
// actually served for the apex (or www when the apex has no TLS).
func assessCAA(apex, www Lookup, issuer string, wildcardLeaf bool) CAAReport {
	rep := CAAReport{Apex: apex.Records, WWW: www.Records, Issuer: issuer}
	effective := parseCAA(apex.Records)
	if len(www.Records) > 0 {
		effective = parseCAA(www.Records) // the www name has its own policy
	}
	if issuer == "" {
		rep.Note = "no certificate observed"
		return rep
	}
	if len(effective) == 0 {
		rep.Note = "no CAA records; any CA may issue"
		return rep
	}
	ids := caaIDsFor(issuer)
	if ids == nil {
		rep.Note = "issuer not in the CAA mapping table"
		return rep
	}
	permitted := caaPermits(effective, ids, wildcardLeaf)
	rep.Permitted = &permitted
	return rep
}
