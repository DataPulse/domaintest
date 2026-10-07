package main

import "strings"

// specialUseSuffixes are names reserved by RFC and served outside the
// global DNS. A validating resolver answers them itself (Unbound serves
// test, invalid, onion and localhost as local zones), so whatever it says
// describes the resolver, not the domain: without this the report turns
// the resolver's own behaviour into a security verdict about the domain.
// Before 2026-10-07 the lookups ran delv, which called foo.invalid's
// unsigned local denial a broken trust chain and the name DNSSEC bogus.
//
// Only the suffixes that never resolve are listed. example.com and its
// siblings are reserved for documentation but are real, delegated names,
// so they are checked like any other domain.
var specialUseSuffixes = map[string]string{
	"invalid":   "RFC 6761",
	"test":      "RFC 6761",
	"localhost": "RFC 6761",
	"example":   "RFC 6761",
	"local":     "RFC 6762",
	"onion":     "RFC 7686",
	"home.arpa": "RFC 8375",
}

// reservedName returns the RFC reserving this name's suffix, or "" when
// the name belongs to the global DNS.
func reservedName(domain string) string {
	d := bareName(domain)
	if d == "" {
		return ""
	}
	for suffix, rfc := range specialUseSuffixes {
		if d == suffix || strings.HasSuffix(d, "."+suffix) {
			return rfc
		}
	}
	return ""
}
