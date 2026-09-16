package main

import "github.com/DataPulse/dpdomain"

// Every name this tool touches — the domain under test, NS and MX targets,
// CNAME and SOA owners, redirect hosts — is normalized by dpdomain, the one
// DataPulse normalizer. DNS-side normalization is lenient: names that exist
// (emoji labels, a-labels IDNA 2008 forbids) must stay testable. Trailing
// dots are always stripped; FQDN() adds one back for the resolver.

// dnsName normalizes a name as DNS carries it (any case, optional trailing
// dot, u- or a-labels) to its bare a-label form.
func dnsName(s string) (dpdomain.Name, error) {
	return dpdomain.Normalize(s, dpdomain.Options{Lenient: true})
}

// hostOrIP is dnsName for a field that may legitimately hold an address (an
// MX target, a redirect host); the caller reads Name.Kind.
func hostOrIP(s string) (dpdomain.Name, error) {
	return dpdomain.Normalize(s, dpdomain.Options{Lenient: true, AllowIP: true})
}

// bareName returns the a-label form of a name already validated upstream
// (the apex, a fixture name), or "" when it is not a name at all.
func bareName(s string) string {
	n, err := dnsName(s)
	if err != nil {
		return ""
	}
	return n.ASCII
}

// fqdnOf returns the absolute form ("example.com.") of a name, or "" when it
// is not a name at all.
func fqdnOf(s string) string {
	n, err := dnsName(s)
	if err != nil {
		return ""
	}
	return n.FQDN()
}
