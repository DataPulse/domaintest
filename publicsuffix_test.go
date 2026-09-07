package main

import "testing"

// The Public Suffix List is the right test for whether www belongs to a
// name, in both directions: a registrable domain stays registrable however
// odd its DNS looks, and a delegated subdomain is a zone apex yet its www
// is just as invented.
func TestRegistrableDomain(t *testing.T) {
	for _, c := range []struct {
		domain string
		want   bool
	}{
		// Registrable: www.<name> is a name someone would configure.
		{"jschmidt.org", true},
		{"reddit.com", true},
		{"bbc.co.uk", true},  // the multi-label suffix case
		{"jeff.co.uk", true}, // registrable even though co.uk is the suffix
		{"example.com.au", true},
		{"xn--mnchen-3ya.de", true}, // an IDN A-label is an ordinary label

		// A host inside a registrable domain: www.<name> is invented.
		{"old.reddit.com", false},
		{"mail.google.com", false},
		{"www.bbc.co.uk", false},
		// A delegated zone apex, but still not registrable.
		{"blog.cloudflare.com", false},

		// Public suffixes are not registrable names themselves.
		{"co.uk", false},
		{"com", false},
		{"", false},
	} {
		check(t, "registrable: "+c.domain, registrableDomain(c.domain), c.want)
	}
}
