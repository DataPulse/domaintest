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

// Nobody receives mail at a registry's own zone, so the mail checks have
// no subject there and the DKIM probing is wasted traffic. Private
// suffixes are excluded: github.io and herokuapp.com are on the list so
// names under them are registrable, but they are ordinary domains their
// owners could run mail on.
func TestRegistrySuffix(t *testing.T) {
	for _, c := range []struct {
		domain string
		want   bool
	}{
		{"com", true},
		{"co.uk", true},
		{"org", true},
		{"github.io", false},     // private suffix: GitHub operates it
		{"herokuapp.com", false}, // private suffix
		{"bbc.co.uk", false},     // a registrable domain, not a suffix
		{"jschmidt.org", false},
		{"", false},
	} {
		check(t, "registry suffix: "+c.domain, registrySuffix(c.domain), c.want)
	}

	// Both sections count as a public suffix for reporting purposes.
	for _, d := range []string{"com", "co.uk", "github.io", "herokuapp.com"} {
		check(t, "public suffix: "+d, isPublicSuffix(d), true)
	}
	for _, d := range []string{"bbc.co.uk", "jschmidt.org", "old.reddit.com"} {
		check(t, "not a public suffix: "+d, isPublicSuffix(d), false)
	}
}
