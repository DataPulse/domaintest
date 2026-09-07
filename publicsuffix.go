package main

import "golang.org/x/net/publicsuffix"

// registrableDomain reports whether the name is exactly a registrable
// domain: one label below a public suffix, as the Public Suffix List
// defines it. jeff.co.uk is registrable and www.jeff.co.uk is a real name
// someone would configure; old.reddit.com is not, and www.old.reddit.com
// is a name only this tool would ever ask for.
//
// The list is the right test rather than "is this a zone apex", in both
// directions. A registrable domain stays registrable however odd its DNS
// looks, and a delegated subdomain like blog.cloudflare.com is a zone apex
// yet www.blog.cloudflare.com is just as invented.
// isPublicSuffix reports whether the name is itself a public suffix, of
// either section: a caller feeding a list needs to tell co.uk from
// bbc.co.uk, and it explains why web.www is absent.
func isPublicSuffix(domain string) bool {
	if domain == "" {
		return false
	}
	suffix, _ := publicsuffix.PublicSuffix(domain)
	return suffix == domain
}

// registrySuffix reports whether the name is itself an ICANN public
// suffix, such as com or co.uk. Nobody receives mail at a registry's zone,
// so the mail checks have no subject there. Private suffixes are excluded
// deliberately: github.io and herokuapp.com are on the list so that names
// under them are registrable, but they are ordinary domains that GitHub
// and Salesforce own and could run mail on.
func registrySuffix(domain string) bool {
	if domain == "" {
		return false
	}
	suffix, icann := publicsuffix.PublicSuffix(domain)
	return icann && suffix == domain
}

func registrableDomain(domain string) bool {
	if domain == "" {
		return false
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(domain)
	return err == nil && etld1 == domain
}
