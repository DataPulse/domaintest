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
func registrableDomain(domain string) bool {
	if domain == "" {
		return false
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(domain)
	return err == nil && etld1 == domain
}
