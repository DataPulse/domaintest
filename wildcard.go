package main

import (
	"crypto/rand"
	"encoding/hex"
	"net/netip"
)

// WildcardReport says whether the zone answers for names that do not exist.
type WildcardReport struct {
	Present        bool     `json:"present"`
	Addresses      []string `json:"addresses"`
	WWWViaWildcard bool     `json:"www_via_wildcard"`
}

// wildcardLabel returns a label that cannot exist by accident.
func wildcardLabel() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "domaintest-probe"
	}
	return "domaintest-" + hex.EncodeToString(b[:])
}

// assessWildcard compares the nonce probe with the www answers.
func assessWildcard(probeA, probeAAAA, wwwA, wwwAAAA Lookup) WildcardReport {
	addrs := append(probeA.Addrs(), probeAAAA.Addrs()...)
	rep := WildcardReport{Present: len(addrs) > 0 || len(probeA.CNAME) > 0 || len(probeAAAA.CNAME) > 0, Addresses: []string{}}
	for _, ip := range addrs {
		rep.Addresses = append(rep.Addresses, ip.String())
	}
	if !rep.Present {
		return rep
	}
	www := append(wwwA.Addrs(), wwwAAAA.Addrs()...)
	rep.WWWViaWildcard = len(www) > 0 && sameAddressSet(www, addrs)
	return rep
}

// wildcardNames returns the probe name for a domain.
func wildcardName(domain string) string {
	return wildcardLabel() + "." + domain
}

var _ = netip.Addr{}
