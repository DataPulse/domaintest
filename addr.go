package main

import (
	"net/netip"

	"github.com/DataPulse/dpdomain/ipnorm"
)

// reservedReason returns why ip must not be published in public DNS, or ""
// when it is a routable address. The judgement is dpdomain's ipnorm.Reserved,
// the one shared with scrape's SSRF guard and every other DataPulse tool, so
// they cannot disagree; it also judges the IPv6 forms that carry an IPv4
// address (IPv4-mapped, NAT64, 6to4, IPv4-compatible). Until 2026-10-06 this
// was a list of its own.
func reservedReason(ip netip.Addr) string {
	return ipnorm.Reserved(ip)
}

// dedupeStrings keeps the first occurrence of each value, in order.
func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// splitReserved partitions addresses into routable and reserved, returning
// the reserved ones with their reasons in input order.
func splitReserved(addrs []netip.Addr) (public []netip.Addr, reserved []string) {
	for _, ip := range addrs {
		if reason := reservedReason(ip); reason != "" {
			reserved = append(reserved, ip.String()+" ("+reason+")")
			continue
		}
		public = append(public, ip)
	}
	return public, reserved
}
