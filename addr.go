package main

import "net/netip"

// reservedRange is an address block that must never appear in public DNS.
type reservedRange struct {
	prefix netip.Prefix
	reason string
}

var reservedRanges = []reservedRange{
	{netip.MustParsePrefix("0.0.0.0/8"), "this-network (RFC 1122)"},
	{netip.MustParsePrefix("10.0.0.0/8"), "private (RFC 1918)"},
	{netip.MustParsePrefix("100.64.0.0/10"), "shared address space / CGNAT (RFC 6598)"},
	{netip.MustParsePrefix("127.0.0.0/8"), "loopback"},
	{netip.MustParsePrefix("169.254.0.0/16"), "link-local"},
	{netip.MustParsePrefix("172.16.0.0/12"), "private (RFC 1918)"},
	{netip.MustParsePrefix("192.0.0.0/24"), "IETF protocol assignments"},
	{netip.MustParsePrefix("192.0.2.0/24"), "documentation TEST-NET-1"},
	{netip.MustParsePrefix("192.168.0.0/16"), "private (RFC 1918)"},
	{netip.MustParsePrefix("198.18.0.0/15"), "benchmarking (RFC 2544)"},
	{netip.MustParsePrefix("198.51.100.0/24"), "documentation TEST-NET-2"},
	{netip.MustParsePrefix("203.0.113.0/24"), "documentation TEST-NET-3"},
	{netip.MustParsePrefix("224.0.0.0/4"), "multicast"},
	{netip.MustParsePrefix("240.0.0.0/4"), "reserved (class E)"},
	{netip.MustParsePrefix("::/128"), "unspecified"},
	{netip.MustParsePrefix("::1/128"), "loopback"},
	{netip.MustParsePrefix("::ffff:0:0/96"), "IPv4-mapped"},
	{netip.MustParsePrefix("100::/64"), "discard-only (RFC 6666)"},
	{netip.MustParsePrefix("2001:db8::/32"), "documentation"},
	{netip.MustParsePrefix("fc00::/7"), "unique local (RFC 4193)"},
	{netip.MustParsePrefix("fe80::/10"), "link-local"},
	{netip.MustParsePrefix("ff00::/8"), "multicast"},
}

// reservedReason returns why ip must not be published in public DNS, or ""
// when it is a routable address. IPv4-mapped IPv6 forms are judged as the
// embedded IPv4 address (delv never prints them, but netip may unmap).
func reservedReason(ip netip.Addr) string {
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	for _, r := range reservedRanges {
		if r.prefix.Contains(ip) {
			return r.reason
		}
	}
	return ""
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
