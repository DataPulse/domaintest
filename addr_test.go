package main

import (
	"net/netip"
	"testing"
)

// reservedReason is dpdomain's ipnorm.Reserved; these pin the reasons the
// report shows and the ranges domaintest relies on.
func TestReservedReason(t *testing.T) {
	reserved := map[string]string{
		"127.0.0.1":        "loopback address",
		"10.1.2.3":         "private (RFC 1918 / ULA) address",
		"172.31.255.255":   "private (RFC 1918 / ULA) address",
		"192.168.0.1":      "private (RFC 1918 / ULA) address",
		"100.64.0.1":       "carrier-grade NAT (RFC 6598) address",
		"169.254.1.1":      "link-local address",
		"192.0.2.1":        "documentation (TEST-NET-1) address",
		"198.18.5.5":       "benchmarking (RFC 2544) address",
		"224.0.0.1":        "multicast address",
		"255.255.255.255":  "reserved (class E) address",
		"0.0.0.0":          "unspecified address",
		"0.1.2.3":          "this-network (RFC 791) address",
		"::1":              "loopback address",
		"::":               "unspecified address",
		"fe80::1":          "link-local address",
		"fd00::1":          "private (RFC 1918 / ULA) address",
		"2001:db8::1":      "documentation address",
		"ff02::1":          "multicast address",
		"::ffff:10.0.0.1":  "private (RFC 1918 / ULA) address",
		"64:ff9b::a00:1":   "NAT64-embedded private (RFC 1918 / ULA) address",
		"64:ff9b::808:808": "NAT64 (RFC 6052) address", // all NAT64 is reserved: never needed on a dual-stack host
		"192.88.99.1":      "deprecated 6to4 relay anycast (RFC 7526) address",
	}
	for ip, want := range reserved {
		check(t, ip, reservedReason(netip.MustParseAddr(ip)), want)
	}
	for _, ip := range []string{"8.8.8.8", "172.32.0.1", "192.0.3.1", "100.128.0.1", "2001:4860:4860::8888", "2600::1"} {
		check(t, ip+" is public", reservedReason(netip.MustParseAddr(ip)), "")
	}
}

func TestSplitReserved(t *testing.T) {
	addrs := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("fd00::1")}
	public, reserved := splitReserved(addrs)
	check(t, "public", public, []netip.Addr{netip.MustParseAddr("8.8.8.8")})
	check(t, "reserved", reserved, []string{"127.0.0.1 (loopback address)", "fd00::1 (private (RFC 1918 / ULA) address)"})
	p, r := splitReserved(nil)
	check(t, "empty", len(p)+len(r), 0)
}

func TestReservedFromFixture(t *testing.T) {
	l := parseDelvYAML(fixture(t, "delv/reserved/localtest_a.yaml"), "A")
	_, reserved := splitReserved(l.Addrs())
	check(t, "localtest.me publishes loopback", reserved, []string{"127.0.0.1 (loopback address)"})
}
