package main

import (
	"net/netip"
	"testing"
)

func TestReservedReason(t *testing.T) {
	reserved := map[string]string{
		"127.0.0.1":       "loopback",
		"10.1.2.3":        "private (RFC 1918)",
		"172.31.255.255":  "private (RFC 1918)",
		"192.168.0.1":     "private (RFC 1918)",
		"100.64.0.1":      "shared address space / CGNAT (RFC 6598)",
		"169.254.1.1":     "link-local",
		"192.0.2.1":       "documentation TEST-NET-1",
		"198.18.5.5":      "benchmarking (RFC 2544)",
		"224.0.0.1":       "multicast",
		"255.255.255.255": "reserved (class E)",
		"0.0.0.0":         "this-network (RFC 1122)",
		"::1":             "loopback",
		"::":              "unspecified",
		"fe80::1":         "link-local",
		"fd00::1":         "unique local (RFC 4193)",
		"2001:db8::1":     "documentation",
		"ff02::1":         "multicast",
		"::ffff:10.0.0.1": "private (RFC 1918)",
	}
	for ip, want := range reserved {
		check(t, ip, reservedReason(netip.MustParseAddr(ip)), want)
	}
	for _, ip := range []string{"8.8.8.8", "172.32.0.1", "192.0.3.1", "100.128.0.1", "2001:4860:4860::8888", "2600::1", "64:ff9b::808:808"} {
		check(t, ip+" is public", reservedReason(netip.MustParseAddr(ip)), "")
	}
}

func TestSplitReserved(t *testing.T) {
	addrs := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("fd00::1")}
	public, reserved := splitReserved(addrs)
	check(t, "public", public, []netip.Addr{netip.MustParseAddr("8.8.8.8")})
	check(t, "reserved", reserved, []string{"127.0.0.1 (loopback)", "fd00::1 (unique local (RFC 4193))"})
	p, r := splitReserved(nil)
	check(t, "empty", len(p)+len(r), 0)
}

func TestReservedFromFixture(t *testing.T) {
	l := parseDelvYAML(fixture(t, "delv/reserved/localtest_a.yaml"), "A")
	_, reserved := splitReserved(l.Addrs())
	check(t, "localtest.me publishes loopback", reserved, []string{"127.0.0.1 (loopback)"})
}
