package main

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

// jschmidtNSLookup serves the captured A/AAAA answers for jschmidt.org's
// nameservers.
func jschmidtNSLookup(t *testing.T) lookupFn {
	return fixtureLookup(t, map[string]string{
		"ns-507.awsdns-63.com/A":       "delv/ns/ns-507_a.yaml",
		"ns-507.awsdns-63.com/AAAA":    "delv/ns/ns-507_aaaa.yaml",
		"ns-1013.awsdns-62.net/A":      "delv/ns/ns-1013_a.yaml",
		"ns-1013.awsdns-62.net/AAAA":   "delv/ns/ns-1013_aaaa.yaml",
		"ns-1034.awsdns-01.org/A":      "delv/ns/ns-1034_a.yaml",
		"ns-1034.awsdns-01.org/AAAA":   "delv/ns/ns-1034_aaaa.yaml",
		"ns-2001.awsdns-58.co.uk/A":    "delv/ns/ns-2001_a.yaml",
		"ns-2001.awsdns-58.co.uk/AAAA": "delv/ns/ns-2001_aaaa.yaml",
	})
}

func TestResolveNS(t *testing.T) {
	names := nsNames(parseDelvYAML(fixture(t, "delv/jschmidt_ns.yaml"), "NS"))
	check(t, "sorted names", names[0], "ns-1013.awsdns-62.net.")
	rep := resolveNS(names, jschmidtNSLookup(t))
	check(t, "count", rep.Count, 4)
	check(t, "all resolved", len(rep.Unresolvable), 0)
	check(t, "no cname", len(rep.NSCNAME), 0)
	check(t, "four /24s", *rep.IPv4Prefixes24, 4)
	check(t, "four /48s", *rep.IPv6Prefixes48, 4)
	check(t, "eight addresses", len(rep.allAddrs()), 8)

	bad := fixtureLookup(t, map[string]string{"cname.example/A": "delv/www_github_cname.yaml"})
	rep = resolveNS([]string{"cname.example.", "gone.example."}, bad)
	check(t, "cname ns", rep.NSCNAME, []string{"cname.example."})
	check(t, "unresolvable", rep.Unresolvable, []string{"gone.example."})
	check(t, "denial is not a gap", rep.Unresolved, []string{})
}

// A lookup that never answered must be reported as unresolved, not as a
// name without an address, and must leave the diversity counts unknown
// rather than reporting zero of everything.
func TestResolveNS_UnansweredIsNotAbsent(t *testing.T) {
	timedOut := func(name, qtype string) Lookup {
		l := parseDelvYAML(fixture(t, "delv/timeout.yaml"), qtype)
		l.Name, l.Status = name, StatusTimeout
		return l
	}
	rep := resolveNS([]string{"ns1.example.", "ns2.example."}, timedOut)
	check(t, "nothing claimed absent", rep.Unresolvable, []string{})
	check(t, "both unresolved", rep.Unresolved, []string{"ns1.example.", "ns2.example."})
	check(t, "v4 diversity unknown", rep.IPv4Prefixes24 == nil, true)
	check(t, "v6 diversity unknown", rep.IPv6Prefixes48 == nil, true)

	// One family answering and the other timing out is still a gap.
	half := func(name, qtype string) Lookup {
		if qtype == "AAAA" {
			return timedOut(name, qtype)
		}
		l := parseDelvYAML(fixture(t, "delv/jschmidt_aaaa_nxrrset.yaml"), qtype)
		l.Name = name
		return l
	}
	rep = resolveNS([]string{"ns1.example."}, half)
	check(t, "half an answer is a gap", rep.Unresolved, []string{"ns1.example."})
	check(t, "not called absent", rep.Unresolvable, []string{})
}

func TestPrefixDiversity(t *testing.T) {
	v4, v6 := prefixDiversity([]netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.1.1"), netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8:1::2")})
	check(t, "v4 /24s", v4, 2)
	check(t, "v6 /48s", v6, 1)
}

func TestNSAuditArgs(t *testing.T) {
	got := strings.Join(nsAuditArgs(netip.MustParseAddr("192.0.2.1"), "example.org", 3), " ")
	check(t, "args", got, "+yaml +norecurse +tries=1 +time=3 -4 @192.0.2.1 example.org SOA example.org SOA +tcp example.org SOA +dnssec")
	check(t, "ipv6", strings.Contains(strings.Join(nsAuditArgs(netip.MustParseAddr("2001:db8::1"), "x", 1), " "), "-6 @2001:db8::1"), true)
	check(t, "glue", strings.Join(glueArgs("a0.org.afilias-nst.info", familyIPv4, 2, "jschmidt.org"), " "), "+yaml +norecurse +tries=1 +time=2 -4 @a0.org.afilias-nst.info jschmidt.org NS")
}

func TestAuditServer(t *testing.T) {
	r := newFakeRunner()
	ip := netip.MustParseAddr("205.251.193.251")
	r.on("dig", nsAuditArgs(ip, "jschmidt.org", 3), fakeCall{stdout: fixture(t, "dig/ns/jschmidt_at_ns-507.yaml")})
	lame := netip.MustParseAddr("216.239.32.10")
	r.on("dig", nsAuditArgs(lame, "jschmidt.org", 3), fakeCall{stdout: fixture(t, "dig/ns/jschmidt_at_ns1_google_refused.yaml")})
	dead := netip.MustParseAddr("192.0.2.1")
	r.on("dig", nsAuditArgs(dead, "jschmidt.org", 3), fakeCall{stdout: fixture(t, "dig/ns/unreachable.yaml"), err: errFake})

	s := auditServer(context.Background(), r, "dig", "ns-507.awsdns-63.com.", ip, "jschmidt.org", 3)
	check(t, "aa", s.AA, true)
	check(t, "rcode", s.Rcode, "NOERROR")
	check(t, "serial", s.Serial, int64(1))
	check(t, "tcp", s.TCP, true)
	check(t, "edns", s.EDNS, true)
	check(t, "no error", s.Error, "")

	s = auditServer(context.Background(), r, "dig", "ns1.google.com.", lame, "jschmidt.org", 3)
	check(t, "lame not aa", s.AA, false)
	check(t, "lame error", s.Error, "not authoritative (REFUSED)")

	s = auditServer(context.Background(), r, "dig", "dead.", dead, "jschmidt.org", 3)
	check(t, "unreachable", s.Error, "no servers could be reached")
}

func TestAuditAllAndSerials(t *testing.T) {
	names := nsNames(parseDelvYAML(fixture(t, "delv/jschmidt_ns.yaml"), "NS"))
	rep := resolveNS(names, jschmidtNSLookup(t))
	r := newFakeRunner()
	r.fallback = func(tool string, args []string) (fakeCall, bool) {
		if tool == "dig" {
			for _, a := range args {
				if strings.HasPrefix(a, "@2600:") { // v6 addresses: pretend one is lame
					return fakeCall{stdout: fixture(t, "dig/ns/jschmidt_at_ns1_google_refused.yaml")}, true
				}
			}
			return fakeCall{stdout: fixture(t, "dig/ns/jschmidt_at_ns-507.yaml")}, true
		}
		return fakeCall{}, false
	}
	auditAll(context.Background(), r, "dig", &rep, "jschmidt.org", []string{familyIPv4, familyIPv6}, 3)
	check(t, "eight servers audited", len(rep.Servers), 8)
	check(t, "sorted by name", rep.Servers[0].Name, "ns-1013.awsdns-62.net.")
	check(t, "serials consistent (lame ones ignored)", *rep.SerialsConsistent, true)
	var lame int
	for _, s := range rep.Servers {
		if !s.AA {
			lame++
		}
	}
	check(t, "four lame v6", lame, 4)

	only4 := resolveNS(names, jschmidtNSLookup(t))
	auditAll(context.Background(), r, "dig", &only4, "jschmidt.org", []string{familyIPv4}, 3)
	check(t, "ipv4 only", len(only4.Servers), 4)

	check(t, "drift", *serialsConsistent([]NSServer{{AA: true, Serial: 1}, {AA: true, Serial: 2}}), false)
	check(t, "single", *serialsConsistent([]NSServer{{AA: true, Serial: 5}}), true)
	// Nothing was compared, so the answer is unknown, not agreement.
	check(t, "none is unknown", serialsConsistent(nil) == nil, true)
	check(t, "only lame servers is unknown", serialsConsistent([]NSServer{{AA: false, Serial: 7}}) == nil, true)
}

func TestCheckGlue(t *testing.T) {
	msgs := parseDigYAML(fixture(t, "dig/ns/glue_google_at_gtld.yaml"))
	addrs := map[string][]netip.Addr{
		"ns1.google.com.": {netip.MustParseAddr("216.239.32.10"), netip.MustParseAddr("2001:4860:4802:32::a")},
		"ns2.google.com.": {netip.MustParseAddr("216.239.34.10")},
		"ns9.google.com.": {netip.MustParseAddr("192.0.2.9")},
		"ns.other.net.":   {netip.MustParseAddr("192.0.2.1")},
	}
	g := checkGlue(msgs, "google.com", addrs)
	check(t, "required in-bailiwick", g.Required, []string{"ns1.google.com.", "ns2.google.com.", "ns9.google.com."})
	check(t, "missing glue", g.Missing, []string{"ns9.google.com."})
	check(t, "no mismatch for real servers", len(g.Mismatch), 0)

	addrs["ns1.google.com."] = []netip.Addr{netip.MustParseAddr("192.0.2.77")}
	g = checkGlue(msgs, "google.com", addrs)
	check(t, "mismatch", g.Mismatch, []string{"ns1.google.com. 192.0.2.77"})

	check(t, "error message gives nil", checkGlue([]digMessage{{Error: "x"}}, "google.com", addrs), (*GlueReport)(nil))
	check(t, "no messages gives nil", checkGlue(nil, "google.com", addrs), (*GlueReport)(nil))
	out := checkGlue(parseDigYAML(fixture(t, "dig/jschmidt_at_org_referral.yaml")), "jschmidt.org", map[string][]netip.Addr{"ns-507.awsdns-63.com.": {netip.MustParseAddr("205.251.193.251")}})
	check(t, "out-of-bailiwick needs no glue", len(out.Required), 0)
}
