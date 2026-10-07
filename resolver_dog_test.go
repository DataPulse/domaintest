package main

import (
	"context"
	"path/filepath"
	"testing"
)

func TestResolvConfServer(t *testing.T) {
	p := filepath.Join(t.TempDir(), "resolv.conf")
	if err := writeFile(p, "# comment\nnameserver fe80::1%eth0\nnameserver 10.0.0.2\nnameserver 2001:db8::53\nnameserver 10.0.0.3\n"); err != nil {
		t.Fatal(err)
	}
	v4, ok := resolvConfServer(p, familyIPv4)
	check(t, "first v4", []any{v4, ok}, []any{"10.0.0.2", true})
	v6, ok := resolvConfServer(p, familyIPv6)
	check(t, "scoped link-local skipped", []any{v6, ok}, []any{"2001:db8::53", true})
	_, ok = resolvConfServer(filepath.Join(t.TempDir(), "missing"), familyIPv4)
	check(t, "unreadable file", ok, false)
	check(t, "nameservers in order", resolvConfNameservers(p), []string{"fe80::1%eth0", "10.0.0.2", "2001:db8::53", "10.0.0.3"})
}

func TestServerForFamily(t *testing.T) {
	withResolvConf(t, "nameserver 10.12.60.1\n")
	sys := baseConfig("x.org", "")
	got, ok := serverForFamily(context.Background(), sys, familyIPv4)
	check(t, "system v4", []any{got, ok}, []any{"10.12.60.1", true})
	_, ok = serverForFamily(context.Background(), sys, familyIPv6)
	check(t, "system has no v6", ok, false)

	lit := baseConfig("x.org", "127.0.0.1:8053")
	got, _ = serverForFamily(context.Background(), lit, familyIPv4)
	check(t, "literal with port", got, "127.0.0.1:8053")
	lit6 := baseConfig("x.org", "[::1]:5353")
	got, _ = serverForFamily(context.Background(), lit6, familyIPv6)
	check(t, "v6 literal with port", got, "[::1]:5353")

	// A hostname server is named by its address of the family; localhost
	// resolves from /etc/hosts without the network.
	host := baseConfig("x.org", "localhost:5353")
	got, ok = serverForFamily(context.Background(), host, familyIPv4)
	check(t, "hostname resolved to v4", []any{got, ok}, []any{"127.0.0.1:5353", true})
}

// The root zone is signed, so a validating resolver authenticates its NS
// set; an answer without AD (here a root server answering itself, as a
// non-validating resolver would) says the resolver does not validate.
func TestResolverValidates(t *testing.T) {
	secure := dogFixture(t, "dog/root_ns_v4.json", "NS")
	plain := dogFixture(t, "dog/root_ns_no_ad_authoritative.json", "NS")
	check(t, "captures", []Trust{secure.Trust, plain.Trust}, []Trust{TrustSecure, TrustInsecure})
	check(t, "no family answered", resolverValidates(map[string]Trust{familyIPv4: ""}), (*bool)(nil))
	yes, no := true, false
	check(t, "validating", resolverValidates(map[string]Trust{familyIPv4: secure.Trust}), &yes)
	check(t, "not validating", resolverValidates(map[string]Trust{familyIPv4: plain.Trust}), &no)
	check(t, "either family validating", resolverValidates(map[string]Trust{familyIPv4: plain.Trust, familyIPv6: secure.Trust}), &yes)
}

// Against a resolver that does not validate, no answer carries trust and
// DNSSEC is unknown with the reason, rather than every signed zone reading
// as insecure for want of an AD bit.
func TestRun_NonValidatingResolver(t *testing.T) {
	s := jschmidtScenario(t)
	s.reach(familyIPv4, "dog/root_ns_no_ad_authoritative.json", t)
	rep := s.run()
	no := false
	check(t, "resolver_validates", rep.DNS.ResolverValidates, &no)
	check(t, "dnssec unknown", rep.DNSSEC.State, DNSSECUnknown)
	check(t, "published DS and DNSKEY still reported", []bool{rep.DNSSEC.DS, rep.DNSSEC.DNSKEY}, []bool{true, true})
	check(t, "says why", rep.DNSSEC.Detail, "the resolver does not validate DNSSEC (it did not authenticate the signed root zone), so no DNSSEC verdict is possible")
	for k, l := range rep.DNS.Apex {
		check(t, "no trust on apex "+k, l.Trust, Trust(""))
	}
	check(t, "tlsa not called signed", rep.TLSA.Signed, false)

	v := jschmidtScenario(t).run()
	yes := true
	check(t, "validating resolver", v.DNS.ResolverValidates, &yes)
	check(t, "secure zone", v.DNSSEC.State, DNSSECSecure)
}
