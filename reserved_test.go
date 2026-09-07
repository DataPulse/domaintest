package main

import "testing"

func TestReservedName(t *testing.T) {
	for _, c := range []struct{ domain, want string }{
		{"foo.invalid", "RFC 6761"},
		{"invalid", "RFC 6761"},
		{"x.test", "RFC 6761"},
		{"localhost", "RFC 6761"},
		{"anything.example", "RFC 6761"},
		{"printer.local", "RFC 6762"},
		{"FOO.INVALID", "RFC 6761"},
		{"foo.invalid.", "RFC 6761"},
		{"expyz.onion", "RFC 7686"},
		{"router.home.arpa", "RFC 8375"},
		// Reserved for documentation, but real, delegated names.
		{"example.com", ""},
		{"example.org", ""},
		// Suffix matching must respect label boundaries.
		{"notinvalid.com", ""},
		{"myexample.net", ""},
		{"jschmidt.org", ""},
	} {
		check(t, "reserved: "+c.domain, reservedName(c.domain), c.want)
	}
}

// A validating resolver answers RFC 6761 names itself, and the denial it
// synthesises is unsigned, so delv reports a broken trust chain. That is a
// fact about the resolver, and must not become a security verdict about
// the domain.
func TestReservedName_NoSecurityVerdict(t *testing.T) {
	rep := &Report{
		Domain:       "foo.invalid",
		ReservedName: "RFC 6761",
		DNSSEC:       DNSSECReport{State: DNSSECBogus, Detail: "broken trust chain"},
		Delegation:   Delegation{Status: DelegationNotDelegated, ParentServer: "d.root-servers.net"},
		DNS: DNSSection{
			Apex: map[string]Lookup{"A": {Status: StatusFailure, Error: "broken trust chain"}, "NS": {Status: StatusFailure}},
			WWW:  map[string]Lookup{},
		},
	}
	buildFindings(rep)
	check(t, "no errors", rep.Errors, []string{})
	check(t, "ok", rep.OK, true)
	check(t, "no bogus claim", contains(rep.Errors, "bogus"), false)
	check(t, "explained once", contains(rep.Warnings, "is reserved by RFC 6761 and is not served by the global DNS"), true)

	// The same shape without the reservation is still a real fault.
	rep.ReservedName = ""
	buildFindings(rep)
	check(t, "bogus still reported", contains(rep.Errors, "DNSSEC validation fails (bogus)"), true)
}
