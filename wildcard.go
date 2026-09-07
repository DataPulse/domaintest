package main

import (
	"crypto/rand"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Wildcard verdicts. A check that could not reach a definite answer reports
// WildcardUnknown: a probe that never came back must never be readable as a
// zone that denied the name.
const (
	WildcardPresent = "present"
	WildcardAbsent  = "absent"
	WildcardUnknown = "unknown"
)

// Per-probe outcomes, as they appear in the report.
const (
	probeAnswered   = "answered"   // an address or a CNAME came back
	probeDenied     = "denied"     // the zone answered, and there is nothing here
	probeUnresolved = "unresolved" // no answer arrived at all
)

// wildcardProbeCount is how many random names must agree before the zone is
// called a wildcard. One sample is not evidence: a resolver that hijacks
// NXDOMAIN, or a single lucky cached answer, would decide it alone.
const wildcardProbeCount = 3

// wildcardLabelLen is the length of each random label. Twelve letters is 56
// bits, far beyond guessing, and carries no prefix that could be matched on.
const wildcardLabelLen = 12

// WildcardProbe is one random name and what it answered.
type WildcardProbe struct {
	Label     string   `json:"label"`
	Status    string   `json:"status"`
	Addresses []string `json:"addresses"`
	CNAME     string   `json:"cname,omitempty"`
}

// WildcardReport says whether the zone answers for names that do not exist.
// Status is the verdict and DeterminedBy says what settled it, so that a
// definite "no" is as legible as a "yes".
type WildcardReport struct {
	Status         string          `json:"status"`
	DeterminedBy   string          `json:"determined_by"`
	Probes         []WildcardProbe `json:"probes"`
	Addresses      []string        `json:"addresses"`
	Consistent     *bool           `json:"consistent"` // null unless the status is present
	WWWViaWildcard bool            `json:"www_via_wildcard"`
}

// wildProbe holds the two lookups made for one random name.
type wildProbe struct {
	label string
	a     Lookup
	aaaa  Lookup
}

// randomLabels returns n unique lower-case labels of wildcardLabelLen
// letters. It is a variable so tests can pin the labels and match fixtures.
var wildcardLabels = randomLabels

func randomLabels(n int) []string {
	seen := map[string]bool{}
	out := make([]string, 0, n)
	for len(out) < n {
		l := randomLabel()
		if seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	return out
}

func randomLabel() string {
	b := make([]byte, wildcardLabelLen)
	if _, err := rand.Read(b); err != nil {
		// Cannot happen in practice; a fixed label still probes a name
		// nobody would register, which is all the check needs.
		return strings.Repeat("q", wildcardLabelLen)
	}
	for i, c := range b {
		b[i] = 'a' + c%26
	}
	return string(b)
}

// wildcardSkipReason reports why no probe is worth issuing, or "" to probe.
// Both cases are definite answers already in hand, so the queries are saved.
func wildcardSkipReason(apex, www map[string]Lookup) string {
	if apex["A"].Status == StatusNXDomain && apex["NS"].Status == StatusNXDomain {
		return "the domain does not exist"
	}
	// Only a true NXDOMAIN for www settles it. NODATA means www exists with
	// some other type, which says nothing about the names around it, while a
	// wildcard would have synthesised an address for a www that did not.
	if www["A"].Status == StatusNXDomain {
		return "www is NXDOMAIN, so no wildcard could have answered for it"
	}
	return ""
}

// classifyProbe judges one random name from both of its lookups together.
// The pair has to be judged as a whole: a wildcard CNAME answers the A query
// with the CNAME and its addresses but returns NXRRSET for AAAA, still
// carrying the CNAME, so either lookup alone would give the wrong verdict.
func classifyProbe(p wildProbe) string {
	if len(p.a.Addrs()) > 0 || len(p.aaaa.Addrs()) > 0 || len(p.a.CNAME) > 0 || len(p.aaaa.CNAME) > 0 {
		return probeAnswered
	}
	// NXDOMAIN is a name-level denial: the name does not exist, so no type
	// can, and the sibling query cannot overturn it.
	if p.a.Status == StatusNXDomain || p.aaaa.Status == StatusNXDomain {
		return probeDenied
	}
	// Otherwise both queries must have answered before an empty result
	// settles anything, since NODATA denies only the type it was asked
	// about. Signed zones behind synthesised NSEC ("black lies", which
	// Cloudflare serves) never say NXDOMAIN at all, so a rule that demanded
	// NXDOMAIN would miss a large share of the internet.
	if p.a.Answered() && p.aaaa.Answered() {
		return probeDenied
	}
	return probeUnresolved
}

// probeAddrs returns the addresses one probe answered with.
func probeAddrs(p wildProbe) []netip.Addr {
	return append(p.a.Addrs(), p.aaaa.Addrs()...)
}

// probeCNAME returns the CNAME target a probe answered with, if any.
func probeCNAME(p wildProbe) string {
	for _, c := range append(append([]string{}, p.a.CNAME...), p.aaaa.CNAME...) {
		if c != "" {
			return strings.ToLower(c)
		}
	}
	return ""
}

// assessWildcard turns the probes into a verdict. skip carries the reason no
// probe was issued, which is itself a definite negative.
func assessWildcard(probes []wildProbe, skip string, wwwA, wwwAAAA Lookup) WildcardReport {
	rep := WildcardReport{Probes: []WildcardProbe{}, Addresses: []string{}}
	if skip != "" {
		rep.Status, rep.DeterminedBy = WildcardAbsent, skip
		return rep
	}
	if len(probes) == 0 {
		rep.Status, rep.DeterminedBy = WildcardUnknown, "no probe was issued"
		return rep
	}
	outcomes := make([]string, len(probes))
	for i, p := range probes {
		outcomes[i] = classifyProbe(p)
		rep.Probes = append(rep.Probes, describeProbe(p, outcomes[i]))
	}
	if setWildcardVerdict(&rep, probes, outcomes) {
		rep.WWWViaWildcard = wwwIsWildcard(probes, append(wwwA.Addrs(), wwwAAAA.Addrs()...))
	}
	return rep
}

// setWildcardVerdict fills Status, DeterminedBy, Addresses and Consistent,
// and reports whether the zone answers every name. A single denial outweighs
// any number of answers: a wildcard, by definition, answers all of them.
func setWildcardVerdict(rep *WildcardReport, probes []wildProbe, outcomes []string) bool {
	for i, o := range outcomes {
		if o == probeDenied {
			rep.Status = WildcardAbsent
			rep.DeterminedBy = fmt.Sprintf("the random name %s is denied", probes[i].label)
			return false
		}
	}
	for i, o := range outcomes {
		if o == probeUnresolved {
			rep.Status = WildcardUnknown
			rep.DeterminedBy = fmt.Sprintf("the lookup for the random name %s did not complete", probes[i].label)
			return false
		}
	}
	addrs := unionAddrs(probes)
	rep.Status = WildcardPresent
	rep.DeterminedBy = fmt.Sprintf("%d random names all answer", len(probes))
	rep.Addresses = addrStrings(addrs)
	rep.Consistent = boolPtr(probesAgree(probes))
	return true
}

// wwwIsWildcard reports whether www resolves to exactly what one of the
// probes answered. Matching a single probe rather than the union is what a
// rotating wildcard requires: www is served one rotation, not all of them.
func wwwIsWildcard(probes []wildProbe, www []netip.Addr) bool {
	if len(www) == 0 {
		return false
	}
	for _, p := range probes {
		addrs := probeAddrs(p)
		if len(addrs) == len(www) && sameAddressSet(www, addrs) {
			return true
		}
	}
	return false
}

// describeProbe renders one probe for the report.
func describeProbe(p wildProbe, outcome string) WildcardProbe {
	return WildcardProbe{
		Label:     p.label,
		Status:    outcome,
		Addresses: addrStrings(probeAddrs(p)),
		CNAME:     probeCNAME(p),
	}
}

// probesAgree reports whether every probe answered with the same addresses
// and the same CNAME target. A catch-all that varies its answers is still a
// catch-all, so this qualifies the verdict rather than deciding it.
func probesAgree(probes []wildProbe) bool {
	first, firstCNAME := probeAddrs(probes[0]), probeCNAME(probes[0])
	for _, p := range probes[1:] {
		if probeCNAME(p) != firstCNAME {
			return false
		}
		other := probeAddrs(p)
		if len(other) != len(first) || !sameAddressSet(other, first) {
			return false
		}
	}
	return true
}

// unionAddrs collects every address any probe answered with, deduplicated.
func unionAddrs(probes []wildProbe) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, p := range probes {
		for _, ip := range probeAddrs(p) {
			if ip = ip.Unmap(); !seen[ip] {
				seen[ip] = true
				out = append(out, ip)
			}
		}
	}
	return out
}

// addrStrings renders addresses in a stable order, never nil.
func addrStrings(addrs []netip.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, ip := range addrs {
		out = append(out, ip.String())
	}
	sort.Strings(out)
	return out
}
