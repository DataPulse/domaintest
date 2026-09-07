package main

import (
	"strings"
	"testing"
)

func TestWildcardLabels(t *testing.T) {
	got := wildcardLabels(wildcardProbeCount)
	check(t, "three labels", len(got), 3)
	seen := map[string]bool{}
	for _, l := range got {
		check(t, "twelve characters: "+l, len(l), wildcardLabelLen)
		check(t, "a-z only: "+l, strings.Trim(l, "abcdefghijklmnopqrstuvwxyz"), "")
		check(t, "distinct within a run: "+l, seen[l], false)
		seen[l] = true
	}
	// A fresh set every run, so a zone cannot learn the names we ask for.
	check(t, "distinct across runs", wildcardLabels(1)[0] == got[0], false)
}

// probe builds one probe from captured fixtures.
func probe(t *testing.T, label, aFile, aaaaFile string) wildProbe {
	t.Helper()
	p := wildProbe{label: label}
	if aFile != "" {
		p.a = parseDelvYAML(fixture(t, aFile), "A")
	}
	if aaaaFile != "" {
		p.aaaa = parseDelvYAML(fixture(t, aaaaFile), "AAAA")
	}
	return p
}

func githubProbe(t *testing.T, label string) wildProbe {
	t.Helper()
	return probe(t, label, "delv/wild/"+label+"_github_io_a.yaml", "delv/wild/"+label+"_github_io_aaaa.yaml")
}

// Each probe is judged from both of its lookups together. The wordpress.com
// row is the reason: a wildcard CNAME answers A with the CNAME and its
// addresses but returns NXRRSET for AAAA, still carrying the CNAME, so either
// lookup alone would give the wrong verdict.
func TestClassifyProbe(t *testing.T) {
	timeout := Lookup{Status: StatusTimeout}
	nx := parseDelvYAML(fixture(t, "delv/wild/qhrmzvbxklap_google_com_a.yaml"), "A")
	nodata := parseDelvYAML(fixture(t, "delv/wild/qhrmzvbxklap_cloudflare_com_a.yaml"), "A")

	check(t, "addresses answer", classifyProbe(githubProbe(t, "qhrmzvbxklap")), probeAnswered)
	check(t, "wildcard cname, aaaa nxrrset", classifyProbe(probe(t, "qhrmzvbxklap",
		"delv/wild/qhrmzvbxklap_wordpress_com_a.yaml", "delv/wild/qhrmzvbxklap_wordpress_com_aaaa.yaml")), probeAnswered)
	check(t, "nxdomain", classifyProbe(wildProbe{a: nx, aaaa: nx}), probeDenied)
	check(t, "nodata on both types", classifyProbe(wildProbe{a: nodata, aaaa: nodata}), probeDenied)
	// NXDOMAIN is a name-level denial, so the sibling query cannot change it.
	check(t, "nxdomain plus a timeout", classifyProbe(wildProbe{a: nx, aaaa: timeout}), probeDenied)
	// NODATA denies only the type asked about, so half an answer decides nothing.
	check(t, "nodata plus a timeout", classifyProbe(wildProbe{a: nodata, aaaa: timeout}), probeUnresolved)
	check(t, "nothing answered", classifyProbe(wildProbe{a: timeout, aaaa: timeout}), probeUnresolved)
	check(t, "failure is not a denial", classifyProbe(wildProbe{a: Lookup{Status: StatusFailure}, aaaa: timeout}), probeUnresolved)
}

func TestAssessWildcard_Present(t *testing.T) {
	var probes []wildProbe
	for _, l := range testWildcardLabels {
		probes = append(probes, githubProbe(t, l))
	}
	w := assessWildcard(probes, "", Lookup{}, Lookup{})
	check(t, "present", w.Status, WildcardPresent)
	check(t, "says why", w.DeterminedBy, "3 random names all answer")
	check(t, "eight addresses, deduplicated", len(w.Addresses), 8)
	check(t, "three probes recorded", len(w.Probes), 3)
	check(t, "every probe answered", w.Probes[0].Status, probeAnswered)
	check(t, "consistent", *w.Consistent, true)

	// www resolving to exactly the wildcard's answers is the one finding.
	wwwA := probes[0].a
	check(t, "www via wildcard", assessWildcard(probes, "", wwwA, probes[0].aaaa).WWWViaWildcard, true)
	check(t, "www with only some of them is not", assessWildcard(probes, "", wwwA, Lookup{}).WWWViaWildcard, false)
}

// A wildcard CNAME is still a wildcard, and the target is reported.
func TestAssessWildcard_CNAME(t *testing.T) {
	var probes []wildProbe
	for _, l := range testWildcardLabels {
		probes = append(probes, probe(t, l,
			"delv/wild/"+l+"_wordpress_com_a.yaml", "delv/wild/"+l+"_wordpress_com_aaaa.yaml"))
	}
	w := assessWildcard(probes, "", Lookup{}, Lookup{})
	check(t, "present", w.Status, WildcardPresent)
	check(t, "cname recorded", w.Probes[0].CNAME, "lb.wordpress.com.")
	check(t, "consistent", *w.Consistent, true)
}

// A denial anywhere means the zone does not answer every name, and a probe
// that never came back is never a denial.
func TestAssessWildcard_AbsentAndUnknown(t *testing.T) {
	nx := parseDelvYAML(fixture(t, "delv/wild/qhrmzvbxklap_google_com_a.yaml"), "A")
	nodata := parseDelvYAML(fixture(t, "delv/wild/qhrmzvbxklap_cloudflare_com_a.yaml"), "A")
	denied := wildProbe{label: "aaaaaaaaaaaa", a: nx, aaaa: nx}
	empty := wildProbe{label: "bbbbbbbbbbbb", a: nodata, aaaa: nodata}
	lost := wildProbe{label: "cccccccccccc", a: Lookup{Status: StatusTimeout}, aaaa: Lookup{Status: StatusTimeout}}

	for _, c := range []struct {
		name   string
		probes []wildProbe
		status string
		reason string
	}{
		{"nxdomain", []wildProbe{denied}, WildcardAbsent, "the random name aaaaaaaaaaaa is denied"},
		{"nodata", []wildProbe{empty}, WildcardAbsent, "the random name bbbbbbbbbbbb is denied"},
		{"nothing answered", []wildProbe{lost}, WildcardUnknown, "the lookup for the random name cccccccccccc did not complete"},
		// One name denied outweighs the others: a wildcard answers all of them.
		{"one dissenter", []wildProbe{githubProbe(t, "qhrmzvbxklap"), denied, lost}, WildcardAbsent, "the random name aaaaaaaaaaaa is denied"},
		// Two answered and one never came back: not enough to confirm.
		{"unconfirmed", []wildProbe{githubProbe(t, "qhrmzvbxklap"), githubProbe(t, "tzwnpcdfjyeu"), lost}, WildcardUnknown, "the lookup for the random name cccccccccccc did not complete"},
	} {
		w := assessWildcard(c.probes, "", Lookup{}, Lookup{})
		check(t, c.name+": status", w.Status, c.status)
		check(t, c.name+": reason", w.DeterminedBy, c.reason)
		check(t, c.name+": nothing to qualify", w.Consistent == nil, true)
		check(t, c.name+": no addresses claimed", w.Addresses, []string{})
		check(t, c.name+": www untouched", w.WWWViaWildcard, false)
	}
}

// Answers that vary between probes are still a wildcard: something is
// synthesising them. The variance qualifies the verdict rather than deciding it.
func TestAssessWildcard_VaryingAnswers(t *testing.T) {
	a := githubProbe(t, "qhrmzvbxklap")
	b := githubProbe(t, "tzwnpcdfjyeu")
	c := probe(t, "kbsvxlmqrtdh", "delv/wild/kbsvxlmqrtdh_wordpress_com_a.yaml", "")
	w := assessWildcard([]wildProbe{a, b, c}, "", Lookup{}, Lookup{})
	check(t, "still a wildcard", w.Status, WildcardPresent)
	check(t, "but not consistent", *w.Consistent, false)
	check(t, "addresses are the union", len(w.Addresses) > 8, true)
}

// A skip reason is an answer already in hand, so it is a definite negative
// and costs no queries.
func TestAssessWildcard_Skipped(t *testing.T) {
	w := assessWildcard(nil, "www is NXDOMAIN, so no wildcard could have answered for it", Lookup{}, Lookup{})
	check(t, "absent", w.Status, WildcardAbsent)
	check(t, "says why", w.DeterminedBy, "www is NXDOMAIN, so no wildcard could have answered for it")
	check(t, "no probes", w.Probes, []WildcardProbe{})
	check(t, "nothing to qualify", w.Consistent == nil, true)

	// No probes and no reason cannot happen, but it must not read as a pass.
	check(t, "never a vacuous absent", assessWildcard(nil, "", Lookup{}, Lookup{}).Status, WildcardUnknown)
}

func TestWildcardSkipReason(t *testing.T) {
	nx := Lookup{Status: StatusNXDomain}
	ok := Lookup{Status: StatusOK, Records: []string{"192.0.2.1"}}
	nodata := Lookup{Status: StatusNXRRSet}

	check(t, "nonexistent domain", wildcardSkipReason(map[string]Lookup{"A": nx, "NS": nx}, nil), "the domain does not exist")
	check(t, "www nxdomain", wildcardSkipReason(map[string]Lookup{"A": ok, "NS": ok}, map[string]Lookup{"A": nx}),
		"www is NXDOMAIN, so no wildcard could have answered for it")
	// www NODATA means www exists with some other type, which says nothing
	// about the names around it, so the probe still has to run.
	check(t, "www nodata probes anyway", wildcardSkipReason(map[string]Lookup{"A": ok, "NS": ok}, map[string]Lookup{"A": nodata}), "")
	check(t, "healthy domain probes", wildcardSkipReason(map[string]Lookup{"A": ok, "NS": ok}, map[string]Lookup{"A": ok}), "")
}
