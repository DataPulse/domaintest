package main

import (
	"strings"
	"testing"
)

func TestWildcardName(t *testing.T) {
	n := wildcardName("example.com")
	check(t, "suffix", strings.HasSuffix(n, ".example.com"), true)
	check(t, "prefix", strings.HasPrefix(n, "domaintest-"), true)
	check(t, "unique", wildcardName("example.com") != n, true)
}

func TestAssessWildcard(t *testing.T) {
	probeA := parseDelvYAML(fixture(t, "delv/wild/domaintest-a1b2c3d4_github_io_a.yaml"), "A")
	probeAAAA := parseDelvYAML(fixture(t, "delv/wild/domaintest-a1b2c3d4_github_io_aaaa.yaml"), "AAAA")
	wwwA := parseDelvYAML(fixture(t, "delv/wild/www_github_io_a.yaml"), "A")
	wwwAAAA := parseDelvYAML(fixture(t, "delv/wild/github_io_aaaa.yaml"), "AAAA") // nxrrset
	rep := assessWildcard(probeA, probeAAAA, wwwA, wwwAAAA)
	check(t, "github.io is a wildcard zone", rep.Present, true)
	check(t, "eight addresses", len(rep.Addresses), 8)
	// www.github.io has only the four A records; the wildcard answers A+AAAA,
	// so the sets differ and www is not flagged as wildcard-only.
	check(t, "www differs (has no AAAA)", rep.WWWViaWildcard, false)

	rep = assessWildcard(probeA, wwwAAAA, wwwA, wwwAAAA)
	check(t, "same set means via wildcard", rep.WWWViaWildcard, true)

	none := parseDelvYAML(fixture(t, "delv/wild/domaintest-a1b2c3d4_jschmidt_org_a.yaml"), "A")
	rep = assessWildcard(none, none, wwwA, wwwAAAA)
	check(t, "no wildcard", rep.Present, false)
	check(t, "no addresses", len(rep.Addresses), 0)

	nx := parseDelvYAML(fixture(t, "delv/wild/domaintest-a1b2c3d4_google_com_a.yaml"), "A")
	check(t, "nxdomain is not a wildcard", assessWildcard(nx, nx, wwwA, wwwAAAA).Present, false)

	cname := parseDelvYAML(fixture(t, "delv/www_github_cname.yaml"), "A")
	check(t, "a CNAME answer counts as present", assessWildcard(cname, none, none, none).Present, true)
}
