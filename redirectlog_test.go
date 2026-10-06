package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// chainCodes are the findings only a followed redirect chain can raise.
var chainCodes = []string{"redirect_loop", "redirect_hop_limit", "redirect_broken", "redirect_ends_error", "redirect_downgrade"}

func TestParseArgs_RedirectLog(t *testing.T) {
	for _, c := range []struct {
		args []string
		want bool
	}{
		{[]string{"x.org"}, false},
		{[]string{"-redirectlog", "x.org"}, true},
		{[]string{"--redirectlog", "x.org"}, true},
		{[]string{"x.org", "-redirectlog", "@1.1.1.1"}, true},
	} {
		cfg, err := parseArgs(c.args)
		if err != nil {
			t.Fatalf("%v: %v", c.args, err)
		}
		check(t, strings.Join(c.args, " "), cfg.RedirectLog, c.want)
	}
}

// By default no chain is followed: the per-address probes still record the
// first answer on 80 and 443, but no host carries redirects, the report says
// the log was off, and the JSON has no redirects key at all.
func TestRun_RedirectLogOffByDefault(t *testing.T) {
	g := googleScenario(t)
	rep := g.s.run()
	check(t, "header", rep.RedirectLog, false)
	apex, www := rep.Web.Apex, rep.Web.WWW
	if apex == nil || www == nil {
		t.Fatalf("web %+v", rep.Web)
	}
	check(t, "apex redirects", apex.Redirects == nil, true)
	check(t, "www redirects", www.Redirects == nil, true)
	a4 := apex.IPv4[0]
	check(t, "per-address http still probed", []interface{}{a4.HTTPRes.Status, a4.HTTPRes.Location}, []interface{}{301, "https://google.com/"})
	check(t, "per-address https still probed", a4.HTTPSRes.Status, 200)
	check(t, "hsts still read", a4.HTTPSRes.HSTS != nil, true)
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	check(t, "no redirects key", strings.Contains(string(b), `"redirects"`), false)
	check(t, "header key", strings.Contains(string(b), `"redirect_log":false`), true)
}

func TestRun_RedirectLogOn(t *testing.T) {
	g := googleScenario(t)
	g.s.cfg.RedirectLog = true
	rep := g.s.run()
	check(t, "header", rep.RedirectLog, true)
	check(t, "apex v4 chain", rep.Web.Apex.Redirects[familyIPv4] != nil, true)
	check(t, "www v4 chain", rep.Web.WWW.Redirects[familyIPv4] != nil, true)
}

// stripChains decodes a captured report and drops its chains, as a run
// without -redirectlog would have produced it, then rebuilds the findings.
func stripChains(t *testing.T, path string) *Report {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	rep := &Report{}
	if err := json.Unmarshal(b, rep); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	for _, h := range []*HostWeb{rep.Web.Apex, rep.Web.WWW} {
		if h != nil {
			h.Redirects = nil
		}
	}
	rep.RedirectLog = false
	buildFindings(rep)
	return rep
}

// ip-house.com sent every address back to the URL it asked for. That is
// seen by the per-address probes alone, so it is still a fail without the
// chains; the loops are the chains' and are not reported.
func TestConsistency_SelfRedirectWithoutChains(t *testing.T) {
	rep := stripChains(t, "testdata/inconsistent/ip-house.com-self-everywhere.json")
	check(t, "self redirect", findingsWithCode(rep, "redirect_self"), []string{
		"fail apex: apex: https://ip-house.com/ redirects to itself on all 12 addresses",
	})
	for _, code := range chainCodes {
		check(t, code, findingsWithCode(rep, code), []string(nil))
	}
	check(t, "still a fail", rep.OK, false)
}

// One address disagreeing with the others is caught among the per-address
// answers without any chain hop: 12 answers, where the chains made it 14.
func TestConsistency_OneAddressWithoutChains(t *testing.T) {
	rep := stripChains(t, "testdata/inconsistent/ip-house.com-self-one-address.json")
	check(t, "self redirect", findingsWithCode(rep, "redirect_self"), []string{
		"fail apex: apex: https://ip-house.com/ redirects to itself on 1 of 12 addresses (13.32.205.24)",
	})
	check(t, "inconsistency without chain hops", contains(findingsWithCode(rep, "http_response_inconsistent"), "200 (11 of 12); 301 -> https://ip-house.com/ (1 of 12)"), true)
}
