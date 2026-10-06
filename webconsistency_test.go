package main

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// findingsWithCode returns the messages of every finding with code.
func findingsWithCode(rep *Report, code string) []string {
	var out []string
	for _, f := range rep.Findings {
		if f.Code == code {
			out = append(out, f.Severity+" "+f.Host+": "+f.Message)
		}
	}
	return out
}

// ip-house.com, 2026-10-05: a CloudFront cache crossing hosts. The www
// per-address probes were sent to the apex while the www redirect chain,
// asking the same URL moments later, was answered 200. The report held
// both facts and said nothing; it must now say they disagree, and it must
// not turn that into a fail on its own.
func TestConsistency_IPHouseWWWChainAnswered200(t *testing.T) {
	rep, _, _ := replayFixture(t, "testdata/inconsistent/ip-house.com-www-chain-200.json")
	check(t, "inconsistency", findingsWithCode(rep, "http_response_inconsistent"), []string{
		"warn www: www: https://www.ip-house.com/ answered differently within one run: 301 -> https://ip-house.com/ (12 of 14); 200 (2 of 14)",
	})
	check(t, "no self redirect", findingsWithCode(rep, "redirect_self"), []string(nil))
	check(t, "still ok", rep.OK, true)
}

// One apex address answered a 301 to the URL it was asked for while the
// others served the page. Before, nothing in the report flagged it.
func TestConsistency_IPHouseSelfRedirectAtOneAddress(t *testing.T) {
	rep, _, _ := replayFixture(t, "testdata/inconsistent/ip-house.com-self-one-address.json")
	check(t, "self redirect", findingsWithCode(rep, "redirect_self"), []string{
		"fail apex: apex: https://ip-house.com/ redirects to itself on 1 of 12 addresses (13.32.205.24)",
	})
	check(t, "apex inconsistency", contains(findingsWithCode(rep, "http_response_inconsistent"), "200 (13 of 14); 301 -> https://ip-house.com/ (1 of 14)"), true)
	check(t, "a self redirect is a fail", rep.OK, false)
}

// Every address redirecting to itself is said once, without listing them.
func TestConsistency_IPHouseSelfEverywhere(t *testing.T) {
	rep, _, _ := replayFixture(t, "testdata/inconsistent/ip-house.com-self-everywhere.json")
	check(t, "self redirect", findingsWithCode(rep, "redirect_self"), []string{
		"fail apex: apex: https://ip-house.com/ redirects to itself on all 12 addresses",
	})
	// The same loop over both families is one finding per host.
	check(t, "loops", findingsWithCode(rep, "redirect_loop"), []string{
		"fail apex: apex (ipv4, ipv6): redirect loop http://ip-house.com/ (301) -> https://ip-house.com/ (301) -> https://ip-house.com/",
		"fail www: www (ipv4, ipv6): redirect loop http://www.ip-house.com/ (301) -> https://www.ip-house.com/ (301) -> https://ip-house.com/ (301) -> https://ip-house.com/",
	})
}

func webWith(apex *HostWeb) *Report {
	return &Report{Domain: "example.com", Web: WebSection{Apex: apex}}
}

func httpsAddr(ip string, status int, location string) AddrWeb {
	return AddrWeb{IP: ip, HTTPSRes: &HTTPResult{Status: status, Location: location}}
}

func TestConsistency_AgreeingAnswersAreSilent(t *testing.T) {
	var f findings
	f.consistencyFindings(webWith(&HostWeb{
		IPv4: []AddrWeb{httpsAddr("192.0.2.1", 301, "https://www.example.com/"), httpsAddr("192.0.2.2", 301, "https://www.example.com/")},
		Redirects: map[string]*RedirectChain{familyIPv4: {Hops: []RedirectHop{
			{URL: "https://example.com/", Status: 301, Location: "https://www.example.com/"},
		}}},
	}))
	check(t, "no findings", len(f.list), 0)
}

// Two answers that mean the same thing are one answer: a relative and an
// absolute Location to the same place, a default port spelled out, a
// different per-request query, and a host name in another case.
func TestConsistency_EquivalentRedirectsAgree(t *testing.T) {
	var f findings
	f.consistencyFindings(webWith(&HostWeb{IPv4: []AddrWeb{
		httpsAddr("192.0.2.1", 302, "/login?state=abc"),
		httpsAddr("192.0.2.2", 302, "https://example.com:443/login?state=def"),
		httpsAddr("192.0.2.3", 302, "https://EXAMPLE.com/login"),
	}}))
	check(t, "no findings", len(f.list), 0)
}

// A refusal answers the client, not the URL, and a redirect recorded
// without its Location names no target: neither is evidence of a server
// contradicting itself.
func TestConsistency_RefusalsAndBareRedirectsAreNotCompared(t *testing.T) {
	var f findings
	f.consistencyFindings(webWith(&HostWeb{
		IPv4: []AddrWeb{httpsAddr("192.0.2.1", 200, ""), httpsAddr("192.0.2.2", 429, ""), httpsAddr("192.0.2.3", 403, "")},
		Redirects: map[string]*RedirectChain{familyIPv4: {Hops: []RedirectHop{
			{URL: "https://example.com/", Status: 301},
		}}},
	}))
	check(t, "no findings", len(f.list), 0)
}

func TestConsistency_DifferentStatusesAreReported(t *testing.T) {
	var f findings
	f.consistencyFindings(webWith(&HostWeb{IPv4: []AddrWeb{
		httpsAddr("192.0.2.1", 200, ""), httpsAddr("192.0.2.2", 200, ""), httpsAddr("192.0.2.3", 404, ""),
	}}))
	check(t, "codes", findingCodes(&f), []string{"warn:http_response_inconsistent"})
	check(t, "message", f.warnings, []string{"apex: https://example.com/ answered differently within one run: 200 (2 of 3); 404 (1 of 3)"})
}

// A relative Location back to the request path is still a self redirect.
func TestConsistency_RelativeSelfRedirect(t *testing.T) {
	var f findings
	f.consistencyFindings(webWith(&HostWeb{IPv4: []AddrWeb{httpsAddr("192.0.2.1", 308, "/")}}))
	check(t, "codes", findingCodes(&f), []string{"fail:redirect_self"})
	check(t, "message", f.errors, []string{"apex: https://example.com/ redirects to itself on its only address (192.0.2.1)"})
}

// A redirect to the same path on the other scheme is the usual upgrade,
// not a self redirect.
func TestConsistency_SchemeUpgradeIsNotSelf(t *testing.T) {
	var f findings
	f.consistencyFindings(webWith(&HostWeb{IPv4: []AddrWeb{{IP: "192.0.2.1", HTTPRes: &HTTPResult{Status: 301, Location: "https://example.com/"}}}}))
	check(t, "no findings", len(f.list), 0)
}

// Loops that differ between families stay separate findings.
func TestRedirectFindings_DifferentLoopsPerFamily(t *testing.T) {
	var f findings
	f.redirectFindings("apex", map[string]*RedirectChain{
		familyIPv4: {Ended: RedirectLoop, Loop: true, Hops: []RedirectHop{{URL: "https://example.com/", Status: 301, Location: "https://example.com/"}}},
		familyIPv6: {Ended: RedirectLoop, Loop: true, Hops: []RedirectHop{{URL: "https://example.com/", Status: 302, Location: "https://example.com/"}}},
	})
	check(t, "two loops", len(f.errors), 2)
	check(t, "ipv4 first", strings.HasPrefix(f.errors[0], "apex (ipv4): "), true)
	check(t, "ipv6 second", strings.HasPrefix(f.errors[1], "apex (ipv6): "), true)
}

func TestDescribeSources(t *testing.T) {
	check(t, "all", describeSources([]string{"a", "b"}, 2), "all 2 addresses")
	check(t, "some", describeSources([]string{"a"}, 3), "1 of 3 addresses (a)")
	check(t, "many", describeSources([]string{"a", "b", "c", "d", "e"}, 9), "5 of 9 addresses (a, b, c, d, ...)")
}

// A chain that returns from https to http gives up what the upgrade
// protected; both families doing it at the same hop are one finding.
func TestRedirectFindings_Downgrade(t *testing.T) {
	hops := []RedirectHop{
		{URL: "http://example.com/", Status: 301, Location: "https://example.com/"},
		{URL: "https://example.com/", Status: 302, Location: "http://www.example.com/landing"},
		{URL: "http://www.example.com/landing", Status: 200},
	}
	var f findings
	f.redirectFindings("apex", map[string]*RedirectChain{
		familyIPv4: {Hops: hops, Ended: RedirectFinal},
		familyIPv6: {Hops: hops, Ended: RedirectFinal},
	})
	check(t, "one finding", f.warnings, []string{"apex (ipv4, ipv6): redirect from https to http: https://example.com/ -> http://www.example.com/landing"})

	var g findings
	g.redirectFindings("apex", map[string]*RedirectChain{familyIPv4: {Hops: hops[:1], Ended: RedirectFinal}})
	check(t, "an upgrade is not a downgrade", g.warnings, []string(nil))
}

// A loop between two spellings of one URL is still a loop, and a redirect
// to a scheme the follower does not speak ends the chain as broken.
func TestFollowRedirects_NormalisedLoopAndScheme(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	hosts := hostAddrs{"example.com": ip}
	d := newMappedDialer()
	d.mapTarget(ip.String(), 80, plainServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "example.com" {
			w.Header().Set("Location", "http://EXAMPLE.com:80/")
		} else {
			w.Header().Set("Location", "http://example.com/")
		}
		w.WriteHeader(http.StatusMovedPermanently)
	})))
	c := followRedirects(context.Background(), d, "http", "example.com", hosts, time.Second)
	check(t, "loop", []any{c.Loop, c.Ended, len(c.Hops)}, []any{true, RedirectLoop, 1})

	d.mapTarget(ip.String(), 80, plainServer(t, redirectHandler(301, "ftp://example.com/file")))
	c = followRedirects(context.Background(), d, "http", "example.com", hosts, time.Second)
	check(t, "non-http", []any{c.Ended, c.Error}, []any{RedirectFailed, "redirect to a non-HTTP URL ftp://example.com/file"})

	d.mapTarget(ip.String(), 80, plainServer(t, redirectHandler(301, "http://example.com:70000/")))
	c = followRedirects(context.Background(), d, "http", "example.com", hosts, time.Second)
	check(t, "bad port", []any{c.Ended, strings.Contains(c.Error, "invalid port")}, []any{RedirectFailed, true})
}
