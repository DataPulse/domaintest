package main

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// A run fetches the same URL several times: once per address of the host
// and again as a hop of each family's redirect chain. A server is expected
// to give one answer to one request. When it does not, as with a CDN whose
// cache key ignores the Host header (ip-house.com, 2026-10-05: the apex
// answered 200 at some addresses and a 301 to itself at others), the
// report would otherwise hold contradictory facts with nothing to say so.
// These helpers compare only what the run already observed; they never
// fetch anything.

// webObservation is one response seen for a URL.
type webObservation struct {
	answer string // "200", or "301 -> https://example.com/path"
	self   bool   // a redirect whose target is the request URL itself
	probe  bool   // a per-address probe rather than a redirect-chain hop
	source string // the address, or "redirect chain (ipv4)"
}

// urlObservations groups the run's observations by URL.
type urlObservations struct {
	url  string
	host string // "apex" or "www"
	obs  []webObservation
}

// collectWebObservations gathers every HTTP response of the run, keyed by
// URL, in a deterministic order.
func collectWebObservations(domain string, web WebSection) []urlObservations {
	byKey := map[string]*urlObservations{}
	var order []string
	note := func(raw string, status int, location, source string, probe bool) {
		key, ok := urlKey(raw)
		if !ok || !comparable(status, location) {
			return
		}
		g := byKey[key]
		if g == nil {
			g = &urlObservations{url: raw, host: hostLabel(domain, raw)}
			byKey[key] = g
			order = append(order, key)
		}
		answer, self := describeAnswer(raw, key, status, location)
		g.obs = append(g.obs, webObservation{answer: answer, self: self, probe: probe, source: source})
	}
	hosts := []struct {
		name string
		h    *HostWeb
	}{{domain, web.Apex}, {"www." + domain, web.WWW}}
	for _, hw := range hosts {
		notePerAddress(hw.name, hw.h, note)
	}
	for _, hw := range hosts {
		noteChains(hw.h, note)
	}
	sort.Strings(order)
	out := make([]urlObservations, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out
}

type noteFn func(raw string, status int, location, source string, probe bool)

func notePerAddress(host string, h *HostWeb, note noteFn) {
	for _, a := range h.addrs() {
		if a.HTTPRes != nil {
			note("http://"+host+"/", a.HTTPRes.Status, a.HTTPRes.Location, a.IP, true)
		}
		if a.HTTPSRes != nil {
			note("https://"+host+"/", a.HTTPSRes.Status, a.HTTPSRes.Location, a.IP, true)
		}
	}
}

func noteChains(h *HostWeb, note noteFn) {
	if h == nil {
		return
	}
	for _, fam := range sortedChainKeys(h.Redirects) {
		for _, hop := range h.Redirects[fam].Hops {
			note(hop.URL, hop.Status, hop.Location, "redirect chain ("+fam+")", false)
		}
	}
}

// comparable reports whether a response says something about the URL
// rather than about the probe. A refusal (a WAF 403, a 429 rate limit)
// answers this client, and a rate limit starting partway through a run is
// not the server contradicting itself. A redirect recorded without its
// Location (reports from before hops kept it) names no target to compare.
func comparable(status int, location string) bool {
	switch {
	case status == 0, probeRefused(status):
		return false
	case isRedirect(status) && location == "":
		return false
	}
	return true
}

// urlKey identifies a request target: scheme, host name in its a-label
// form, port, path and query. The fragment never reaches a server.
func urlKey(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	return requestKey(u, true)
}

var defaultPort = map[string]string{"http": "80", "https": "443"}

func requestKey(u *url.URL, withQuery bool) (string, bool) {
	host := bareName(u.Hostname())
	if host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", false
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	key := u.Scheme + "://" + host
	if p := u.Port(); p != "" && p != defaultPort[u.Scheme] {
		key += ":" + p
	}
	key += path
	if withQuery && u.RawQuery != "" {
		key += "?" + u.RawQuery
	}
	return key, true
}

// describeAnswer renders a response for comparison. A redirect is named by
// where it points, without the query: a query often carries a per-request
// token (an SSO nonce), and two redirects that differ only there are the
// same answer.
func describeAnswer(raw, key string, status int, location string) (string, bool) {
	if !isRedirect(status) || location == "" {
		return strconv.Itoa(status), false
	}
	base, err := url.Parse(raw)
	if err != nil {
		return strconv.Itoa(status), false
	}
	ref, err := url.Parse(location)
	if err != nil {
		return fmt.Sprintf("%d -> (bad Location)", status), false
	}
	target := base.ResolveReference(ref)
	full, ok := requestKey(target, true)
	if !ok {
		return fmt.Sprintf("%d -> %s", status, clipLocation(location)), false
	}
	short, _ := requestKey(target, false)
	return fmt.Sprintf("%d -> %s", status, short), full == key
}

// hostLabel names the host a URL belongs to, as findings label it.
func hostLabel(domain, raw string) string {
	u, err := url.Parse(raw)
	if err == nil && bareName(u.Hostname()) == bareName(domain) {
		return "apex"
	}
	return "www"
}

// answerTally counts how often each distinct answer was seen, most
// frequent first.
func answerTally(obs []webObservation) []string {
	counts := map[string]int{}
	for _, o := range obs {
		counts[o.answer]++
	}
	answers := make([]string, 0, len(counts))
	for a := range counts {
		answers = append(answers, a)
	}
	sort.Slice(answers, func(i, j int) bool {
		if counts[answers[i]] != counts[answers[j]] {
			return counts[answers[i]] > counts[answers[j]]
		}
		return answers[i] < answers[j]
	})
	parts := make([]string, len(answers))
	for i, a := range answers {
		parts[i] = fmt.Sprintf("%s (%d of %d)", a, counts[a], len(obs))
	}
	return parts
}

// selfRedirects lists the per-address probes that were sent back to the
// URL they asked for. A chain hop doing the same is a redirect loop and
// is reported as one.
func selfRedirects(obs []webObservation) (sources []string, probes int) {
	for _, o := range obs {
		if !o.probe {
			continue
		}
		probes++
		if o.self {
			sources = append(sources, o.source)
		}
	}
	return sources, probes
}

// maxListedSources bounds how many addresses a message names; past it,
// the count alone says enough.
const maxListedSources = 4

// describeSources names the probes a finding is about: every one when
// they were all affected, a few by address otherwise.
func describeSources(s []string, total int) string {
	switch {
	case total == 1 && len(s) == 1:
		return "its only address (" + s[0] + ")"
	case len(s) == total:
		return fmt.Sprintf("all %d addresses", total)
	case len(s) <= maxListedSources:
		return fmt.Sprintf("%d of %d addresses (%s)", len(s), total, strings.Join(s, ", "))
	}
	return fmt.Sprintf("%d of %d addresses (%s, ...)", len(s), total, strings.Join(s[:maxListedSources], ", "))
}
