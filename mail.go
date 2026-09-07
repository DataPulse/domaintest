package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// lookupFn resolves name/qtype through the run's memoised delv cache.
type lookupFn func(name, qtype string) Lookup

// ---------------------------------------------------------------- DMARC

// DMARC is the parsed _dmarc policy.
type DMARC struct {
	Present         bool     `json:"present"`
	Policy          string   `json:"policy,omitempty"`
	SubdomainPolicy string   `json:"subdomain_policy,omitempty"`
	Pct             int      `json:"pct"`
	RUA             bool     `json:"rua"`
	Records         int      `json:"records"`
	Problems        []string `json:"problems"`
}

// parseDMARC evaluates the TXT records found at _dmarc.<domain>.
func parseDMARC(l Lookup) DMARC {
	d := DMARC{Pct: 100, Problems: []string{}}
	var dmarc []string
	for _, r := range l.Records {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), "v=dmarc1") {
			dmarc = append(dmarc, r)
		}
	}
	d.Records = len(dmarc)
	if len(dmarc) == 0 {
		return d
	}
	d.Present = true
	if len(dmarc) > 1 {
		d.Problems = append(d.Problems, "multiple DMARC records (invalid, receivers ignore all)")
	}
	tags := parseTags(dmarc[0])
	d.Policy = tags["p"]
	d.SubdomainPolicy = tags["sp"]
	d.RUA = tags["rua"] != ""
	if v, ok := tags["pct"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			d.Pct = n
		}
	}
	switch d.Policy {
	case "none", "quarantine", "reject":
	case "":
		d.Problems = append(d.Problems, "missing p= tag")
	default:
		d.Problems = append(d.Problems, "unknown policy p="+d.Policy)
	}
	return d
}

// parseTags splits "k=v; k2=v2" style records (DMARC, DKIM, MTA-STS, TLSRPT).
func parseTags(record string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(record, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			tags[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.TrimSpace(kv[1])
		}
	}
	return tags
}

// ------------------------------------------------------------------ SPF

// spfLookupLimit is the RFC 7208 §4.6.4 limit on DNS-querying terms.
const spfLookupLimit = 10

// spfVoidLimit is the RFC 7208 limit on lookups that return no records.
const spfVoidLimit = 2

// SPFResult is the evaluation of the apex SPF policy.
type SPFResult struct {
	Records     int      `json:"records"`
	Lookups     int      `json:"lookups"`
	VoidLookups int      `json:"void_lookups"`
	All         string   `json:"all,omitempty"`
	Includes    []string `json:"includes"`
	Problems    []string `json:"problems"`
}

// spfEvaluator walks include/redirect chains counting DNS-querying terms.
type spfEvaluator struct {
	lookup   lookupFn
	visited  map[string]bool
	lookups  int
	void     int
	includes []string
	problems []string
}

// evaluateSPF parses the apex TXT records and follows the include tree.
func evaluateSPF(domain string, txt Lookup, lookup lookupFn) SPFResult {
	spf := spfRecords(txt.Records)
	res := SPFResult{Records: len(spf), Includes: []string{}, Problems: []string{}}
	if len(spf) == 0 {
		return res
	}
	e := &spfEvaluator{lookup: lookup, visited: map[string]bool{domain: true}}
	if len(spf) > 1 {
		e.problems = append(e.problems, "multiple SPF records (permerror: SPF fails entirely)")
	}
	res.All = e.walk(spf[0], domain, 0)
	res.Lookups, res.VoidLookups = e.lookups, e.void
	res.Includes = nonNil(e.includes)
	if e.lookups > spfLookupLimit {
		e.problems = append(e.problems, fmt.Sprintf("%d DNS lookups exceed the limit of %d (permerror: SPF fails entirely)", e.lookups, spfLookupLimit))
	}
	if e.void > spfVoidLimit {
		e.problems = append(e.problems, fmt.Sprintf("%d void lookups exceed the limit of %d", e.void, spfVoidLimit))
	}
	res.Problems = nonNil(e.problems)
	return res
}

func spfRecords(txt []string) []string {
	var out []string
	for _, r := range txt {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), "v=spf1") {
			out = append(out, strings.TrimSpace(r))
		}
	}
	return out
}

// spfTerm is one mechanism or modifier.
type spfTerm struct {
	qualifier string // + - ~ ?
	name      string // a, mx, include, redirect, all, ...
	arg       string
	modifier  bool
}

func parseSPFTerms(record string) []spfTerm {
	var terms []spfTerm
	for _, f := range strings.Fields(record)[1:] {
		t := spfTerm{qualifier: "+"}
		if strings.ContainsAny(f[:1], "+-~?") {
			t.qualifier, f = f[:1], f[1:]
		}
		if i := strings.IndexByte(f, '='); i > 0 && !strings.ContainsRune(f[:i], ':') {
			t.modifier, t.name, t.arg = true, strings.ToLower(f[:i]), f[i+1:]
		} else if i := strings.IndexAny(f, ":/"); i > 0 {
			t.name, t.arg = strings.ToLower(f[:i]), f[i:]
		} else {
			t.name = strings.ToLower(f)
		}
		terms = append(terms, t)
	}
	return terms
}

// walk evaluates one record for domain at depth and returns the qualifier
// of its all mechanism ("" when none).
func (e *spfEvaluator) walk(record, domain string, depth int) string {
	all := ""
	terminated := false
	for _, t := range parseSPFTerms(record) {
		switch {
		case t.name == "all" && !t.modifier:
			all, terminated = t.qualifier+"all", true
			e.noteAll(t.qualifier, depth)
		case t.name == "redirect" && t.modifier:
			terminated = true
			e.follow(t, depth)
		case t.name == "include" && !t.modifier:
			e.follow(t, depth)
		default:
			e.term(t, domain)
		}
	}
	if depth == 0 && !terminated {
		e.problems = append(e.problems, "record has no all mechanism or redirect (default neutral)")
	}
	return all
}

// follow counts an include/redirect and walks its target.
func (e *spfEvaluator) follow(t spfTerm, depth int) {
	e.lookups++
	e.descend(strings.TrimPrefix(t.arg, ":"), depth)
}

// term accounts for a mechanism that does not reference another record.
func (e *spfEvaluator) term(t spfTerm, domain string) {
	switch {
	case t.name == "a", t.name == "mx", t.name == "exists":
		e.lookups++
	case t.name == "ptr":
		e.lookups++
		e.problems = append(e.problems, "ptr mechanism is deprecated (RFC 7208 §5.5)")
	case t.name == "ip4", t.name == "ip6", t.modifier:
	default:
		e.problems = append(e.problems, "unknown mechanism "+t.name+" in "+domain)
	}
}

func (e *spfEvaluator) noteAll(qualifier string, depth int) {
	if depth > 0 {
		return
	}
	switch qualifier {
	case "+":
		e.problems = append(e.problems, "+all authorises every sender (no protection)")
	case "?":
		e.problems = append(e.problems, "?all is neutral (no protection)")
	}
}

// descend fetches an included domain's SPF and walks it. Macro targets
// cannot be expanded and count as one lookup only.
func (e *spfEvaluator) descend(target string, depth int) {
	target = strings.ToLower(strings.TrimSuffix(target, "."))
	if strings.Contains(target, "%") || target == "" || e.visited[target] || depth > 20 {
		return
	}
	e.visited[target] = true
	e.includes = append(e.includes, target)
	if e.lookups > spfLookupLimit*3 {
		return // pathological tree; the limit finding already fires
	}
	l := e.lookup(target, "TXT")
	recs := spfRecords(l.Records)
	if !l.HasRecords() || len(recs) == 0 {
		e.void++
		if l.Answered() {
			e.problems = append(e.problems, "include:"+target+" has no SPF record")
		}
		return
	}
	e.walk(recs[0], target, depth+1)
}

// ------------------------------------------------------------------- MX

// MXCheck is the sanity result for one MX exchange.
type MXCheck struct {
	Host      string   `json:"host"`
	Pref      int      `json:"preference"`
	Addresses int      `json:"addresses"`
	CNAME     bool     `json:"cname"`
	IPLiteral bool     `json:"ip_literal"`
	Problems  []string `json:"problems"`
}

// checkMX validates every MX target: no IP literals, no CNAME, resolvable.
// Targets are checked in parallel.
func checkMX(mx Lookup, lookup lookupFn) []MXCheck {
	out := []MXCheck{}
	for _, rec := range mx.Records {
		f := strings.Fields(rec)
		if len(f) != 2 {
			continue
		}
		c := MXCheck{Host: strings.ToLower(f[1]), Problems: []string{}}
		c.Pref, _ = strconv.Atoi(f[0])
		if c.Host == "." && len(mx.Records) > 1 {
			c.Problems = append(c.Problems, "null MX mixed with real MX records")
		}
		out = append(out, c)
	}
	var tasks []func()
	for i := range out {
		if out[i].Host == "." {
			continue
		}
		tasks = append(tasks, func() { out[i] = checkMXTarget(out[i], lookup) })
	}
	parallel(tasks...)
	return out
}

func checkMXTarget(c MXCheck, lookup lookupFn) MXCheck {
	if _, err := netip.ParseAddr(strings.TrimSuffix(c.Host, ".")); err == nil {
		c.IPLiteral = true
		c.Problems = append(c.Problems, "MX target is an IP literal (invalid, RFC 2181 §10.3)")
		return c
	}
	a, aaaa := lookup(c.Host, "A"), lookup(c.Host, "AAAA")
	c.Addresses = len(a.Addrs()) + len(aaaa.Addrs())
	if len(a.CNAME) > 0 || len(aaaa.CNAME) > 0 {
		c.CNAME = true
		c.Problems = append(c.Problems, "MX target is a CNAME (RFC 2181 §10.3)")
	}
	switch {
	case a.Status == StatusNXDomain:
		c.Problems = append(c.Problems, "MX target does not exist")
	case !a.Answered() && !aaaa.Answered():
		c.Problems = append(c.Problems, "MX target lookup failed")
	case c.Addresses == 0:
		c.Problems = append(c.Problems, "MX target has no address")
	}
	return c
}

// ----------------------------------------------------------------- DKIM

// dkimSelectors are the selectors probed; DKIM cannot be enumerated, so
// these cover the common providers (Microsoft 365, Google, generic).
var dkimSelectors = []string{"google", "selector1", "selector2", "default", "k1", "s1", "mail", "dkim"}

// DKIMResult lists selectors that publish a key.
type DKIMResult struct {
	SelectorsFound []string `json:"selectors_found"`
	Revoked        []string `json:"revoked"`
}

// probeDKIM looks every selector up in parallel (a dead resolver would
// otherwise cost one timeout per selector, sequentially).
func probeDKIM(domain string, lookup lookupFn) DKIMResult {
	res := DKIMResult{SelectorsFound: []string{}, Revoked: []string{}}
	answers := make([]Lookup, len(dkimSelectors))
	var tasks []func()
	for i, sel := range dkimSelectors {
		tasks = append(tasks, func() { answers[i] = lookup(sel+"._domainkey."+domain, "TXT") })
	}
	parallel(tasks...)
	for i, sel := range dkimSelectors {
		l := answers[i]
		for _, r := range l.Records {
			tags := parseTags(r)
			_, hasP := tags["p"]
			if !hasP && !strings.HasPrefix(strings.ToLower(r), "v=dkim1") {
				continue
			}
			res.SelectorsFound = append(res.SelectorsFound, sel)
			if hasP && tags["p"] == "" {
				res.Revoked = append(res.Revoked, sel)
			}
			break
		}
	}
	return res
}

// -------------------------------------------------------------- MTA-STS

// MTASTS is the _mta-sts record plus the fetched policy.
type MTASTS struct {
	Record    bool     `json:"record"`
	ID        string   `json:"id,omitempty"`
	Mode      string   `json:"mode,omitempty"`
	MaxAge    int      `json:"max_age,omitempty"`
	MXPattern []string `json:"mx"`
	PolicyOK  bool     `json:"policy_ok"`
	MXCovered bool     `json:"mx_covered"`
	Error     string   `json:"error,omitempty"`
}

// parseMTASTSRecord reads the _mta-sts TXT.
func parseMTASTSRecord(l Lookup) MTASTS {
	for _, r := range l.Records {
		tags := parseTags(r)
		if strings.EqualFold(tags["v"], "STSv1") {
			return MTASTS{Record: true, ID: tags["id"]}
		}
	}
	return MTASTS{}
}

// parseMTASTSPolicy parses the .well-known/mta-sts.txt body.
func parseMTASTSPolicy(body string, m *MTASTS) {
	for _, line := range strings.Split(body, "\n") {
		kv := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(kv) != 2 {
			continue
		}
		v := strings.TrimSpace(kv[1])
		switch strings.ToLower(strings.TrimSpace(kv[0])) {
		case "version":
			m.PolicyOK = strings.EqualFold(v, "STSv1")
		case "mode":
			m.Mode = strings.ToLower(v)
		case "max_age":
			m.MaxAge, _ = strconv.Atoi(v)
		case "mx":
			m.MXPattern = append(m.MXPattern, strings.ToLower(v))
		}
	}
	if m.Mode != "enforce" && m.Mode != "testing" && m.Mode != "none" {
		m.PolicyOK = false
	}
}

// mtaSTSCovers reports whether every MX host matches a policy mx pattern
// ("*.example.com" matches one label).
func mtaSTSCovers(patterns []string, mxHosts []string) bool {
	for _, h := range mxHosts {
		h = strings.ToLower(strings.TrimSuffix(h, "."))
		if h == "" || h == "." {
			continue
		}
		if !matchesAny(patterns, h) {
			return false
		}
	}
	return true
}

func matchesAny(patterns []string, host string) bool {
	for _, p := range patterns {
		p = strings.TrimSuffix(p, ".")
		if p == host {
			return true
		}
		if strings.HasPrefix(p, "*.") {
			if rest, ok := strings.CutPrefix(host, host[:strings.IndexByte(host+".", '.')]+"."); ok && rest == p[2:] {
				return true
			}
		}
	}
	return false
}

// policyFetcher retrieves the MTA-STS policy text; replaceable in tests.
var policyFetcher = fetchMTASTSPolicy

// fetchMTASTSPolicy GETs https://mta-sts.<domain>/.well-known/mta-sts.txt
// with full certificate verification, as RFC 8461 requires. The host is
// resolved through the tool's own validating lookups rather than the
// system resolver, so the fetch sees the same DNS as every other check.
func fetchMTASTSPolicy(ctx context.Context, domain string, timeout time.Duration, lookup lookupFn) (string, error) {
	host := "mta-sts." + domain
	addrs := append(lookup(host, "A").Addrs(), lookup(host, "AAAA").Addrs()...)
	if len(addrs) == 0 {
		return "", fmt.Errorf("%s has no address", host)
	}
	dialer := &net.Dialer{Timeout: timeout}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: tlsRoots, MinVersion: tls.VersionTLS12, ServerName: host},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, netip.AddrPortFrom(addrs[0], 443).String())
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://mta-sts."+domain+"/.well-known/mta-sts.txt", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return string(body), err
}

// checkMTASTS combines the record, the policy fetch and the MX comparison.
func checkMTASTS(ctx context.Context, domain string, rec Lookup, mxHosts []string, timeout time.Duration, lookup lookupFn) *MTASTS {
	m := parseMTASTSRecord(rec)
	m.MXPattern = []string{}
	if !m.Record {
		return &m
	}
	body, err := policyFetcher(ctx, domain, timeout, lookup)
	if err != nil {
		m.Error = "policy fetch failed: " + scrubResolver(err.Error())
		return &m
	}
	parseMTASTSPolicy(body, &m)
	if !m.PolicyOK {
		m.Error = firstNonEmpty(m.Error, "policy file is not a valid STSv1 policy")
		return &m
	}
	m.MXCovered = mtaSTSCovers(m.MXPattern, mxHosts)
	return &m
}

// resolverAddrRe matches Go's "lookup X on 10.0.0.2:53: ..." fragments.
var resolverAddrRe = regexp.MustCompile(` on [0-9a-fA-F.:\[\]]+:\d+`)

// scrubResolver removes resolver addresses from error text so that no
// finding reveals which resolver the probe used.
func scrubResolver(msg string) string {
	return resolverAddrRe.ReplaceAllString(msg, "")
}

// ----------------------------------------------------------------- Mail

// MailReport is the mail section of the report.
type MailReport struct {
	DMARC  DMARC      `json:"dmarc"`
	SPF    SPFResult  `json:"spf"`
	MX     []MXCheck  `json:"mx"`
	DKIM   DKIMResult `json:"dkim"`
	MTASTS *MTASTS    `json:"mta_sts,omitempty"`
	TLSRPT bool       `json:"tls_rpt"`
}

// mxHosts returns the exchange names of an MX lookup, sorted.
func mxHosts(mx Lookup) []string {
	var out []string
	for _, rec := range mx.Records {
		if f := strings.Fields(rec); len(f) == 2 && f[1] != "." {
			out = append(out, strings.ToLower(f[1]))
		}
	}
	sort.Strings(out)
	return out
}

// hasTLSRPT reports whether a _smtp._tls TXT with v=TLSRPTv1 exists.
func hasTLSRPT(l Lookup) bool {
	for _, r := range l.Records {
		if strings.EqualFold(parseTags(r)["v"], "TLSRPTv1") {
			return true
		}
	}
	return false
}
