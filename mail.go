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
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/DataPulse/dpdomain"
)

// lookupFn resolves name/qtype through the run's memoised delv cache.
type lookupFn func(name, qtype string) Lookup

// ---------------------------------------------------------------- DMARC

// DMARC is the parsed _dmarc policy.
type DMARC struct {
	Present         bool     `json:"present"`
	Unresolved      bool     `json:"unresolved"` // the lookup did not complete: absence was never observed
	Policy          string   `json:"policy,omitempty"`
	SubdomainPolicy string   `json:"subdomain_policy,omitempty"`
	Pct             int      `json:"pct"`
	RUA             bool     `json:"rua"`
	Records         int      `json:"records"`
	Problems        []string `json:"problems"`
}

// parseDMARC evaluates the TXT records found at _dmarc.<domain>.
func parseDMARC(l Lookup) DMARC {
	d := DMARC{Pct: 100, Problems: []string{}, Unresolved: l.Status != "" && !l.Answered()}
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
	applyDMARCTags(&d, parseTags(dmarc[0]))
	return d
}

// applyDMARCTags reads the policy tags of the record in force.
func applyDMARCTags(d *DMARC, tags map[string]string) {
	// Tag values are case-insensitive (RFC 7489 §6.3): p=Reject is reject.
	d.Policy = strings.ToLower(tags["p"])
	d.SubdomainPolicy = strings.ToLower(tags["sp"])
	d.RUA = tags["rua"] != ""
	if v, ok := tags["pct"]; ok {
		d.Pct, ok = parsePct(v)
		if !ok {
			d.Problems = append(d.Problems, "invalid pct="+v+" (not a whole number from 0 to 100)")
		}
	}
	switch d.Policy {
	case "none", "quarantine", "reject":
	case "":
		d.Problems = append(d.Problems, "missing p= tag")
	default:
		d.Problems = append(d.Problems, "unknown policy p="+d.Policy)
	}
	if d.SubdomainPolicy != "" && !validDMARCPolicy(d.SubdomainPolicy) {
		d.Problems = append(d.Problems, "unknown subdomain policy sp="+d.SubdomainPolicy)
	}
}

func validDMARCPolicy(p string) bool {
	return p == "none" || p == "quarantine" || p == "reject"
}

// parsePct reads a pct tag. A value that is not a whole number from 0 to
// 100 is reported and treated as the default, 100: that is what a
// receiver that ignores the malformed tag applies.
func parsePct(v string) (int, bool) {
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 100 {
		return 100, false
	}
	return n, true
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

// spfAnswerLimit is the UDP payload RFC 7208 §3.4 requires every SPF-related
// TXT answer to fit within; spfAnswerWarn is where headroom gets thin (one
// more verification token at the apex is typically 60-90 octets).
const (
	spfAnswerLimit = 512
	spfAnswerWarn  = 450
)

// SPFResult is the evaluation of the apex SPF policy.
type SPFResult struct {
	Records      int      `json:"records"`
	Lookups      int      `json:"lookups"`
	VoidLookups  int      `json:"void_lookups"`
	AnswerOctets int      `json:"txt_answer_octets,omitempty"` // apex TXT reply size without EDNS
	All          string   `json:"all,omitempty"`
	Includes     []string `json:"includes"`
	Problems     []string `json:"problems"`
}

// spfEvaluator walks include/redirect chains counting DNS-querying terms.
type spfEvaluator struct {
	lookup   lookupFn
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
	e := &spfEvaluator{lookup: lookup}
	if len(spf) > 1 {
		e.problem("multiple SPF records (permerror: SPF fails entirely)")
	}
	res.AnswerOctets = txt.udpAnswerOctets()
	e.apexSize(res.AnswerOctets)
	var via string
	res.All, via = e.walk(spf[0], []string{bareName(domain)})
	if res.All != "" {
		e.noteAll(res.All[:1], via)
	}
	res.Lookups, res.VoidLookups = e.lookups, e.void
	res.Includes = nonNil(e.includes)
	if e.lookups > spfLookupLimit {
		e.problem(fmt.Sprintf("%d DNS lookups exceed the limit of %d (permerror: SPF fails entirely)", e.lookups, spfLookupLimit))
	}
	if e.void > spfVoidLimit {
		e.problem(fmt.Sprintf("%d void lookups exceed the limit of %d", e.void, spfVoidLimit))
	}
	res.Problems = nonNil(e.problems)
	return res
}

func spfRecords(txt []string) []string {
	var out []string
	for _, r := range txt {
		if isSPFRecord(r) {
			out = append(out, strings.TrimSpace(r))
		}
	}
	return out
}

// problem records one problem once: a domain included twice is evaluated
// twice, but its defects are the same defects.
func (e *spfEvaluator) problem(p string) {
	if !slices.Contains(e.problems, p) {
		e.problems = append(e.problems, p)
	}
}

// isSPFRecord reports whether a TXT string is an SPF record: "v=spf1"
// followed by a space or nothing (RFC 7208 §4.5). "v=spf1include:x", which
// a record split into strings at the wrong place concatenates to, is not
// one, and receivers ignore it.
func isSPFRecord(r string) bool {
	s := strings.ToLower(strings.TrimSpace(r))
	return s == "v=spf1" || strings.HasPrefix(s, "v=spf1 ")
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

// walk evaluates one record. path is the chain of domains that led here,
// the apex first. It returns the qualified all mechanism that ends the
// evaluation ("" when none) and, when that came from a redirect target,
// the redirect that led there.
func (e *spfEvaluator) walk(record string, path []string) (all, via string) {
	terms := parseSPFTerms(record)
	own := recordAll(terms)
	all = own
	hasRedirect := false
	for _, t := range terms {
		if t.name != "redirect" || !t.modifier {
			e.mechanism(t, path)
			continue
		}
		hasRedirect = true
		// RFC 7208 §6.1: a record with an all mechanism ignores its redirect.
		if own == "" {
			all, via = e.redirect(t, path)
		}
	}
	if len(path) == 1 && own == "" && !hasRedirect {
		e.problem("record has no all mechanism or redirect (default neutral)")
	}
	return all, via
}

// redirect follows a redirect modifier: the target's evaluation replaces
// the record's, so its all is the record's.
func (e *spfEvaluator) redirect(t spfTerm, path []string) (all, via string) {
	target := spfTarget(t)
	e.lookups++
	if a := e.descend(target, path); a != "" {
		return a, "redirect=" + target
	}
	return "", ""
}

// mechanism accounts for one term other than redirect.
func (e *spfEvaluator) mechanism(t spfTerm, path []string) {
	switch {
	case t.name == "include" && !t.modifier:
		// An include whose record passes everyone matches every sender,
		// so the including record authorises them all.
		target := spfTarget(t)
		e.lookups++
		if e.descend(target, path) == "+all" {
			e.noteAll("+", "include:"+target)
		}
	case t.name == "all" && !t.modifier:
	default:
		e.term(t, path[len(path)-1])
	}
}

// recordAll is the qualified all mechanism of a record, "" when it has
// none.
func recordAll(terms []spfTerm) string {
	for _, t := range terms {
		if t.name == "all" && !t.modifier {
			return t.qualifier + "all"
		}
	}
	return ""
}

func spfTarget(t spfTerm) string {
	return strings.TrimPrefix(t.arg, ":")
}

// term accounts for a mechanism that does not reference another record.
func (e *spfEvaluator) term(t spfTerm, domain string) {
	switch {
	case t.name == "a", t.name == "mx", t.name == "exists":
		e.lookups++
	case t.name == "ptr":
		e.lookups++
		e.problem("ptr mechanism is deprecated (RFC 7208 §5.5)")
	case t.name == "ip4", t.name == "ip6", t.modifier:
	default:
		e.problem("unknown mechanism " + t.name + " in " + domain)
	}
}

// noteAll reports an all that leaves senders unprotected. via names the
// redirect or include it was reached through, "" when the apex record
// carries it.
func (e *spfEvaluator) noteAll(qualifier, via string) {
	suffix := ""
	if via != "" {
		suffix = ", reached through " + via
	}
	switch qualifier {
	case "+":
		e.problem("+all authorises every sender (no protection)" + suffix)
	case "?":
		e.problem("?all is neutral (no protection)" + suffix)
	}
}

// apexSize applies RFC 7208 §3.4 to the apex TXT answer. Every TXT record
// at the name counts, not just the SPF one, because a TXT query returns
// them all.
func (e *spfEvaluator) apexSize(octets int) {
	switch {
	case octets > spfAnswerLimit:
		e.problem(fmt.Sprintf("apex TXT answer is %d octets, over the %d-octet UDP limit (RFC 7208 §3.4): resolvers without EDNS get a truncated reply and must retry over TCP", octets, spfAnswerLimit))
	case octets > spfAnswerWarn:
		e.problem(fmt.Sprintf("apex TXT answer is %d octets, close to the %d-octet UDP limit (RFC 7208 §3.4): one more TXT record may push it over", octets, spfAnswerLimit))
	}
}

// includeSize applies the same limit to an included domain's TXT answer;
// only an outright breach is reported since the record is not the
// domain owner's to trim.
func (e *spfEvaluator) includeSize(target string, l Lookup) {
	if octets := l.udpAnswerOctets(); octets > spfAnswerLimit {
		e.problem(fmt.Sprintf("include:%s TXT answer is %d octets, over the %d-octet UDP limit (RFC 7208 §3.4)", target, octets, spfAnswerLimit))
	}
}

// descend fetches an included or redirected-to domain's SPF and walks it,
// returning the all its evaluation ends with. Every evaluation counts:
// RFC 7208 §4.6.4 charges a domain included twice twice, so only the
// current path is remembered, to stop a loop. Macro targets cannot be
// expanded and count as one lookup only.
func (e *spfEvaluator) descend(target string, path []string) string {
	if strings.Contains(target, "%") || target == "" {
		return ""
	}
	n, err := dnsName(target)
	if err != nil {
		e.problem(fmt.Sprintf("include:%s is not a valid domain name (%v)", target, err))
		return ""
	}
	target = n.ASCII
	if slices.Contains(path, target) {
		e.problem(fmt.Sprintf("include loop %s -> %s (permerror: SPF fails entirely)", strings.Join(path, " -> "), target))
		return ""
	}
	e.noteInclude(target)
	if e.lookups > spfLookupLimit*3 || len(path) > 20 {
		return "" // pathological tree; the limit finding already fires
	}
	l := e.lookup(target, "TXT")
	recs := spfRecords(l.Records)
	switch {
	case !l.Answered():
		// Neither void nor missing: the question went unanswered.
		e.problem("include:" + target + " could not be checked: its TXT lookup did not complete")
		return ""
	case !l.HasRecords():
		e.void++
		e.problem("include:" + target + " has no SPF record")
		return ""
	case len(recs) == 0:
		e.problem("include:" + target + " has no SPF record")
		return ""
	}
	e.includeSize(target, l)
	all, _ := e.walk(recs[0], append(slices.Clip(path), target))
	return all
}

// noteInclude lists a target once, however often it is evaluated.
func (e *spfEvaluator) noteInclude(target string) {
	if !slices.Contains(e.includes, target) {
		e.includes = append(e.includes, target)
	}
}

// ------------------------------------------------------------------- MX

// MXCheck is the sanity result for one MX exchange. Unresolved marks a
// target whose address lookup never completed, which is a gap in the check
// rather than a fault in the domain.
type MXCheck struct {
	Host       string   `json:"host"`
	Pref       int      `json:"preference"`
	Addresses  int      `json:"addresses"`
	CNAME      bool     `json:"cname"`
	IPLiteral  bool     `json:"ip_literal"`
	Unresolved bool     `json:"unresolved"`
	Problems   []string `json:"problems"`
}

// mxUnresolvedProblem is the text recorded when neither address lookup
// reached a definite answer. It is reported as a warning, not an error.
const mxUnresolvedProblem = "MX target lookup did not complete, so the target was not checked"

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
	n, err := hostOrIP(c.Host)
	if err != nil {
		c.Problems = append(c.Problems, "MX target is not a valid hostname: "+err.Error())
		return c
	}
	if n.Kind == dpdomain.KindIP {
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
	case !a.Answered() || !aaaa.Answered():
		// One family unanswered is enough: "no address" would then be an
		// assertion about an answer we never received.
		c.Unresolved = true
		c.Problems = append(c.Problems, mxUnresolvedProblem)
	case a.Status == StatusNXDomain:
		c.Problems = append(c.Problems, "MX target does not exist")
	case c.Addresses == 0:
		c.Problems = append(c.Problems, "MX target has no address")
	}
	return c
}

// ----------------------------------------------------------------- DKIM

// dkimSelectors are the selectors probed; DKIM cannot be enumerated, so
// these cover the common providers (Microsoft 365, Google, generic).
var dkimSelectors = []string{"google", "selector1", "selector2", "default", "k1", "s1", "mail", "dkim"}

// DKIMResult lists selectors that publish a key. Wildcard says the zone
// answers every selector, which makes the found list meaningless: the
// names were never evidence of anything a sender configured.
type DKIMResult struct {
	Wildcard       bool     `json:"wildcard"`
	SelectorsFound []string `json:"selectors_found"`
	Revoked        []string `json:"revoked"`
}

// probeDKIM looks every selector up in parallel (a dead resolver would
// otherwise cost one timeout per selector, sequentially), alongside a
// random selector nobody would configure.
//
// The random one is the control. Selectors cannot be enumerated, so the
// probe is a guess, and a zone that wildcards _domainkey answers every
// guess: example.com returns a valid revoked key for any name, which
// reported all eight selectors as found and revoked. Checking that the
// record parses as DKIM does not help there, only that it is answered for
// a name chosen at random.
func probeDKIM(domain string, lookup lookupFn) DKIMResult {
	res := DKIMResult{SelectorsFound: []string{}, Revoked: []string{}}
	answers := make([]Lookup, len(dkimSelectors))
	var control Lookup
	tasks := []func(){func() { control = lookup(randomLabel()+"._domainkey."+domain, "TXT") }}
	for i, sel := range dkimSelectors {
		tasks = append(tasks, func() { answers[i] = lookup(sel+"._domainkey."+domain, "TXT") })
	}
	parallel(tasks...)
	if _, _, ok := dkimKey(control); ok {
		// Every selector would "answer", so none of them is a finding.
		res.Wildcard = true
		return res
	}
	for i, sel := range dkimSelectors {
		revoked, _, ok := dkimKey(answers[i])
		if !ok {
			continue
		}
		res.SelectorsFound = append(res.SelectorsFound, sel)
		if revoked {
			res.Revoked = append(res.Revoked, sel)
		}
	}
	return res
}

// dkimKey reports whether a lookup carries a DKIM key, and whether that key
// is revoked (published with an empty p= tag).
func dkimKey(l Lookup) (revoked bool, record string, ok bool) {
	for _, r := range l.Records {
		tags := parseTags(r)
		p, hasP := tags["p"]
		if !hasP && !strings.HasPrefix(strings.ToLower(r), "v=dkim1") {
			continue
		}
		return hasP && p == "", r, true
	}
	return false, "", false
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
		if h == "" || h == "." {
			continue
		}
		n, err := dnsName(h)
		if err != nil || !matchesAny(patterns, n.ASCII) {
			return false
		}
	}
	return true
}

// matchesAny reports whether host equals a pattern or, for a "*." pattern,
// is exactly one label below it. A pattern that is not a name never matches.
func matchesAny(patterns []string, host string) bool {
	for _, p := range patterns {
		wild := strings.HasPrefix(p, "*.")
		n, err := dnsName(strings.TrimPrefix(p, "*."))
		if err != nil {
			continue
		}
		if !wild && n.ASCII == host {
			return true
		}
		if wild {
			if rest, ok := strings.CutPrefix(host, host[:strings.IndexByte(host+".", '.')]+"."); ok && rest == n.ASCII {
				return true
			}
		}
	}
	return false
}

// policyFetcher retrieves the MTA-STS policy text; replaceable in tests.
var policyFetcher = fetchMTASTSPolicy

// mtaSTSDialer connects the policy fetch; tests point it at local servers.
var mtaSTSDialer dialer = &netDialer{}

// fetchMTASTSPolicy GETs https://mta-sts.<domain>/.well-known/mta-sts.txt
// with full certificate verification, as RFC 8461 requires. The host is
// resolved through the tool's own validating lookups rather than the
// system resolver, so the fetch sees the same DNS as every other check.
// Every public address is tried at once and the first to connect serves
// the fetch: a host with one dead address of several still has a policy.
// Reserved addresses are never contacted, as for the web probes.
func fetchMTASTSPolicy(ctx context.Context, domain string, timeout time.Duration, lookup lookupFn) (string, error) {
	host := "mta-sts." + domain
	all := append(lookup(host, "A").Addrs(), lookup(host, "AAAA").Addrs()...)
	addrs, reserved := splitReserved(all)
	switch {
	case len(addrs) == 0 && len(reserved) > 0:
		return "", fmt.Errorf("%s has only reserved addresses (%s)", host, strings.Join(reserved, ", "))
	case len(addrs) == 0:
		return "", fmt.Errorf("%s has no address", host)
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: tlsRoots, MinVersion: tls.VersionTLS12, ServerName: host},
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialFirst(ctx, mtaSTSDialer, addrs, 443)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/.well-known/mta-sts.txt", nil)
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

// dialFirst connects to every address at once and returns the first
// connection made, closing any that complete after it. It fails only when
// every address does, with the last error.
func dialFirst(ctx context.Context, d dialer, addrs []netip.Addr, port uint16) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result, len(addrs))
	for _, ip := range addrs {
		go func() {
			c, err := d.DialContext(ctx, tcpNetwork(ip), netip.AddrPortFrom(ip, port).String())
			results <- result{c, err}
		}()
	}
	var won net.Conn
	var lastErr error
	for range addrs {
		r := <-results
		switch {
		case r.err != nil:
			lastErr = r.err
		case won == nil:
			won = r.conn
			cancel() // the rest may stop trying
		default:
			_ = r.conn.Close() // a later winner is not needed
		}
	}
	if won != nil {
		return won, nil
	}
	return nil, lastErr
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
		m.Error = "policy fetch failed: " + scrubProbeError(err.Error())
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

// netOpRe matches the socket preamble Go puts on network errors,
// "read tcp4 10.0.0.5:46962->93.184.216.34:443: ".
var netOpRe = regexp.MustCompile(`\b(?:read|write|dial|readfrom|writeto|accept|set)\s+(?:tcp|udp|ip)[46]?\s+\S+:\s+`)

// scrubProbeError reduces a network error to its operational cause. The
// preamble names our own source address and a fresh ephemeral port on
// every run, which publishes the vantage point and makes otherwise
// identical findings differ from run to run; the finding already names
// the address that was probed.
func scrubProbeError(msg string) string {
	return strings.TrimSpace(netOpRe.ReplaceAllString(scrubResolver(msg), ""))
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
