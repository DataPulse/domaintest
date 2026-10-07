package main

import (
	"bufio"
	"context"
	"errors"
	"maps"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// netDialer is the production dialer.
type netDialer struct{ net.Dialer }

// lookupCache memoises DNS lookups for one run so that SPF includes, MX
// targets and NS names are fetched once however many checks need them.
type lookupCache struct {
	ctx  context.Context // the current phase's context; run() advances it
	r    Runner
	cfg  config
	mu   sync.Mutex
	done map[string]Lookup
}

// setContext binds later lookups to a new phase context.
func (c *lookupCache) setContext(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ctx = ctx
}

func newLookupCache(ctx context.Context, cfg config, r Runner) *lookupCache {
	return &lookupCache{ctx: ctx, r: r, cfg: cfg, done: map[string]Lookup{}}
}

// get returns the memoised lookup, running dog on first use. Each miss
// gets its own timeout so that lookups requested after the DNS phase
// (nameserver names learned from the parent, for instance) still have a
// budget instead of inheriting an expired deadline.
func (c *lookupCache) get(name, qtype string) Lookup {
	n, err := dnsName(name)
	if err != nil {
		// A target the resolver handed us that is not a DNS name (rare, but
		// an NS or MX record can carry anything) is a finding, not a query.
		return Lookup{Name: name, Type: qtype, Status: StatusFailure, Error: "not a valid DNS name: " + err.Error()}
	}
	name = n.ASCII
	key := name + "/" + qtype
	c.mu.Lock()
	l, ok := c.done[key]
	base := c.ctx
	c.mu.Unlock()
	if ok {
		return l
	}
	if base.Err() != nil {
		// The phase budget is already spent (a first-wave lookup hung). Do
		// not run, and do not cache: a later phase retries with its own
		// budget instead of inheriting a poisoned timeout.
		return Lookup{Name: name, Type: qtype, Status: StatusTimeout, Error: "dns lookup timed out"}
	}
	lctx, cancel := context.WithTimeout(base, c.cfg.timeout())
	defer cancel()
	l = dnsLookup(lctx, c.r, c.cfg.DogPath, c.cfg.Resolver.dogServer(), c.cfg.TimeoutSec, name, qtype)
	c.mu.Lock()
	c.done[key] = l
	c.mu.Unlock()
	return l
}

// dnsResults collects every DNS lookup for one run.
type dnsResults struct {
	apex   map[string]Lookup
	www    map[string]Lookup
	ds     Lookup
	dnskey Lookup
	reach  map[string]string
	// reachTrust is the trust of the root NS answer per family: whether
	// the resolver validates at all.
	reachTrust map[string]Trust
	dmarc      Lookup
	mtaSTS     Lookup
	tlsRPT     Lookup
	wild       []wildProbe // the random-name probes, in the order issued
	wildSkip   string      // why no probe was issued: an answer already in hand
	caaApex    Lookup
	caaWWW     Lookup
	tlsaApex   Lookup
	tlsaWWW    Lookup
	cache      *lookupCache
}

// run performs every check for cfg and returns the finished report.
func run(ctx context.Context, cfg config, r Runner, d dialer) *Report {
	start := time.Now()
	rep := newReport(cfg)
	rep.Timestamp = reportTimestamp(start)

	// The DNS tools are capped together; quicprobe is left alone because it
	// waits on the network rather than competing for CPU, and queueing it
	// behind DNS work would only cost QUIC answers.
	dnsRunner := limitRunner(r, cfg.DNSConcurrency)

	// A name reserved by RFC is not in the global DNS, so there is no
	// delegation to trace; classifyZone records why.
	reserved := reservedName(cfg.Domain) != ""
	var dns dnsResults
	web := &earlyWeb{}
	defer web.stop()
	parallel(
		func() {
			if !reserved {
				rep.Delegation = runTrace(ctx, cfg, dnsRunner)
			}
		},
		func() {
			dns = gatherDNS(ctx, cfg, dnsRunner, r, func(first dnsResults) {
				// A reserved name's addresses are the resolver's local
				// answers (localhost is 127.0.0.1 and ::1), not the
				// domain's, so they are never probed.
				if !reserved {
					web.start(ctx, cfg, r, d, first, rep)
				}
			})
		},
	)
	classifyDNS(ctx, rep, cfg, &dns, dnsRunner)

	// When the delegated servers were silent to the trace, ask each of them
	// before anything else. If none answers for the zone, nothing else can
	// work, and the report is that one fact. The audit has its own budget:
	// silent servers spend all of it, and the probes after it need theirs.
	audited := false
	if delegationSilent(rep.Delegation, dns.apex["NS"]) {
		rep.Nameservers, audited = auditFirst(ctx, cfg, dnsRunner, dns, rep), true
		if zoneUnreachable(rep) {
			web.stop() // nothing is reported about a zone no server answers for
			return finishReport(ctx, rep, start)
		}
	}
	probeCtx, cancel := context.WithTimeout(ctx, probeBudget(cfg))
	defer cancel()
	dns.cache.setContext(probeCtx) // late lookups share the probe budget
	parallel(
		func() { rep.Web = web.wait() },
		func() {
			if !audited {
				rep.Nameservers = auditNameservers(probeCtx, cfg, dnsRunner, dns, rep)
			}
		},
		func() { rep.Mail = assessMail(probeCtx, cfg, dns, noMailPossible(rep, dns)) },
		func() {
			p := checkPreload(probeCtx, cfg)
			rep.HSTSPreload, rep.HSTSPreloadCoveredBy, rep.HSTSPreloadPolicy, rep.HSTSPreloadError = p.status, p.coveredBy, p.policy, p.problem
			rep.HSTSPreloadIncludeSubdomains = p.includeSubdomains
		},
	)
	rep.Wildcard = wildcardSection(dns, rep.Web)
	rep.CAA, rep.TLSA = assessCertPolicies(dns, rep)
	return finishReport(ctx, rep, start)
}

// classifyDNS records the lookups and judges the zone. Every trust level
// is the resolver's AD bit, so a resolver that does not validate has its
// silence withheld rather than read as every zone being unsigned.
func classifyDNS(ctx context.Context, rep *Report, cfg config, dns *dnsResults, r Runner) {
	validates := resolverValidates(dns.reachTrust)
	blind := validates != nil && !*validates
	if blind {
		dns.dropTrust()
	}
	rep.DNS = DNSSection{Apex: dns.apex, WWW: dns.www, ResolverReachable: dns.reach, ResolverValidates: validates}
	classifyZone(ctx, rep, cfg, *dns, r)
	if blind && rep.ReservedName == "" {
		rep.DNSSEC = DNSSECReport{State: DNSSECUnknown, DS: dns.ds.HasRecords(), DNSKEY: dns.dnskey.HasRecords(),
			Detail: "the resolver does not validate DNSSEC (it did not authenticate the signed root zone), so no DNSSEC verdict is possible"}
	}
}

// earlyWeb runs the web probes alongside the second DNS wave. They need only
// the apex and www addresses, which the first wave settles, and waiting for
// the dependent lookups, the delegation trace and the DNSSEC classification
// left every TCP, TLS and QUIC handshake idle for that whole time. The
// probes keep the budget they always had, counted from their own start.
// While each lookup was a delv process (until 2026-10-07) this made a
// CPU-bound host worse: the probes competed with the second wave for CPU.
type earlyWeb struct {
	done   chan struct{}
	cancel context.CancelFunc
	result WebSection
}

// start launches probeWeb on the first wave's answers. It gets its own copy
// of the apex and www maps, which the classification may still rewrite
// (dropTrust); rep is only written at ReservedAddresses, which nothing else
// touches before the report is finished.
func (w *earlyWeb) start(ctx context.Context, cfg config, r Runner, d dialer, first dnsResults, rep *Report) {
	first.apex, first.www = maps.Clone(first.apex), maps.Clone(first.www)
	wctx, cancel := context.WithTimeout(ctx, probeBudget(cfg))
	w.done, w.cancel = make(chan struct{}), cancel
	go func() {
		defer close(w.done)
		w.result = probeWeb(wctx, cfg, r, d, first, rep)
	}()
}

// wait returns the probes' result once they finish; an empty section when
// they never started (a reserved name, or a DNS phase that ended before its
// first wave did).
func (w *earlyWeb) wait() WebSection {
	if w.done == nil {
		return WebSection{}
	}
	<-w.done
	w.cancel()
	return w.result
}

// stop cancels the probes and waits for them to return, so no goroutine
// outlives the run. It is safe to call more than once.
func (w *earlyWeb) stop() {
	if w.done == nil {
		return
	}
	w.cancel()
	<-w.done
}

// auditFirst runs the nameserver audit ahead of the probes, under a budget
// of its own.
func auditFirst(ctx context.Context, cfg config, r Runner, dns dnsResults, rep *Report) *NSReport {
	actx, cancel := context.WithTimeout(ctx, probeBudget(cfg))
	defer cancel()
	dns.cache.setContext(actx)
	return auditNameservers(actx, cfg, r, dns, rep)
}

// finishReport records whether the run deadline cut the run short, builds
// the findings and stamps the elapsed time.
func finishReport(ctx context.Context, rep *Report, start time.Time) *Report {
	rep.DeadlineReached = errors.Is(ctx.Err(), context.DeadlineExceeded)
	buildFindings(rep)
	hoistCertNames(rep)
	rep.ElapsedMs = time.Since(start).Milliseconds()
	return rep
}

// reportTimestamp formats the probe's start for the report header: UTC,
// RFC 3339, whole seconds.
func reportTimestamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

func newReport(cfg config) *Report {
	return &Report{
		Domain:         cfg.Domain,
		Version:        buildVersion(),
		UnicodeDomain:  cfg.UnicodeDomain,
		Resolver:       cfg.Resolver.String(),
		Families:       cfg.Families,
		TimeoutSec:     cfg.TimeoutSec,
		TCPTimeoutSec:  cfg.TCPTimeoutSec,
		QuicTimeoutSec: cfg.QuicTimeoutSec,
		MaxTimeSec:     cfg.MaxTimeSec,
		DNSConcurrency: cfg.DNSConcurrency,
		RedirectLog:    cfg.RedirectLog,
	}
}

// probeBudget bounds the whole probe phase: connect, TLS, HTTP and one
// redirect chain, plus QUIC.
func probeBudget(cfg config) time.Duration {
	b := 3 * cfg.tcpTimeout()
	if q := time.Duration(cfg.QuicTimeoutSec)*time.Second + time.Second; q > b {
		b = q
	}
	return b + time.Second
}

// classifyZone fills the not-a-zone and DNSSEC verdicts.
func classifyZone(ctx context.Context, rep *Report, cfg config, dns dnsResults, r Runner) {
	rep.PublicSuffix = !registrableDomain(cfg.Domain) && isPublicSuffix(cfg.Domain)
	if rep.ReservedName = reservedName(cfg.Domain); rep.ReservedName != "" {
		// The name is not in the global DNS, so neither a trust chain nor
		// a delegation can be judged. Whatever the resolver answered says
		// something about the resolver, not about the domain.
		rep.DNSSEC = DNSSECReport{State: DNSSECUnknown, Detail: "name reserved by " + rep.ReservedName + ", outside the global DNS"}
		rep.Delegation = Delegation{Status: DelegationReservedName, Error: "name reserved by " + rep.ReservedName + ", outside the global DNS: not traced"}
		return
	}
	if rep.NotAZone, rep.EnclosingZone = detectNotAZone(cfg.Domain, dns, rep.Delegation); rep.NotAZone {
		rep.DNSSEC = classifyByTrust(dns.apex)
		rep.Delegation = Delegation{Status: DelegationNotAZone, Error: "name is a host inside " + firstNonEmpty(rep.EnclosingZone, "another zone")}
		return
	}
	bctx, cancel := context.WithTimeout(ctx, cfg.timeout())
	defer cancel()
	rep.DNSSEC = classifyDNSSEC(dns.ds, dns.dnskey, dns.apex,
		newBogusProbe(bctx, r, cfg.DigPath, cfg.Resolver, cfg.TimeoutSec))
}

// detectNotAZone reports whether the name is a host inside a zone rather
// than a zone apex. A real apex always has an NS RRset, so the NS query
// answering NXRRSET is the primary signal; it is confirmed by either a
// positive answer of another type (A, AAAA, MX or TXT: the name exists) or
// a negative answer whose SOA is owned by a name above this one (the
// resolver consulted an enclosing zone). A name the parent zone actually
// delegates is a zone whatever its apex looks like, so any delegation
// found by the trace overrides the heuristic. The enclosing zone is
// reported when a SOA revealed it.
func detectNotAZone(domain string, dns dnsResults, deleg Delegation) (bool, string) {
	if len(deleg.ParentNS) > 0 {
		return false, "" // the parent delegates it, so it is a zone
	}
	// A name with a CNAME cannot be a zone apex: RFC 1034 forbids a CNAME
	// coexisting with other data, and an apex must carry NS and SOA. The
	// NS query follows the CNAME, so any records that come back describe
	// the target's zone. Without this, gist.github.com looks like a zone
	// served by github.com's nameservers, and auditing them for a zone
	// they do not have produces a REFUSED from every one.
	if len(dns.apex["NS"].CNAME) > 0 {
		return true, enclosingZone(domain, dns)
	}
	if dns.apex["NS"].Status != StatusNXRRSet {
		return false, ""
	}
	zone := enclosingZone(domain, dns)
	if zone == "" && !anyPositive(dns.apex) {
		return false, ""
	}
	return true, zone
}

// enclosingZone returns the owner of a SOA seen in a negative answer when
// that owner lies above the name, or "".
func enclosingZone(domain string, dns dnsResults) string {
	fqdn := domain + "."
	for _, t := range apexTypes {
		owner := dns.apex[t].SOAOwner()
		if owner != "" && owner != fqdn && strings.HasSuffix(fqdn, "."+owner) {
			return bareName(owner)
		}
	}
	return ""
}

func anyPositive(apex map[string]Lookup) bool {
	for _, t := range apexTypes {
		if t != "NS" && apex[t].HasRecords() {
			return true
		}
	}
	return false
}

// parallel runs fns concurrently and waits for all of them.
func parallel(fns ...func()) {
	var wg sync.WaitGroup
	for _, fn := range fns {
		wg.Add(1)
		go func(fn func()) {
			defer wg.Done()
			fn()
		}(fn)
	}
	wg.Wait()
}

// runTrace runs the delegation trace under twice the configured timeout:
// it is a chain of about five sequential queries, each already limited by
// dig's own +time.
func runTrace(ctx context.Context, cfg config, r Runner) Delegation {
	tctx, cancel := context.WithTimeout(ctx, 2*cfg.timeout())
	defer cancel()
	return traceDelegation(tctx, r, cfg.DigPath, traceFamily(cfg), cfg.TimeoutSec, cfg.Domain)
}

func traceFamily(cfg config) string {
	if !cfg.wantsFamily(familyIPv4) {
		return familyIPv6
	}
	return familyIPv4
}

// gatherDNS runs all DNS lookups in parallel in two waves: first the fixed
// set, then the lookups that depend on those answers (SPF includes, MX
// targets, DKIM selectors, NS names). Each wave gets its own budget.
// afterFirst, when set, is called with the first wave's results before the
// second wave starts.
//
// gatherDNS runs the record lookups through the capped runner. The
// reachability probe uses the uncapped one: it measures our own resolver,
// so letting the target's hung lookups starve it would turn a slow domain
// into a false claim that the resolver is down.
func gatherDNS(ctx context.Context, cfg config, r, reachRunner Runner, afterFirst func(dnsResults)) dnsResults {
	dctx, cancel := context.WithTimeout(ctx, cfg.timeout())
	defer cancel()
	res := dnsResults{
		apex:       make(map[string]Lookup, len(apexTypes)),
		www:        make(map[string]Lookup, len(wwwTypes)),
		reach:      make(map[string]string, len(cfg.Families)),
		reachTrust: make(map[string]Trust, len(cfg.Families)),
		cache:      newLookupCache(dctx, cfg, r),
	}
	var mu sync.Mutex
	get := res.cache.get
	tasks := fixedLookups(&res, &mu, cfg, get)
	for _, fam := range cfg.Families {
		tasks = append(tasks, func() {
			status, trust := checkReachability(dctx, cfg, reachRunner, fam)
			store(&mu, res.reach, fam, status)
			store(&mu, res.reachTrust, fam, trust)
		})
	}
	parallel(tasks...)
	if afterFirst != nil {
		// The apex and www maps are complete; the second wave only reads
		// them, and the hook takes its own copy before anything rewrites them.
		afterFirst(res)
	}

	// The second wave gets its own allowance rather than the remainder of
	// the first. Sharing one budget charged the first wave's queueing to
	// the second, so under a concurrency cap every MX target and
	// nameserver address timed out at once and was then reported as
	// missing. The waves are sequential, so the run's DNS phase is bounded
	// by twice the timeout.
	wctx, wcancel := context.WithTimeout(ctx, cfg.timeout())
	defer wcancel()
	res.cache.setContext(wctx)
	parallel(dependentLookups(&res, cfg, get)...)
	return res
}

// fixedLookups are the lookups known before any answer arrives.
func fixedLookups(res *dnsResults, mu *sync.Mutex, cfg config, get lookupFn) []func() {
	d, www := cfg.Domain, "www."+cfg.Domain
	set := func(dst *Lookup, name, qtype string) func() {
		return func() {
			l := get(name, qtype)
			mu.Lock()
			*dst = l
			mu.Unlock()
		}
	}
	var tasks []func()
	for _, t := range apexTypes {
		tasks = append(tasks, func() { store(mu, res.apex, t, get(d, t)) })
	}
	for _, t := range wwwTypes {
		tasks = append(tasks, func() { store(mu, res.www, t, get(www, t)) })
	}
	tasks = append(tasks,
		set(&res.ds, d, "DS"), set(&res.dnskey, d, "DNSKEY"),
		set(&res.dmarc, "_dmarc."+d, "TXT"), set(&res.mtaSTS, "_mta-sts."+d, "TXT"), set(&res.tlsRPT, "_smtp._tls."+d, "TXT"),
		set(&res.caaApex, d, "CAA"), set(&res.caaWWW, www, "CAA"),
		set(&res.tlsaApex, "_443._tcp."+d, "TLSA"), set(&res.tlsaWWW, "_443._tcp."+www, "TLSA"),
	)
	return tasks
}

// dependentLookups warm the cache for names learned from the first wave so
// that the evaluators run against memoised answers.
func dependentLookups(res *dnsResults, cfg config, get lookupFn) []func() {
	var tasks []func()
	if !registrySuffix(cfg.Domain) {
		for _, sel := range dkimSelectors {
			name := sel + "._domainkey." + cfg.Domain
			tasks = append(tasks, func() { get(name, "TXT") })
		}
	}
	for _, host := range mxHosts(res.apex["MX"]) {
		tasks = append(tasks, func() { get(host, "A") }, func() { get(host, "AAAA") })
	}
	for _, ns := range nsNames(res.apex["NS"]) {
		tasks = append(tasks, func() { get(ns, "A") }, func() { get(ns, "AAAA") })
	}
	// The policy fetch resolves mta-sts.<domain> late in the probe phase,
	// A then AAAA, where the two lookups were the run's last serial step.
	if parseMTASTSRecord(res.mtaSTS).Record {
		host := "mta-sts." + cfg.Domain
		tasks = append(tasks, func() { get(host, "A") }, func() { get(host, "AAAA") })
	}
	tasks = append(tasks,
		func() { evaluateSPF(cfg.Domain, res.apex["TXT"], get) },
		func() { probeWildcard(res, cfg, get) },
	)
	return tasks
}

// probeWildcard asks whether the zone answers names that cannot exist. It
// belongs in the second wave because its cheapest answer comes from www,
// which the first wave looks up, and because a wildcard needs three
// agreeing probes: one sample is not evidence.
//
// The stages stop at the first definite answer, so the common case where no
// wildcard exists costs the same two queries as the single probe it
// replaces, and a domain whose www is NXDOMAIN costs none at all.
func probeWildcard(res *dnsResults, cfg config, get lookupFn) {
	if res.wildSkip = wildcardSkipReason(res.apex, res.www); res.wildSkip != "" {
		return
	}
	labels := wildcardLabels(wildcardProbeCount)
	res.wild = []wildProbe{runWildProbe(labels[0], cfg.Domain, get)}
	if classifyProbe(res.wild[0]) != probeAnswered {
		// Denied settles it, and a probe that never answered will not be
		// helped by asking two more names of the same resolver.
		return
	}
	rest := make([]wildProbe, len(labels)-1)
	var tasks []func()
	for i, label := range labels[1:] {
		tasks = append(tasks, func() { rest[i] = runWildProbe(label, cfg.Domain, get) })
	}
	parallel(tasks...)
	res.wild = append(res.wild, rest...)
}

// runWildProbe looks up one random name over both address types at once.
func runWildProbe(label, domain string, get lookupFn) wildProbe {
	p := wildProbe{label: label}
	name := label + "." + domain
	parallel(
		func() { p.a = get(name, "A") },
		func() { p.aaaa = get(name, "AAAA") },
	)
	return p
}

func store[V any](mu *sync.Mutex, m map[string]V, k string, v V) {
	mu.Lock()
	defer mu.Unlock()
	m[k] = v
}

// reachabilityQuery is the name queried to test the resolver: the root NS
// set, which every resolver can answer regardless of the domain's health.
const reachabilityQuery = "."

// checkReachability asks the resolver for the root NS set over a single
// transport family, and returns the answer's trust too: the root zone is
// signed, so a validating resolver always authenticates it. It is skipped
// when the resolver has no address of that family.
func checkReachability(ctx context.Context, cfg config, r Runner, family string) (string, Trust) {
	if !resolverSupports(cfg, family) {
		return ReachSkipped + ": resolver has no " + family + " address", ""
	}
	server, ok := serverForFamily(ctx, cfg, family)
	if !ok {
		return ReachNo, ""
	}
	l := dnsLookup(ctx, r, cfg.DogPath, server, cfg.TimeoutSec, reachabilityQuery, "NS")
	if l.Answered() {
		return ReachYes, l.Trust
	}
	return ReachNo, ""
}

// serverForFamily names the resolver by an address of one family, since
// dog has no switch to force the transport: a literal @server as given, a
// hostname @server through its address of that family, and the system
// resolver through the first resolv.conf nameserver of that family.
func serverForFamily(ctx context.Context, cfg config, family string) (string, bool) {
	res := cfg.Resolver
	if res.Host == "" {
		addr, ok := resolvConfServer(resolvConfPath, family)
		return addr, ok
	}
	if cfg.dnsFamily != "" {
		return res.dogServer(), true
	}
	network := map[string]string{familyIPv4: "ip4", familyIPv6: "ip6"}[family]
	ips, err := net.DefaultResolver.LookupNetIP(ctx, network, res.Host)
	if err != nil || len(ips) == 0 {
		return "", false
	}
	port := res.Port
	if port == 0 {
		port = 53
	}
	return net.JoinHostPort(ips[0].Unmap().String(), strconv.Itoa(port)), true
}

// resolvConfServer returns the first nameserver of family in a resolv.conf
// file. A scoped link-local address (fe80::1%eth0) is skipped: dog cannot
// name the interface.
func resolvConfServer(path, family string) (string, bool) {
	for _, ns := range resolvConfNameservers(path) {
		if !strings.Contains(ns, "%") && serverFamily(ns) == family {
			return ns, true
		}
	}
	return "", false
}

// resolverValidates reads whether the resolver validates DNSSEC from the
// root NS answers: nil when no family answered.
func resolverValidates(reachTrust map[string]Trust) *bool {
	var seen, validated bool
	for _, t := range reachTrust {
		if t == "" {
			continue
		}
		seen = true
		validated = validated || t == TrustSecure
	}
	if !seen {
		return nil
	}
	return &validated
}

// dropTrust clears every lookup's trust. A resolver that does not validate
// never sets AD, so its silence says nothing about a zone's signatures.
func (d *dnsResults) dropTrust() {
	for _, m := range []map[string]Lookup{d.apex, d.www} {
		for k, l := range m {
			l.Trust = ""
			m[k] = l
		}
	}
	for _, l := range []*Lookup{&d.ds, &d.dnskey, &d.dmarc, &d.mtaSTS, &d.tlsRPT, &d.caaApex, &d.caaWWW, &d.tlsaApex, &d.tlsaWWW} {
		l.Trust = ""
	}
	for i := range d.wild {
		d.wild[i].a.Trust, d.wild[i].aaaa.Trust = "", ""
	}
	d.cache.dropTrust()
}

// dropTrust clears the trust of every memoised lookup.
func (c *lookupCache) dropTrust() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, l := range c.done {
		l.Trust = ""
		c.done[k] = l
	}
}

// resolverSupports reports whether DNS over family makes sense: a literal
// @server pins the family; the system resolver is checked against the
// nameserver lines of /etc/resolv.conf; a hostname server is assumed to.
func resolverSupports(cfg config, family string) bool {
	if cfg.dnsFamily != "" {
		return cfg.dnsFamily == family
	}
	if cfg.Resolver.Host != "" {
		return true
	}
	fams := resolvConfFamilies(resolvConfPath)
	return len(fams) == 0 || fams[family]
}

var resolvConfPath = "/etc/resolv.conf"

// resolvConfFamilies returns the address families of the nameservers in a
// resolv.conf file. An unreadable file yields an empty map.
func resolvConfFamilies(path string) map[string]bool {
	fams := map[string]bool{}
	for _, ns := range resolvConfNameservers(path) {
		if fam := serverFamily(strings.Split(ns, "%")[0]); fam != "" {
			fams[fam] = true
		}
	}
	return fams
}

// resolvConfNameservers returns the nameserver addresses of a resolv.conf
// file in order. An unreadable file yields none.
func resolvConfNameservers(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			out = append(out, fields[1])
		}
	}
	return out
}

// ------------------------------------------------------------------ web

// probeWeb probes apex and www separately (the TLS name and Host header
// differ even when the addresses are shared), records reserved addresses,
// and follows one redirect chain per family per name.
func probeWeb(ctx context.Context, cfg config, r Runner, d dialer, dns dnsResults, rep *Report) WebSection {
	apexAll := wantedAddrs(cfg, dns.apex["A"], dns.apex["AAAA"])
	// www is a convention at a registrable domain. Prefixing it to a name
	// that is already a host invents a name nobody configured:
	// www.old.reddit.com answers from a catch-all and is served a
	// *.reddit.com certificate that cannot cover it, which read as a
	// hostname mismatch on a healthy site.
	var wwwAll []netip.Addr
	if registrableDomain(cfg.Domain) {
		wwwAll = wantedAddrs(cfg, dns.www["A"], dns.www["AAAA"])
	}
	apexAddrs, reservedApex := splitReserved(apexAll)
	wwwAddrs, reservedWWW := splitReserved(wwwAll)
	// An address published at both apex and www is one reserved address,
	// not two: everything else in the report aggregates, and this path
	// listed 127.0.0.1 twice for localtest.me with nothing to tell the
	// entries apart.
	rep.ReservedAddresses = dedupeStrings(append(reservedApex, reservedWWW...))

	apex, www := cfg.Domain, "www."+cfg.Domain
	hosts := hostAddrsByFamily(map[string][]netip.Addr{apex: apexAddrs, www: wwwAddrs})
	// Both names share the caps: a zone publishing a hundred addresses
	// must not open hundreds of sockets and processes at once.
	slots := make(chan struct{}, maxAddressProbes)
	r = limitRunner(r, maxQUICProbes)
	var web WebSection
	parallel(
		func() { web.Apex = probeHost(ctx, cfg, r, d, apex, apexAddrs, reservedApex, hosts, slots) },
		func() {
			if !registrableDomain(cfg.Domain) {
				return
			}
			web.WWW = probeHost(ctx, cfg, r, d, www, wwwAddrs, reservedWWW, hosts, slots)
		},
	)
	if web.WWW != nil && len(apexAll) > 0 && sameAddressSet(apexAll, wwwAll) {
		web.WWW.SameAsApex = true
	}
	return web
}

// maxAddressProbes is how many addresses are probed at once across both
// names. One address holds up to four sockets (80, 443 and the two
// legacy-TLS handshakes), so this bounds a run at about 64; real hosts
// publish at most a dozen or so.
const maxAddressProbes = 16

// maxQUICProbes is how many quicprobe processes run at once.
const maxQUICProbes = 16

// hostAddrsByFamily builds, per family, the address the redirect follower
// uses for each host.
func hostAddrsByFamily(addrs map[string][]netip.Addr) map[string]hostAddrs {
	out := map[string]hostAddrs{familyIPv4: {}, familyIPv6: {}}
	for host, list := range addrs {
		for _, ip := range list {
			fam := familyOf(ip)
			if _, ok := out[fam][host]; !ok {
				out[fam][host] = ip
			}
		}
	}
	return out
}

// probeHost runs the per-address probes for one hostname and assembles
// its HostWeb entry.
func probeHost(ctx context.Context, cfg config, r Runner, d dialer, host string, addrs []netip.Addr, reserved []string, hosts map[string]hostAddrs, slots chan struct{}) *HostWeb {
	if len(addrs) == 0 && len(reserved) == 0 {
		return nil
	}
	apex, www := cfg.Domain, "www."+cfg.Domain
	probes := make([]addrProbe, len(addrs))
	var tasks []func()
	for i, ip := range addrs {
		tasks = append(tasks, func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			probes[i] = probeAddress(ctx, d, ip, host, apex, www, cfg.tcpTimeout())
		})
	}
	var quic map[string]*QUICResult
	tasks = append(tasks, func() { quic = quicAll(ctx, cfg, r, host, addrs) })
	parallel(tasks...)

	h := &HostWeb{}
	for _, p := range probes {
		h.add(addrEntry(p, quic[p.IP.String()]))
	}
	for _, res := range reserved {
		h.add(AddrWeb{IP: strings.Fields(res)[0], HTTP: PortSkipped, HTTPS: PortSkipped})
	}
	// Following a chain walks the site as a visitor would; the scraper's
	// browser does that, so it is opt-in here.
	if cfg.RedirectLog {
		h.Redirects = redirectChains(ctx, d, host, hosts, cfg.tcpTimeout())
	}
	h.CertConsistent = certConsistent(h.addrs())
	return h
}

func addrEntry(p addrProbe, q *QUICResult) AddrWeb {
	return AddrWeb{IP: p.IP.String(), HTTP: p.HTTP, HTTPS: p.HTTPS, HTTPRes: p.HTTPRes, HTTPSRes: p.HTTPSRes, TLS: p.TLS, QUIC: q, HTTPVersions: httpVersionsFor(p, q)}
}

// redirectChains follows the HTTP entry point of host once per family.
func redirectChains(ctx context.Context, d dialer, host string, hosts map[string]hostAddrs, timeout time.Duration) map[string]*RedirectChain {
	out := map[string]*RedirectChain{}
	var mu sync.Mutex
	var tasks []func()
	for _, fam := range []string{familyIPv4, familyIPv6} {
		if _, ok := hosts[fam][host]; !ok {
			continue
		}
		tasks = append(tasks, func() {
			c := followRedirects(ctx, d, "http", host, hosts[fam], timeout)
			mu.Lock()
			out[fam] = &c
			mu.Unlock()
		})
	}
	parallel(tasks...)
	if len(out) == 0 {
		return nil
	}
	return out
}

// certConsistent is nil without certificates, otherwise whether every
// address served the same leaf.
func certConsistent(addrs []AddrWeb) *bool {
	var first string
	seen := false
	for _, a := range addrs {
		if a.TLS == nil || a.TLS.Cert == nil {
			continue
		}
		if seen && a.TLS.Cert.Fingerprint != first {
			f := false
			return &f
		}
		first, seen = a.TLS.Cert.Fingerprint, true
	}
	if !seen {
		return nil
	}
	t := true
	return &t
}

// wantedAddrs returns the addresses from A/AAAA lookups that belong to an
// enabled family.
func wantedAddrs(cfg config, lookups ...Lookup) []netip.Addr {
	var out []netip.Addr
	for _, l := range lookups {
		for _, ip := range l.Addrs() {
			if cfg.wantsFamily(familyOf(ip)) {
				out = append(out, ip)
			}
		}
	}
	return out
}

func familyOf(ip netip.Addr) string {
	if ip.Unmap().Is4() {
		return familyIPv4
	}
	return familyIPv6
}

// quicAll probes QUIC on every address of the host, keyed by address, so
// that QUIC facts are as complete as the TLS and HTTP ones.
func quicAll(ctx context.Context, cfg config, r Runner, host string, addrs []netip.Addr) map[string]*QUICResult {
	out := map[string]*QUICResult{}
	var mu sync.Mutex
	var tasks []func()
	seen := map[netip.Addr]bool{}
	for _, ip := range addrs {
		if seen[ip] {
			continue
		}
		seen[ip] = true
		tasks = append(tasks, func() {
			q := probeQUIC(ctx, r, cfg.QuicPath, host, ip, cfg.QuicTimeoutSec)
			mu.Lock()
			out[ip.String()] = &q
			mu.Unlock()
		})
	}
	parallel(tasks...)
	return out
}

// --------------------------------------------------------------- others

// auditNameservers resolves the NS set, audits every address and checks
// glue. Skipped for names that are not zones, and for names outside the
// global DNS, whose NS answer (if any) came from the resolver itself.
func auditNameservers(ctx context.Context, cfg config, r Runner, dns dnsResults, rep *Report) *NSReport {
	if rep.NotAZone || rep.ReservedName != "" {
		return nil
	}
	names := nsNames(dns.apex["NS"])
	if len(names) == 0 {
		names = rep.Delegation.ParentNS
	}
	if len(names) == 0 {
		return nil
	}
	ns := resolveNS(names, dns.cache.get)
	auditAll(ctx, r, cfg.DigPath, &ns, cfg.Domain, cfg.Families, cfg.TimeoutSec)
	// Glue is checked against the NS names, resolved or not: a name under
	// the zone that does not resolve is the one most likely to lack glue.
	if rep.Delegation.ParentServer != "" && rep.Delegation.Status != DelegationSameServers {
		msgs := runDig(ctx, r, cfg.DigPath, glueArgs(rep.Delegation.ParentServer, traceFamily(cfg), cfg.TimeoutSec, cfg.Domain)...)
		ns.Glue = checkGlue(msgs, cfg.Domain, names, ns.addrs)
	}
	return &ns
}

// assessMail evaluates DMARC, SPF, MX, DKIM, MTA-STS and TLS-RPT for a
// zone apex. Hosts inside a zone get no mail section, like the nameserver
// audit: mail policy lives at the zone, and looking up _dmarc under a
// _dmarc name only produces noise.
// noMailPossible reports whether the name can have no mail configuration
// at all: a host inside a zone, a name outside the global DNS, or a name
// that does not exist. None of them has anything to configure, so "no
// DMARC record" would be a warning nobody could act on.
func noMailPossible(rep *Report, dns dnsResults) bool {
	if rep.NotAZone || rep.ReservedName != "" || registrySuffix(rep.Domain) {
		return true
	}
	return nameDoesNotExist(dns.apex)
}

func assessMail(ctx context.Context, cfg config, dns dnsResults, skip bool) *MailReport {
	if skip {
		return nil
	}
	get := dns.cache.get
	m := &MailReport{
		DMARC:  parseDMARC(dns.dmarc),
		SPF:    evaluateSPF(cfg.Domain, dns.apex["TXT"], get),
		MX:     checkMX(dns.apex["MX"], get),
		DKIM:   probeDKIM(cfg.Domain, get),
		TLSRPT: hasTLSRPT(dns.tlsRPT),
	}
	m.MTASTS = checkMTASTS(ctx, cfg.Domain, dns.mtaSTS, mxHosts(dns.apex["MX"]), cfg.tcpTimeout(), get)
	m.mtaSTSAbsent = dns.mtaSTS.Answered() && !m.MTASTS.Record
	m.tlsRPTAbsent = dns.tlsRPT.Answered() && !m.TLSRPT
	return m
}

// checkPreload answers from the cached Chromium preload list, fetching it
// once per host when the cache is cold. The wait and the fetch share the
// probe budget, so a cold or contended start costs this run its preload
// value rather than delaying or failing the run.
func checkPreload(ctx context.Context, cfg config) preloadFacts {
	if !cfg.HSTSPreload {
		return preloadFacts{}
	}
	// Zero timeout: the probe context is the only bound, so the download is
	// not held to the per-connection budget.
	list, err := loadPreloadList(ctx, cfg.HSTSCache, 0)
	if err != nil {
		return preloadFacts{status: PreloadUnknown, problem: scrubResolver(err.Error())}
	}
	p := preloadFacts{problem: scrubResolver(list.note)}
	p.status, p.coveredBy, p.policy = list.status(cfg.Domain)
	switch {
	case p.status != PreloadPreloaded:
	case p.coveredBy != "":
		// An ancestor covers the name only through include_subdomains.
		p.includeSubdomains = boolPtr(true)
	default:
		p.includeSubdomains = boolPtr(list.entries[bareName(cfg.Domain)].includeSubdomains)
	}
	return p
}

// preloadFacts is what the preload list says about the domain.
type preloadFacts struct {
	status, coveredBy, policy, problem string
	includeSubdomains                  *bool // set when preloaded
}

// wildcardSection evaluates the random-name probes and stamps www when its
// addresses are just the wildcard's.
func wildcardSection(dns dnsResults, web WebSection) *WildcardReport {
	w := assessWildcard(dns.wild, dns.wildSkip, dns.www["A"], dns.www["AAAA"])
	if w.WWWViaWildcard && web.WWW != nil {
		web.WWW.ViaWildcard = true
	}
	return &w
}

// assessCertPolicies evaluates CAA and TLSA against the certificates that
// were actually served.
func assessCertPolicies(dns dnsResults, rep *Report) (*CAAReport, *TLSAReport) {
	caa := assessCAA(dns.caaApex, dns.caaWWW, servedLeaf(rep.Web.Apex), servedLeaf(rep.Web.WWW))
	tlsa := assessTLSA(dns.tlsaApex, dns.tlsaWWW, rep.Web)
	return &caa, tlsa
}

// servedLeaf describes the first leaf certificate a host presented.
func servedLeaf(h *HostWeb) servedCert {
	for _, a := range h.addrs() {
		if a.TLS != nil && len(a.TLS.chain) > 0 {
			return servedCert{issuer: issuerOrg(a.TLS.chain[0]), wildcard: a.TLS.Cert != nil && a.TLS.Cert.Wildcard}
		}
	}
	return servedCert{}
}

// TLSAReport is the tlsa section of the report. Signed says whether the
// TLSA answers, positive or negative, were DNSSEC-validated: in a signed
// zone the denial of a missing TLSA set is itself signed, which is what
// lets a DANE client trust the absence.
type TLSAReport struct {
	Apex   []string `json:"apex"`
	WWW    []string `json:"www"`
	Signed bool     `json:"signed"`
	Result string   `json:"result"` // none, match, mismatch, unverified
}

// assessTLSA matches the TLSA sets against every address's chain and
// stamps each address with its own verdict.
func assessTLSA(apexRec, wwwRec Lookup, web WebSection) *TLSAReport {
	rep := &TLSAReport{Apex: nonNil(apexRec.Records), WWW: nonNil(wwwRec.Records), Result: TLSANone}
	rep.Signed = tlsaSigned(apexRec) && tlsaSigned(wwwRec)
	if len(apexRec.Records)+len(wwwRec.Records) == 0 {
		// No records and no answer is not "this domain has no DANE": the
		// absence has to be observed before it can be reported.
		if !apexRec.Answered() || !wwwRec.Answered() {
			rep.Result, rep.Signed = TLSAUnknown, false
		}
		return rep
	}
	rep.Result = tlsaResult(stampHosts(apexRec, wwwRec, web))
	return rep
}

// stampHosts matches each host's served chains against its TLSA records,
// reporting whether any address matched and whether any was checked.
func stampHosts(apexRec, wwwRec Lookup, web WebSection) (anyMatch, anyChecked bool) {
	for _, pair := range []struct {
		h   *HostWeb
		rec Lookup
	}{{web.Apex, apexRec}, {web.WWW, wwwRec}} {
		records := parseTLSARecords(pair.rec.Records)
		if pair.h == nil || len(records) == 0 {
			continue
		}
		m, c := stampHost(pair.h, records)
		anyMatch, anyChecked = anyMatch || m, anyChecked || c
	}
	return anyMatch, anyChecked
}

func tlsaResult(anyMatch, anyChecked bool) string {
	switch {
	case !anyChecked:
		return "unverified"
	case anyMatch:
		return TLSAMatch
	}
	return TLSAMismatch
}

// tlsaSigned is true when the answer, positive or negative, validated.
func tlsaSigned(l Lookup) bool {
	return l.Trust == TrustSecure
}

// stampHost applies matchTLSA to every address of a host and reports
// whether any matched and whether any could be checked.
func stampHost(h *HostWeb, records []tlsaRecord) (anyMatch, anyChecked bool) {
	for _, list := range [][]AddrWeb{h.IPv4, h.IPv6} {
		for i := range list {
			a := &list[i]
			if a.TLS == nil || len(a.TLS.chain) == 0 {
				continue
			}
			a.TLSA = matchTLSA(records, a.TLS.chain, a.TLS.pkixValid)
			anyChecked = true
			anyMatch = anyMatch || a.TLSA == TLSAMatch
		}
	}
	return anyMatch, anyChecked
}
