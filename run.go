package main

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// netDialer is the production dialer.
type netDialer struct{ net.Dialer }

// lookupCache memoises delv lookups for one run so that SPF includes, MX
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

// get returns the memoised lookup, running delv on first use. Each miss
// gets its own timeout so that lookups requested after the DNS phase
// (nameserver names learned from the parent, for instance) still have a
// budget instead of inheriting an expired deadline.
func (c *lookupCache) get(name, qtype string) Lookup {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
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
		return Lookup{Name: name, Type: qtype, Status: StatusTimeout, Error: "delv timed out"}
	}
	lctx, cancel := context.WithTimeout(base, c.cfg.timeout())
	defer cancel()
	l = delvLookup(lctx, c.r, c.cfg.DelvPath, c.cfg.Resolver, "", name, qtype)
	c.mu.Lock()
	c.done[key] = l
	c.mu.Unlock()
	return l
}

// dnsResults collects every delv lookup for one run.
type dnsResults struct {
	apex     map[string]Lookup
	www      map[string]Lookup
	ds       Lookup
	dnskey   Lookup
	reach    map[string]string
	dmarc    Lookup
	mtaSTS   Lookup
	tlsRPT   Lookup
	wildA    Lookup
	wildAAAA Lookup
	caaApex  Lookup
	caaWWW   Lookup
	tlsaApex Lookup
	tlsaWWW  Lookup
	cache    *lookupCache
}

// run performs every check for cfg and returns the finished report.
func run(ctx context.Context, cfg config, r Runner, d dialer) *Report {
	start := time.Now()
	rep := newReport(cfg)

	// The DNS tools are capped together; quicprobe is left alone because it
	// waits on the network rather than competing for CPU, and queueing it
	// behind delv would only cost QUIC answers.
	dnsRunner := limitRunner(r, cfg.DNSConcurrency)

	var dns dnsResults
	parallel(
		func() { rep.Delegation = runTrace(ctx, cfg, dnsRunner) },
		func() { dns = gatherDNS(ctx, cfg, dnsRunner, r) },
	)
	rep.DNS = DNSSection{Apex: dns.apex, WWW: dns.www, ResolverReachable: dns.reach}
	classifyZone(rep, cfg, dns, dnsRunner)

	probeCtx, cancel := context.WithTimeout(ctx, probeBudget(cfg))
	defer cancel()
	dns.cache.setContext(probeCtx) // late lookups share the probe budget
	parallel(
		func() { rep.Web = probeWeb(probeCtx, cfg, r, d, dns, rep) },
		func() { rep.Nameservers = auditNameservers(probeCtx, cfg, dnsRunner, dns, rep) },
		func() { rep.Mail = assessMail(probeCtx, cfg, dns, rep.NotAZone) },
		func() {
			rep.HSTSPreload, rep.HSTSPreloadCoveredBy, rep.HSTSPreloadError = checkPreload(probeCtx, cfg)
		},
	)
	rep.Wildcard = wildcardSection(dns, rep.Web)
	rep.CAA, rep.TLSA = assessCertPolicies(dns, rep)

	buildFindings(rep)
	rep.ElapsedMs = time.Since(start).Milliseconds()
	return rep
}

func newReport(cfg config) *Report {
	return &Report{
		Domain:         cfg.Domain,
		UnicodeDomain:  cfg.UnicodeDomain,
		Resolver:       cfg.Resolver.String(),
		Families:       cfg.Families,
		TimeoutSec:     cfg.TimeoutSec,
		TCPTimeoutSec:  cfg.TCPTimeoutSec,
		QuicTimeoutSec: cfg.QuicTimeoutSec,
		DNSConcurrency: cfg.DNSConcurrency,
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
func classifyZone(rep *Report, cfg config, dns dnsResults, r Runner) {
	if rep.NotAZone, rep.EnclosingZone = detectNotAZone(cfg.Domain, dns, rep.Delegation); rep.NotAZone {
		rep.DNSSEC = classifyByTrust(dns.apex)
		rep.Delegation = Delegation{Status: DelegationNotAZone, Error: "name is a host inside " + firstNonEmpty(rep.EnclosingZone, "another zone")}
		return
	}
	bctx, cancel := context.WithTimeout(context.Background(), cfg.timeout())
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
	if dns.apex["NS"].Status != StatusNXRRSet || len(deleg.ParentNS) > 0 {
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
			return strings.TrimSuffix(owner, ".")
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

// gatherDNS runs all delv lookups in parallel in two waves: first the fixed
// set, then the lookups that depend on those answers (SPF includes, MX
// targets, DKIM selectors, NS names). Each wave gets its own budget.
//
// gatherDNS runs the record lookups through the capped runner. The
// reachability probe uses the uncapped one: it measures our own resolver,
// so letting the target's hung lookups starve it would turn a slow domain
// into a false claim that the resolver is down.
func gatherDNS(ctx context.Context, cfg config, r, reachRunner Runner) dnsResults {
	dctx, cancel := context.WithTimeout(ctx, cfg.timeout())
	defer cancel()
	res := dnsResults{
		apex:  make(map[string]Lookup, len(apexTypes)),
		www:   make(map[string]Lookup, len(wwwTypes)),
		reach: make(map[string]string, len(cfg.Families)),
		cache: newLookupCache(dctx, cfg, r),
	}
	var mu sync.Mutex
	get := res.cache.get
	tasks := fixedLookups(&res, &mu, cfg, get)
	for _, fam := range cfg.Families {
		tasks = append(tasks, func() {
			store(&mu, res.reach, fam, checkReachability(dctx, cfg, reachRunner, fam))
		})
	}
	parallel(tasks...)

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
	wild := wildcardName(d)
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
		set(&res.wildA, wild, "A"), set(&res.wildAAAA, wild, "AAAA"),
		set(&res.caaApex, d, "CAA"), set(&res.caaWWW, www, "CAA"),
		set(&res.tlsaApex, "_443._tcp."+d, "TLSA"), set(&res.tlsaWWW, "_443._tcp."+www, "TLSA"),
	)
	return tasks
}

// dependentLookups warm the cache for names learned from the first wave so
// that the evaluators run against memoised answers.
func dependentLookups(res *dnsResults, cfg config, get lookupFn) []func() {
	var tasks []func()
	for _, sel := range dkimSelectors {
		name := sel + "._domainkey." + cfg.Domain
		tasks = append(tasks, func() { get(name, "TXT") })
	}
	for _, host := range mxHosts(res.apex["MX"]) {
		tasks = append(tasks, func() { get(host, "A") }, func() { get(host, "AAAA") })
	}
	for _, ns := range nsNames(res.apex["NS"]) {
		tasks = append(tasks, func() { get(ns, "A") }, func() { get(ns, "AAAA") })
	}
	tasks = append(tasks, func() { evaluateSPF(cfg.Domain, res.apex["TXT"], get) })
	return tasks
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
// transport family. It is skipped when the resolver has no address of
// that family.
func checkReachability(ctx context.Context, cfg config, r Runner, family string) string {
	if !resolverSupports(cfg, family) {
		return ReachSkipped + ": resolver has no " + family + " address"
	}
	l := delvLookup(ctx, r, cfg.DelvPath, cfg.Resolver, family, reachabilityQuery, "NS")
	if l.Answered() {
		return ReachYes
	}
	return ReachNo
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
	f, err := os.Open(path)
	if err != nil {
		return fams
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if fam := serverFamily(strings.Split(fields[1], "%")[0]); fam != "" {
			fams[fam] = true
		}
	}
	return fams
}

// ------------------------------------------------------------------ web

// probeWeb probes apex and www separately (the TLS name and Host header
// differ even when the addresses are shared), records reserved addresses,
// and follows one redirect chain per family per name.
func probeWeb(ctx context.Context, cfg config, r Runner, d dialer, dns dnsResults, rep *Report) WebSection {
	apexAll := wantedAddrs(cfg, dns.apex["A"], dns.apex["AAAA"])
	wwwAll := wantedAddrs(cfg, dns.www["A"], dns.www["AAAA"])
	apexAddrs, reservedApex := splitReserved(apexAll)
	wwwAddrs, reservedWWW := splitReserved(wwwAll)
	rep.ReservedAddresses = append(reservedApex, reservedWWW...)

	apex, www := cfg.Domain, "www."+cfg.Domain
	hosts := hostAddrsByFamily(map[string][]netip.Addr{apex: apexAddrs, www: wwwAddrs})
	var web WebSection
	parallel(
		func() { web.Apex = probeHost(ctx, cfg, r, d, apex, apexAddrs, reservedApex, hosts) },
		func() { web.WWW = probeHost(ctx, cfg, r, d, www, wwwAddrs, reservedWWW, hosts) },
	)
	if web.WWW != nil && len(apexAll) > 0 && sameAddressSet(apexAll, wwwAll) {
		web.WWW.SameAsApex = true
	}
	return web
}

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
func probeHost(ctx context.Context, cfg config, r Runner, d dialer, host string, addrs []netip.Addr, reserved []string, hosts map[string]hostAddrs) *HostWeb {
	if len(addrs) == 0 && len(reserved) == 0 {
		return nil
	}
	apex, www := cfg.Domain, "www."+cfg.Domain
	probes := make([]addrProbe, len(addrs))
	var tasks []func()
	for i, ip := range addrs {
		tasks = append(tasks, func() { probes[i] = probeAddress(ctx, d, ip, host, apex, www, cfg.tcpTimeout()) })
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
	h.Redirects = redirectChains(ctx, d, host, hosts, cfg.tcpTimeout())
	h.CertConsistent = certConsistent(h.addrs())
	return h
}

func addrEntry(p addrProbe, q *QUICResult) AddrWeb {
	return AddrWeb{IP: p.IP.String(), HTTP: p.HTTP, HTTPS: p.HTTPS, HTTPRes: p.HTTPRes, HTTPSRes: p.HTTPSRes, TLS: p.TLS, QUIC: q}
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
// glue. Skipped for names that are not zones.
func auditNameservers(ctx context.Context, cfg config, r Runner, dns dnsResults, rep *Report) *NSReport {
	if rep.NotAZone {
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
	// Glue can only be compared against addresses the child gave us. With
	// none, an empty glue report would read as "checked, nothing missing".
	if len(ns.addrs) > 0 && rep.Delegation.ParentServer != "" && rep.Delegation.Status != DelegationSameServers {
		msgs := runDig(ctx, r, cfg.DigPath, glueArgs(rep.Delegation.ParentServer, traceFamily(cfg), cfg.TimeoutSec, cfg.Domain)...)
		ns.Glue = checkGlue(msgs, cfg.Domain, ns.addrs)
	}
	return &ns
}

// assessMail evaluates DMARC, SPF, MX, DKIM, MTA-STS and TLS-RPT for a
// zone apex. Hosts inside a zone get no mail section, like the nameserver
// audit: mail policy lives at the zone, and looking up _dmarc under a
// _dmarc name only produces noise.
func assessMail(ctx context.Context, cfg config, dns dnsResults, notAZone bool) *MailReport {
	if notAZone {
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
	return m
}

// checkPreload answers from the cached Chromium preload list, fetching it
// once per host when the cache is cold. The wait and the fetch share the
// probe budget, so a cold or contended start costs this run its preload
// value rather than delaying or failing the run.
func checkPreload(ctx context.Context, cfg config) (status, coveredBy, problem string) {
	if !cfg.HSTSPreload {
		return "", "", ""
	}
	// Zero timeout: the probe context is the only bound, so the download is
	// not held to the per-connection budget.
	list, err := loadPreloadList(ctx, cfg.HSTSCache, 0)
	if err != nil {
		return PreloadUnknown, "", scrubResolver(err.Error())
	}
	status, coveredBy = list.status(cfg.Domain)
	return status, coveredBy, ""
}

// wildcardSection evaluates the nonce probe and stamps www when its
// addresses are just the wildcard's.
func wildcardSection(dns dnsResults, web WebSection) *WildcardReport {
	w := assessWildcard(dns.wildA, dns.wildAAAA, dns.www["A"], dns.www["AAAA"])
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
		return rep
	}
	anyMatch, anyChecked := false, false
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
	switch {
	case !anyChecked:
		rep.Result = "unverified"
	case anyMatch:
		rep.Result = TLSAMatch
	default:
		rep.Result = TLSAMismatch
	}
	return rep
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
