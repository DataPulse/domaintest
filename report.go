package main

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Address families.
const (
	familyIPv4 = "ipv4"
	familyIPv6 = "ipv6"
)

// Record types queried at the apex, in report order.
var apexTypes = []string{"A", "AAAA", "MX", "TXT", "NS"}

// Record types queried for the www name.
var wwwTypes = []string{"A", "AAAA"}

// Reachability values for dns.resolver_reachable.
const (
	ReachYes     = "yes"
	ReachNo      = "no"
	ReachSkipped = "skipped"
)

// Report is the JSON document domaintest prints.
type Report struct {
	Domain string `json:"domain"`
	// UnicodeDomain is the U-label form when Domain is an IDN A-label.
	UnicodeDomain string `json:"unicode_domain,omitempty"`
	// NotAZone is set when the name is a host inside a zone rather than a
	// zone apex; EnclosingZone names that zone when a SOA revealed it.
	NotAZone             bool            `json:"not_a_zone,omitempty"`
	EnclosingZone        string          `json:"enclosing_zone,omitempty"`
	Resolver             string          `json:"resolver"`
	Families             []string        `json:"families"`
	TimeoutSec           int             `json:"timeout_sec"`
	TCPTimeoutSec        int             `json:"tcp_timeout_sec"`
	DNSConcurrency       int             `json:"dns_concurrency"`
	QuicTimeoutSec       int             `json:"quic_timeout_sec"`
	DNS                  DNSSection      `json:"dns"`
	DNSSEC               DNSSECReport    `json:"dnssec"`
	Delegation           Delegation      `json:"delegation"`
	Web                  WebSection      `json:"web"`
	Mail                 *MailReport     `json:"mail,omitempty"`
	Nameservers          *NSReport       `json:"nameservers,omitempty"`
	CAA                  *CAAReport      `json:"caa,omitempty"`
	TLSA                 *TLSAReport     `json:"tlsa,omitempty"`
	Wildcard             *WildcardReport `json:"wildcard,omitempty"`
	ReservedAddresses    []string        `json:"reserved_addresses,omitempty"`
	HSTSPreload          string          `json:"hsts_preload,omitempty"`
	HSTSPreloadCoveredBy string          `json:"hsts_preload_covered_by,omitempty"`
	HSTSPreloadError     string          `json:"hsts_preload_error,omitempty"`
	Errors               []string        `json:"errors"`
	Warnings             []string        `json:"warnings"`
	OK                   bool            `json:"ok"`
	ElapsedMs            int64           `json:"elapsed_ms"`
}

// DNSSection holds the record lookups.
type DNSSection struct {
	Apex              map[string]Lookup `json:"apex"`
	WWW               map[string]Lookup `json:"www"`
	ResolverReachable map[string]string `json:"resolver_reachable,omitempty"`
}

// WebSection holds TCP and QUIC probe results per name.
type WebSection struct {
	Apex *HostWeb `json:"apex,omitempty"`
	WWW  *HostWeb `json:"www,omitempty"`
}

// HostWeb holds per-family probe results for one hostname.
type HostWeb struct {
	SameAsApex     bool                      `json:"same_as_apex,omitempty"`
	ViaWildcard    bool                      `json:"via_wildcard,omitempty"`
	IPv4           []AddrWeb                 `json:"ipv4,omitempty"`
	IPv6           []AddrWeb                 `json:"ipv6,omitempty"`
	Redirects      map[string]*RedirectChain `json:"redirects,omitempty"`
	CertConsistent *bool                     `json:"cert_consistent,omitempty"`
}

// add appends an address entry to the right family list.
func (h *HostWeb) add(a AddrWeb) {
	ip, err := netip.ParseAddr(a.IP)
	if err == nil && ip.Is6() {
		h.IPv6 = append(h.IPv6, a)
		return
	}
	h.IPv4 = append(h.IPv4, a)
}

// AddrWeb is the probe outcome for one address.
type AddrWeb struct {
	IP       string      `json:"ip"`
	HTTP     PortState   `json:"80"`
	HTTPS    PortState   `json:"443"`
	HTTPRes  *HTTPResult `json:"http,omitempty"`
	HTTPSRes *HTTPResult `json:"https,omitempty"`
	TLS      *TLSResult  `json:"tls,omitempty"`
	TLSA     string      `json:"tlsa,omitempty"`
	QUIC     *QUICResult `json:"quic,omitempty"`
}

func (h *HostWeb) addrs() []AddrWeb {
	if h == nil {
		return nil
	}
	return append(append([]AddrWeb{}, h.IPv4...), h.IPv6...)
}

// findings collects errors and warnings while walking the report.
type findings struct {
	errors   []string
	warnings []string
}

func (f *findings) errorf(format string, a ...any) {
	f.errors = append(f.errors, fmt.Sprintf(format, a...))
}
func (f *findings) warningf(format string, a ...any) {
	f.warnings = append(f.warnings, fmt.Sprintf(format, a...))
}

// buildFindings fills Errors, Warnings and OK from the rest of the report.
func buildFindings(rep *Report) {
	var f findings
	f.dnsFindings(rep)
	f.dnssecFindings(rep.DNSSEC)
	f.delegationFindings(rep.Delegation)
	f.reachabilityFindings(rep.DNS.ResolverReachable)
	f.webFindings("apex", rep.Web.Apex)
	f.webFindings("www", rep.Web.WWW)
	f.deepFindings(rep)
	rep.Errors = nonNil(f.errors)
	rep.Warnings = nonNil(f.warnings)
	rep.OK = len(rep.Errors) == 0
}

func (f *findings) dnsFindings(rep *Report) {
	apex := rep.DNS.Apex
	if apex["NS"].Status == StatusNXDomain || apex["A"].Status == StatusNXDomain {
		f.errorf("apex %s does not exist (NXDOMAIN)", rep.Domain)
		return
	}
	// A bogus or SERVFAIL verdict already explains every failed lookup.
	folded := rep.DNSSEC.State == DNSSECBogus || rep.DNSSEC.State == DNSSECServfail
	for _, t := range apexTypes {
		f.lookupFindings("apex", t, apex[t], folded)
	}
	for _, t := range wwwTypes {
		f.lookupFindings("www", t, rep.DNS.WWW[t], folded)
	}
	switch {
	case rep.NotAZone:
		f.warningf("%s is not a zone apex%s: delegation and DNSSEC zone checks skipped", rep.Domain, enclosing(rep.EnclosingZone))
	case rep.Delegation.Status == DelegationChildNoNS:
		// the delegation finding already says the zone has no NS RRset
	case !apex["NS"].HasRecords() && apex["NS"].Answered():
		f.errorf("apex has no NS records")
	}
	f.presenceWarnings(rep)
}

func enclosing(zone string) string {
	if zone == "" {
		return ""
	}
	return " (inside zone " + zone + ")"
}

// lookupFindings reports lookups that did not complete. Failures are
// suppressed when the DNSSEC verdict (bogus or SERVFAIL) already explains
// them.
func (f *findings) lookupFindings(label, qtype string, l Lookup, folded bool) {
	switch l.Status {
	case StatusTimeout:
		f.errorf("%s %s lookup timed out", label, qtype)
	case StatusFailure:
		if !folded {
			f.errorf("%s %s lookup failed: %s", label, qtype, l.Error)
		}
	}
}

// presenceWarnings flags missing records. Only lookups that actually
// answered count; failures and timeouts are reported as errors elsewhere.
func (f *findings) presenceWarnings(rep *Report) {
	apex, www := rep.DNS.Apex, rep.DNS.WWW
	f.addressWarnings("apex", apex["A"], apex["AAAA"])
	f.addressWarnings("www", www["A"], www["AAAA"])
	switch {
	case apex["MX"].IsNullMX():
		f.warningf("apex publishes a null MX (RFC 7505): accepts no mail")
	case apex["MX"].Answered() && !apex["MX"].HasRecords():
		f.warningf("apex has no MX records")
	}
	if apex["TXT"].Answered() && !hasSPF(apex["TXT"].Records) {
		f.warningf("no SPF (v=spf1) record in apex TXT")
	}
}

func (f *findings) addressWarnings(label string, a, aaaa Lookup) {
	if !a.Answered() || !aaaa.Answered() {
		return
	}
	switch {
	case a.Status == StatusNXDomain:
		f.warningf("%s name does not exist", label)
	case !a.HasRecords() && !aaaa.HasRecords():
		f.warningf("%s has no A or AAAA records", label)
	case !aaaa.HasRecords():
		f.warningf("%s has no AAAA record", label)
	}
}

func hasSPF(txt []string) bool {
	for _, t := range txt {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
			return true
		}
	}
	return false
}

func (f *findings) dnssecFindings(d DNSSECReport) {
	switch d.State {
	case DNSSECBogus:
		f.errorf("DNSSEC validation fails (bogus): %s", firstNonEmpty(d.EDE, d.Detail))
	case DNSSECServfail:
		f.errorf("resolver returned SERVFAIL: %s", firstNonEmpty(d.EDE, d.Detail))
	case DNSSECIsland:
		f.warningf("DNSSEC: %s", d.Detail)
	case DNSSECUnknown:
		f.warningf("DNSSEC state unknown: %s", d.Detail)
	}
}

func (f *findings) delegationFindings(d Delegation) {
	switch d.Status {
	case DelegationMismatch:
		f.errorf("NS delegation mismatch: parent-only %v, child-only %v", d.ParentOnly, d.ChildOnly)
	case DelegationNotDelegated:
		f.errorf("domain is not delegated by its parent zone (%s)", d.ParentServer)
	case DelegationNoChildAnswer:
		f.errorf("delegated NS servers did not answer the NS query: %s", firstNonEmpty(d.Error, "no response"))
	case DelegationChildNoNS:
		f.errorf("lame delegation: %s", d.Error)
	case DelegationError:
		f.errorf("delegation trace failed: %s", d.Error)
	}
}

func (f *findings) reachabilityFindings(reach map[string]string) {
	for _, fam := range sortedKeys(reach) {
		if reach[fam] == ReachNo {
			f.errorf("resolver not reachable over %s", fam)
		}
	}
}

// webFindings warns about addresses with nothing listening, and about QUIC
// being available on some addresses of a host but not others. A host with
// no QUIC at all is not flagged: most sites do not serve h3, and the
// per-address result is already in the report.
func (f *findings) webFindings(label string, h *HostWeb) {
	addrs := h.addrs()
	for _, a := range addrs {
		switch {
		case a.HTTP == PortSkipped && a.HTTPS == PortSkipped:
			// Not a connectivity failure: the probe declined to connect
			// because the address is reserved. Reporting it as "no
			// listener" sends anyone triaging it after a problem that
			// does not exist.
			f.warningf("%s %s: not probed (reserved address)", label, a.IP)
		case a.HTTP != PortOpen && a.HTTPS != PortOpen:
			f.warningf("%s %s: no listener on 80 or 443 (%s/%s)", label, a.IP, a.HTTP, a.HTTPS)
		case a.HTTPS != PortOpen:
			f.warningf("%s %s: HTTP on 80 answers but HTTPS on 443 does not (%s)", label, a.IP, a.HTTPS)
		}
	}
	if !anyQUIC(addrs) {
		return
	}
	for _, a := range addrs {
		if a.QUIC != nil && !a.QUIC.Supported {
			f.warningf("%s %s: QUIC/h3 works on another probed address of this host but not here", label, a.IP)
		}
	}
}

func anyQUIC(addrs []AddrWeb) bool {
	for _, a := range addrs {
		if a.QUIC != nil && a.QUIC.Supported {
			return true
		}
	}
	return false
}

// sameAddressSet reports whether two address lists contain the same IPs.
func sameAddressSet(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[netip.Addr]bool, len(a))
	for _, ip := range a {
		set[ip.Unmap()] = true
	}
	for _, ip := range b {
		if !set[ip.Unmap()] {
			return false
		}
	}
	return true
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// deepFindings runs the rules for the TLS, HTTP, mail, nameserver, CAA,
// TLSA, wildcard and reserved-address sections.
func (f *findings) deepFindings(rep *Report) {
	f.reservedFindings(rep)
	f.wildcardFindings(rep)
	f.tlsFindings("apex", rep.Web.Apex, rep.Web.WWW)
	f.tlsFindings("www", rep.Web.WWW, rep.Web.Apex)
	f.httpFindings("apex", rep.Web.Apex)
	f.httpFindings("www", rep.Web.WWW)
	f.mailFindings(rep.Mail)
	f.nsFindings(rep.Nameservers)
	f.caaFindings(rep.CAA)
	f.tlsaFindings(rep.TLSA)
	f.preloadFindings(rep)
}

// ------------------------------------------------------------ deep checks

// expiryWarnDays is the threshold below which certificate expiry warns.
const expiryWarnDays = 30

// hstsMinAge is the max-age below which HSTS is considered too short.
const hstsMinAge = 15552000 // 180 days

func (f *findings) reservedFindings(rep *Report) {
	for _, r := range rep.ReservedAddresses {
		f.errorf("reserved address published in DNS: %s", r)
	}
}

func (f *findings) wildcardFindings(rep *Report) {
	if rep.Wildcard != nil && rep.Wildcard.WWWViaWildcard {
		f.warningf("www is answered by a wildcard record, not a real host")
	}
}

// tlsFindings judges the certificates and protocol versions of one host.
// Chain problems are errors per address; facts that repeat across a CDN's
// addresses (old protocol versions, no TLS 1.3, coverage, expiry) are
// reported once per host with a count.
func (f *findings) tlsFindings(label string, h *HostWeb, sibling *HostWeb) {
	addrs := withTLS(h.addrs())
	if len(addrs) == 0 {
		return
	}
	f.chainFindings(label, addrs)
	f.expiryFindings(label, addrs)
	f.coverageFindings(label, addrs, sibling)
	f.versionFindings(label, addrs)
	if h.CertConsistent != nil && !*h.CertConsistent {
		f.warningf("%s: addresses serve different certificates", label)
	}
}

// chainFindings reports each distinct chain problem once for the host,
// with the count of addresses it affected, the way the nameserver audit
// reports a failing name. A CDN fleet that all fails the same way is one
// fact, not fourteen; the per-address detail stays in the web section.
func (f *findings) chainFindings(label string, addrs []AddrWeb) {
	type tally struct {
		chain, detail string
		count         int
	}
	byCause := map[string]*tally{}
	var order []string
	for _, a := range addrs {
		if a.TLS.Chain == ChainValid {
			continue
		}
		key := a.TLS.Chain + "\x00" + a.TLS.Error
		if byCause[key] == nil {
			byCause[key] = &tally{chain: a.TLS.Chain, detail: a.TLS.Error}
			order = append(order, key)
		}
		byCause[key].count++
	}
	for _, key := range order {
		t := byCause[key]
		f.errorf("%s: certificate %s on %d of %d addresses: %s", label,
			strings.ReplaceAll(t.chain, "_", " "), t.count, len(addrs), t.detail)
	}
}

func withTLS(addrs []AddrWeb) []AddrWeb {
	var out []AddrWeb
	for _, a := range addrs {
		if a.TLS != nil {
			out = append(out, a)
		}
	}
	return out
}

// expiryFindings warns once per host about the soonest-expiring valid
// certificate; expired ones are already errors.
func (f *findings) expiryFindings(label string, addrs []AddrWeb) {
	soonest := -1
	for _, a := range addrs {
		if a.TLS.Cert == nil || a.TLS.Chain == ChainExpired {
			continue
		}
		if soonest < 0 || a.TLS.Cert.DaysRemaining < soonest {
			soonest = a.TLS.Cert.DaysRemaining
		}
	}
	switch {
	case soonest < 0 || soonest >= expiryWarnDays:
	case soonest < 7:
		f.warningf("%s: certificate expires in %d days (urgent)", label, soonest)
	default:
		f.warningf("%s: certificate expires in %d days", label, soonest)
	}
}

// coverageFindings warns when this host's valid certificate does not
// cover the sibling name, but only if the sibling resolves and has no
// valid certificate of its own: a separately certified www is fine.
func (f *findings) coverageFindings(label string, addrs []AddrWeb, sibling *HostWeb) {
	if sibling == nil || len(sibling.addrs()) == 0 || hasValidCert(sibling) {
		return
	}
	for _, a := range addrs {
		if a.TLS.Chain != ChainValid || a.TLS.Cert == nil {
			continue
		}
		covers := a.TLS.Cert.CoversWWW
		other := "www"
		if label == "www" {
			covers, other = a.TLS.Cert.CoversApex, "the apex"
		}
		if !covers {
			f.warningf("%s: certificate does not cover %s, which resolves but has no valid certificate", label, other)
			return
		}
	}
}

func hasValidCert(h *HostWeb) bool {
	for _, a := range h.addrs() {
		if a.TLS != nil && a.TLS.Chain == ChainValid {
			return true
		}
	}
	return false
}

// versionFindings aggregates protocol facts per host.
func (f *findings) versionFindings(label string, addrs []AddrWeb) {
	old10, old11, no13, total := 0, 0, 0, 0
	for _, a := range addrs {
		if a.TLS.Chain == ChainHandshakeFailed {
			continue
		}
		total++
		if a.TLS.TLS10 {
			old10++
		}
		if a.TLS.TLS11 {
			old11++
		}
		if a.TLS.Version != "" && a.TLS.Version != "TLS 1.3" {
			no13++
		}
	}
	if old10+old11 > 0 {
		f.warningf("%s: TLS 1.0/1.1 still accepted on %d of %d addresses", label, maxInt(old10, old11), total)
	}
	if no13 > 0 {
		f.warningf("%s: no TLS 1.3 on %d of %d addresses", label, no13, total)
	}
}

// httpFindings judges status codes per port, clear-text serving, redirect
// chains and HSTS strength for one host.
func (f *findings) httpFindings(label string, h *HostWeb) {
	if h == nil {
		return
	}
	addrs := h.addrs()
	f.statusFindings(label, "80", addrs, func(a AddrWeb) *HTTPResult { return a.HTTPRes })
	f.statusFindings(label, "443", addrs, func(a AddrWeb) *HTTPResult { return a.HTTPSRes })
	f.cleartextFindings(label, addrs)
	f.redirectFindings(label, h.Redirects)
	f.hstsFindings(label, addrs)
}

// statusFindings: every address ≥ 500 is an error, some is a warning, every
// address 4xx is a warning.
func (f *findings) statusFindings(label, port string, addrs []AddrWeb, pick func(AddrWeb) *HTTPResult) {
	total, server5xx, client4xx := 0, 0, 0
	for _, a := range addrs {
		r := pick(a)
		if r == nil || r.Status == 0 {
			continue
		}
		total++
		switch {
		case r.Status >= 500:
			server5xx++
		case r.Status >= 400:
			client4xx++
		}
	}
	switch {
	case total == 0:
	case server5xx == total:
		f.errorf("%s: every address returns a server error on port %s", label, port)
	case server5xx > 0:
		f.warningf("%s: %d of %d addresses return a server error on port %s", label, server5xx, total, port)
	case client4xx == total:
		f.warningf("%s: every address returns a client error on port %s", label, port)
	}
}

// cleartextFindings warns once per host when port 80 serves content or
// redirects somewhere that is not https.
func (f *findings) cleartextFindings(label string, addrs []AddrWeb) {
	served, elsewhere, total := 0, 0, 0
	for _, a := range addrs {
		r := a.HTTPRes
		if r == nil || r.Status == 0 {
			continue
		}
		total++
		switch {
		case r.Status < 300:
			served++
		case isRedirect(r.Status) && !strings.HasPrefix(strings.ToLower(r.Location), "https://"):
			elsewhere++
		}
	}
	if served > 0 {
		f.warningf("%s: HTTP serves content in the clear instead of redirecting to HTTPS (%d of %d addresses)", label, served, total)
	}
	if elsewhere > 0 {
		f.warningf("%s: HTTP redirects to a non-HTTPS URL (%d of %d addresses)", label, elsewhere, total)
	}
}

func (f *findings) redirectFindings(label string, chains map[string]*RedirectChain) {
	for _, fam := range sortedChainKeys(chains) {
		c := chains[fam]
		switch {
		case len(c.Hops) == 0:
			// The entry point did not answer; port 80's state already says so.
		case c.Loop:
			f.errorf("%s (%s): redirect loop %s", label, fam, describeHops(c.Hops))
		case c.Error != "" && strings.HasPrefix(c.Error, "more than"):
			f.errorf("%s (%s): %s: %s", label, fam, c.Error, describeHops(c.Hops))
		case c.Error != "":
			f.warningf("%s (%s): redirect chain broke: %s", label, fam, c.Error)
		case c.Hops[len(c.Hops)-1].Status >= 400:
			f.warningf("%s (%s): redirect chain ends in HTTP %d at %s", label, fam, c.Hops[len(c.Hops)-1].Status, c.FinalURL)
		}
	}
}

func describeHops(hops []RedirectHop) string {
	var parts []string
	for _, h := range hops {
		parts = append(parts, fmt.Sprintf("%s (%d)", h.URL, h.Status))
	}
	return strings.Join(parts, " -> ")
}

func sortedChainKeys(m map[string]*RedirectChain) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// hstsFindings warns once per host about the shortest HSTS max-age seen.
func (f *findings) hstsFindings(label string, addrs []AddrWeb) {
	shortest := int64(-1)
	for _, a := range addrs {
		if a.HTTPSRes == nil || a.HTTPSRes.HSTS == nil {
			continue
		}
		if shortest < 0 || a.HTTPSRes.HSTS.MaxAge < shortest {
			shortest = a.HTTPSRes.HSTS.MaxAge
		}
	}
	if shortest >= 0 && shortest < hstsMinAge {
		f.warningf("%s: HSTS max-age %d is under 180 days", label, shortest)
	}
}

// mailFindings covers DMARC, SPF, MX, DKIM and MTA-STS.
func (f *findings) mailFindings(m *MailReport) {
	if m == nil {
		return
	}
	f.dmarcFindings(m.DMARC)
	f.spfFindings(m.SPF)
	for _, mx := range m.MX {
		for _, p := range mx.Problems {
			if mx.Unresolved && p == mxUnresolvedProblem {
				f.warningf("MX %s: %s", mx.Host, p)
				continue
			}
			f.errorf("MX %s: %s", mx.Host, p)
		}
	}
	if m.DKIM.Wildcard {
		f.warningf("the zone answers every _domainkey selector (wildcard), so no selector could be verified")
	}
	for _, sel := range m.DKIM.Revoked {
		f.warningf("DKIM selector %s publishes a revoked (empty) key", sel)
	}
	f.mtaSTSFindings(m.MTASTS)
}

func (f *findings) dmarcFindings(d DMARC) {
	switch {
	case !d.Present:
		f.warningf("no DMARC record")
		return
	case d.Policy == "none":
		f.warningf("DMARC policy is p=none (monitor only)")
	}
	if d.Pct < 100 {
		f.warningf("DMARC applies to only %d%% of mail (pct=%d)", d.Pct, d.Pct)
	}
	for _, p := range d.Problems {
		f.errorf("DMARC: %s", p)
	}
}

// spfFindings maps evaluator problems to severities: anything that makes
// SPF fail outright or authorise everyone is an error.
func (f *findings) spfFindings(s SPFResult) {
	for _, p := range s.Problems {
		if strings.Contains(p, "permerror") || strings.HasPrefix(p, "+all") || strings.HasPrefix(p, "unknown mechanism") {
			f.errorf("SPF: %s", p)
		} else {
			f.warningf("SPF: %s", p)
		}
	}
}

func (f *findings) mtaSTSFindings(m *MTASTS) {
	if m == nil || !m.Record {
		return
	}
	severity := f.warningf
	if m.Mode == "enforce" {
		severity = f.errorf
	}
	switch {
	case m.Error != "":
		severity("MTA-STS: %s", m.Error)
	case !m.MXCovered:
		severity("MTA-STS policy mx patterns do not cover every MX host")
	}
}

// nsFindings covers count, resolution, per-server behaviour, serials,
// diversity and glue.
func (f *findings) nsFindings(n *NSReport) {
	if n == nil {
		return
	}
	if n.Count < 2 {
		f.errorf("only %d nameserver (at least two required)", n.Count)
	}
	for _, name := range n.NSCNAME {
		f.errorf("nameserver %s is a CNAME (RFC 2181 §10.3)", name)
	}
	for _, name := range n.Unresolvable {
		f.errorf("nameserver %s has no address", name)
	}
	for _, name := range n.Unresolved {
		f.warningf("nameserver %s: the address lookup did not complete, so it was not audited", name)
	}
	if len(n.Servers) == 0 {
		f.warningf("no nameserver was reached, so none of the per-server checks ran")
	}
	f.serverFindings(n.Servers)
	if n.SerialsConsistent != nil && !*n.SerialsConsistent {
		f.warningf("SOA serial differs between nameservers: %s", serialList(n.Servers))
	}
	f.diversityFindings(n)
	f.glueFindings(n.Glue)
}

// nsTally counts the addresses of one nameserver name, keeping the two
// kinds of failure apart: a server that answered and disclaimed authority
// is a different fact from one that said nothing at all.
type nsTally struct {
	total  int
	lame   int    // answered, and not authoritative
	silent int    // never answered
	reason string // why the lame ones are lame
}

// serverFindings reports each nameserver name once (anycast names have many
// addresses) and adds per-address warnings for TCP and EDNS gaps.
func (f *findings) serverFindings(servers []NSServer) {
	byName, order := tallyServers(f, servers)
	for _, name := range order {
		f.nameFindings(name, byName[name])
	}
}

func tallyServers(f *findings, servers []NSServer) (map[string]*nsTally, []string) {
	byName := map[string]*nsTally{}
	var order []string
	for _, s := range servers {
		t, ok := byName[s.Name]
		if !ok {
			t = &nsTally{}
			byName[s.Name] = t
			order = append(order, s.Name)
		}
		t.total++
		switch {
		case s.Error == "" || s.AA:
			f.serverWarnings(s)
		case unanswered(s.Error):
			t.silent++
		default:
			t.lame++
			t.reason = firstNonEmpty(t.reason, s.Error)
		}
	}
	return byName, order
}

// nameFindings judges one nameserver name. A server that answered and said
// it is not authoritative is proof of lameness at any count. A server that
// never answered proves nothing on its own, so it is a fault only when
// every address of the name failed: one silent address behind a quorum
// that is still authoritative is a flaky node, not a broken delegation.
func (f *findings) nameFindings(name string, t *nsTally) {
	if t.lame > 0 {
		f.errorf("nameserver %s: %s on %d of %d addresses", name, t.reason, t.lame, t.total)
	}
	switch {
	case t.silent > 0 && t.silent == t.total:
		f.errorf("nameserver %s: no answer on %d of %d addresses", name, t.silent, t.total)
	case t.silent > 0:
		f.warningf("nameserver %s: no answer on %d of %d addresses, the others are authoritative", name, t.silent, t.total)
	}
}

func (f *findings) serverWarnings(s NSServer) {
	if !s.TCP {
		f.warningf("nameserver %s (%s): no answer over TCP", s.Name, s.IP)
	}
	if !s.EDNS {
		f.warningf("nameserver %s (%s): no EDNS support", s.Name, s.IP)
	}
}

// serialList names the address beside each serial: in a drift report which
// address disagrees is the useful part, and a dual-stack or anycast name
// would otherwise repeat itself with no added information.
func serialList(servers []NSServer) string {
	var parts []string
	for _, s := range servers {
		if s.AA {
			parts = append(parts, fmt.Sprintf("%s(%s)=%d", s.Name, s.IP, s.Serial))
		}
	}
	return strings.Join(parts, ", ")
}

// diversityFindings warns only when prefixes were actually counted. A null
// count means nothing was examined and says nothing about diversity.
func (f *findings) diversityFindings(n *NSReport) {
	if n.IPv4Prefixes24 == nil || n.IPv6Prefixes48 == nil {
		return
	}
	v4, v6 := 0, 0
	for _, s := range n.Servers {
		if ip, err := netip.ParseAddr(s.IP); err == nil && ip.Is4() {
			v4++
		} else if err == nil {
			v6++
		}
	}
	if v4 >= 2 && *n.IPv4Prefixes24 == 1 {
		f.warningf("all IPv4 nameserver addresses share one /24")
	}
	if v6 >= 2 && *n.IPv6Prefixes48 == 1 {
		f.warningf("all IPv6 nameserver addresses share one /48")
	}
}

func (f *findings) glueFindings(g *GlueReport) {
	if g == nil {
		return
	}
	for _, name := range g.Missing {
		f.errorf("no glue at the parent for in-bailiwick nameserver %s", name)
	}
	for _, m := range g.Mismatch {
		f.warningf("glue at the parent differs from the zone for %s", m)
	}
}

func (f *findings) caaFindings(c *CAAReport) {
	if c == nil {
		return
	}
	for _, label := range []string{"apex", "www"} {
		if v := c.Hosts[label]; v != nil && v.Permitted != nil && !*v.Permitted {
			f.errorf("%s: CAA records do not permit the certificate issuer %q", label, v.Issuer)
		}
	}
}

// preloadMinAge is the max-age the HSTS preload list requires.
const preloadMinAge = 31536000

// preloadFindings cross-checks the preload-list status with the header
// actually served on the apex.
func (f *findings) preloadFindings(rep *Report) {
	h := servedHSTS(rep.Web.Apex)
	switch {
	case rep.HSTSPreload == PreloadPreloaded && !meetsPreload(h):
		f.warningf("domain is on the HSTS preload list but the served header no longer meets the preload requirements (max-age >= 1 year, includeSubDomains, preload)")
	case rep.HSTSPreload == PreloadAbsent && h != nil && h.Preload && !meetsPreload(h):
		f.warningf("HSTS header carries the preload directive but does not meet the preload requirements (max-age >= 1 year, includeSubDomains)")
	case rep.HSTSPreload == PreloadUnknown:
		f.warningf("HSTS preload list could not be consulted: %s", rep.HSTSPreloadError)
	}
}

// servedHSTS returns the first HSTS header seen on the host, or nil.
func servedHSTS(h *HostWeb) *HSTS {
	for _, a := range h.addrs() {
		if a.HTTPSRes != nil && a.HTTPSRes.HSTS != nil {
			return a.HTTPSRes.HSTS
		}
	}
	return nil
}

func meetsPreload(h *HSTS) bool {
	return h != nil && h.Preload && h.IncludeSubdomains && h.MaxAge >= preloadMinAge
}

func (f *findings) tlsaFindings(t *TLSAReport) {
	if t == nil || t.Result == TLSANone {
		return
	}
	if !t.Signed {
		f.warningf("TLSA records are published in an unsigned zone (DANE clients ignore them)")
	}
	if t.Result == TLSAMismatch {
		f.errorf("no TLSA record matches the certificate served (DANE validation fails)")
	}
}
