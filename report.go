package main

import (
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
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
	// Version and Timestamp lead the report as its header: which build
	// produced it, and when. Version is the stamped commit (see
	// buildVersion for an unstamped build). Timestamp is when the probe
	// began, UTC, RFC 3339 to the second; elapsed_ms later it finished.
	Version   string `json:"version"`
	Timestamp string `json:"timestamp"`
	Domain    string `json:"domain"`
	// UnicodeDomain is the U-label form when Domain is an IDN A-label.
	UnicodeDomain string `json:"unicode_domain,omitempty"`
	// NotAZone is set when the name is a host inside a zone rather than a
	// zone apex; EnclosingZone names that zone when a SOA revealed it.
	NotAZone       bool     `json:"not_a_zone,omitempty"`
	ReservedName   string   `json:"reserved_name,omitempty"` // the RFC reserving this suffix
	PublicSuffix   bool     `json:"public_suffix,omitempty"` // the name is itself a public suffix, not a registrable domain
	EnclosingZone  string   `json:"enclosing_zone,omitempty"`
	Resolver       string   `json:"resolver"`
	Families       []string `json:"families"`
	TimeoutSec     int      `json:"timeout_sec"`
	TCPTimeoutSec  int      `json:"tcp_timeout_sec"`
	DNSConcurrency int      `json:"dns_concurrency"`
	QuicTimeoutSec int      `json:"quic_timeout_sec"`
	MaxTimeSec     int      `json:"max_time_sec"`
	// RedirectLog says whether redirect chains were followed (-redirectlog).
	// Without it no host carries `redirects`, and no chain finding can fire.
	RedirectLog          bool                 `json:"redirect_log"`
	DNS                  DNSSection           `json:"dns"`
	DNSSEC               DNSSECReport         `json:"dnssec"`
	Delegation           Delegation           `json:"delegation"`
	Web                  WebSection           `json:"web"`
	Certificates         map[string]CertNames `json:"certificates,omitempty"` // by fingerprint_sha256
	Mail                 *MailReport          `json:"mail,omitempty"`
	Nameservers          *NSReport            `json:"nameservers,omitempty"`
	CAA                  *CAAReport           `json:"caa,omitempty"`
	TLSA                 *TLSAReport          `json:"tlsa,omitempty"`
	Wildcard             *WildcardReport      `json:"wildcard,omitempty"`
	ReservedAddresses    []string             `json:"reserved_addresses,omitempty"`
	HSTSPreload          string               `json:"hsts_preload,omitempty"`
	HSTSPreloadCoveredBy string               `json:"hsts_preload_covered_by,omitempty"`
	HSTSPreloadPolicy    string               `json:"hsts_preload_policy,omitempty"`
	HSTSPreloadError     string               `json:"hsts_preload_error,omitempty"`
	// HSTSPreloadIncludeSubdomains is whether the entry that preloads the
	// domain covers its subdomains, www among them; absent when the domain
	// is not preloaded.
	HSTSPreloadIncludeSubdomains *bool    `json:"hsts_preload_include_subdomains,omitempty"`
	Errors                       []string `json:"errors"`
	Warnings                     []string `json:"warnings"`
	// Findings is every result with a stable code and a severity (fail,
	// warn, info). fail entries are exactly Errors and warn entries exactly
	// Warnings, in the same order; info entries appear only here.
	Findings []Finding `json:"findings"`
	OK       bool      `json:"ok"`
	// DeadlineReached is set when the run hit max_time_sec: checks still
	// running then were cut off, and their results say only that.
	DeadlineReached bool  `json:"deadline_reached,omitempty"`
	ElapsedMs       int64 `json:"elapsed_ms"`
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

// CertNames is one certificate's name list, kept once per report.
type CertNames struct {
	SANs []string `json:"sans"`
}

// hoistCertNames moves each certificate's SAN list out of the per-address
// entries into rep.Certificates, keyed by fingerprint. A certificate served
// on many addresses carried its whole list on every one: wikipedia.org's 41
// names on 4 addresses for apex and www made most of a 15 KB report, paid
// for in tokens by every LLM reading it (2026-10-06 tester report). Nothing
// in the findings reads the list; covers_apex and covers_www stay per address.
func hoistCertNames(rep *Report) {
	for _, h := range []*HostWeb{rep.Web.Apex, rep.Web.WWW} {
		for _, a := range h.addrs() {
			if a.TLS == nil || a.TLS.Cert == nil || a.TLS.Cert.Fingerprint == "" {
				continue
			}
			c := a.TLS.Cert
			if rep.Certificates == nil {
				rep.Certificates = map[string]CertNames{}
			}
			if _, seen := rep.Certificates[c.Fingerprint]; !seen {
				rep.Certificates[c.Fingerprint] = CertNames{SANs: nonNil(c.SANs)}
			}
			c.SANs = nil
		}
	}
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

// Finding severities. fail is what makes ok false; warn is a defect worth
// fixing; info is a configuration fact that is normal for some domains
// (no MX, no AAAA, TLS 1.0 kept for legacy clients) and is recorded rather
// than scored. The set is closed: a consumer may treat any other value as
// warn, so adding a tier is a contract change.
const (
	SeverityFail = "fail"
	SeverityWarn = "warn"
	SeverityInfo = "info"
)

// Finding is one structured result. Code is stable once shipped: consumers
// key on it rather than on Message, which is free to be reworded. Host is
// "apex", "www", a nameserver or MX host name, or empty for a finding about
// the domain as a whole.
type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Host     string `json:"host"`
	Message  string `json:"message"`
}

// findings collects results while walking the report. Every finding is
// recorded once in list; fail is mirrored into errors and warn into
// warnings for consumers that read those arrays. info lives in list only:
// a configuration fact is not a warning, and listing it as one is what
// turned well-run domains yellow.
type findings struct {
	errors   []string
	warnings []string
	list     []Finding
}

func (f *findings) add(sev, code, host, format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	f.list = append(f.list, Finding{Code: code, Severity: sev, Host: host, Message: msg})
	switch sev {
	case SeverityFail:
		f.errors = append(f.errors, msg)
	case SeverityWarn:
		f.warnings = append(f.warnings, msg)
	}
}

func (f *findings) fail(code, host, format string, a ...any) {
	f.add(SeverityFail, code, host, format, a...)
}
func (f *findings) warn(code, host, format string, a ...any) {
	f.add(SeverityWarn, code, host, format, a...)
}
func (f *findings) info(code, host, format string, a ...any) {
	f.add(SeverityInfo, code, host, format, a...)
}

// buildFindings fills Errors, Warnings and OK from the rest of the report.
func buildFindings(rep *Report) {
	var f findings
	if zoneUnreachable(rep) {
		// Nothing below the delegation can work, so every other finding
		// would only restate this one. The resolver's own reachability is
		// kept: it is about the probe, not the domain.
		f.reachabilityFindings(rep.DNS.ResolverReachable)
		f.deadlineFindings(rep)
		f.fail("zone_unreachable", "", "no delegated nameserver answers for the zone: %s", describeSilentServers(rep.Nameservers))
		f.finish(rep)
		return
	}
	f.dnsFindings(rep)
	if rep.ReservedName == "" {
		f.dnssecFindings(rep.DNSSEC)
		f.delegationFindings(rep)
	}
	f.reachabilityFindings(rep.DNS.ResolverReachable)
	f.deadlineFindings(rep)
	f.webFindings("apex", rep.Web.Apex)
	f.webFindings("www", rep.Web.WWW)
	f.deepFindings(rep)
	f.finish(rep)
}

// deadlineFindings says when the run was cut off. It is about the probe,
// not the domain, so it is info: each check that did not finish already
// reports its own timeout.
func (f *findings) deadlineFindings(rep *Report) {
	if rep.DeadlineReached {
		f.info("run_deadline_reached", "", "the run reached its %d-second deadline; checks still running then were cut short", rep.MaxTimeSec)
	}
}

// finish copies the collected findings into the report.
func (f *findings) finish(rep *Report) {
	rep.Errors = nonNil(f.errors)
	rep.Warnings = nonNil(f.warnings)
	rep.Findings = f.list
	if rep.Findings == nil {
		rep.Findings = []Finding{}
	}
	rep.OK = len(rep.Errors) == 0
}

// delegationSilent reports whether the trace reached the parent zone, got
// a referral, and then heard nothing from the delegated servers. An empty
// NS answer (NODATA) is an answer and does not count. The parent's referral
// is what shows the probe's own network was working.
func delegationSilent(d Delegation, apexNS Lookup) bool {
	return d.Status == DelegationNoChildAnswer && d.ParentServer != "" && apexNS.Status != StatusNXRRSet
}

// noServerAnswers reports whether the nameserver audit examined the
// delegation and found no server answering for the zone: every address
// silent or refusing, or the name without an address. A name whose
// address lookup did not complete leaves the question open, so it is not
// counted as dead.
func noServerAnswers(n *NSReport) bool {
	if n == nil || len(n.Unresolved) > 0 || len(n.Servers)+len(n.Unresolvable) == 0 {
		return false
	}
	for _, s := range n.Servers {
		if s.Error == "" || s.AA {
			return false
		}
	}
	return true
}

// zoneUnreachable reports whether the zone is dead at the delegation: the
// parent delegates it and no delegated nameserver answers for it. Every
// other check depends on an answer from those servers, so the probe stops
// there and reports this one finding.
func zoneUnreachable(rep *Report) bool {
	return rep.ReservedName == "" && !rep.NotAZone &&
		delegationSilent(rep.Delegation, rep.DNS.Apex["NS"]) && noServerAnswers(rep.Nameservers)
}

// describeSilentServers says what each delegated nameserver did, once per
// name, in the shape the per-server findings use.
func describeSilentServers(n *NSReport) string {
	byName, order := tallyServers(&findings{}, n.Servers)
	var parts []string
	for _, name := range order {
		t := byName[name]
		var what []string
		if t.lame > 0 {
			what = append(what, fmt.Sprintf("%s on %d of %d addresses", t.reason, t.lame, t.total))
		}
		if t.silent > 0 {
			what = append(what, fmt.Sprintf("no answer on %d of %d addresses", t.silent, t.total))
		}
		if t.reserved > 0 {
			what = append(what, fmt.Sprintf("reserved address (%s) on %d of %d addresses", t.resWhy, t.reserved, t.total))
		}
		parts = append(parts, name+" "+strings.Join(what, ", "))
	}
	for _, name := range n.Unresolvable {
		parts = append(parts, name+" has no address")
	}
	return strings.Join(parts, "; ")
}

func (f *findings) dnsFindings(rep *Report) {
	apex := rep.DNS.Apex
	// A name with nothing at it is one fact, and the rest of the checks
	// only restate it. A reserved name is excluded: not existing in the
	// global DNS is the definition of the name, not a fault in it.
	if rep.ReservedName == "" && f.apexMissing(rep) {
		return
	}
	// A bogus or SERVFAIL verdict already explains every failed lookup.
	// A reserved name folds its lookup failures the way a bogus zone does:
	// they are all the one fact that the name is not in the global DNS.
	folded := rep.DNSSEC.State == DNSSECBogus || rep.DNSSEC.State == DNSSECServfail || rep.ReservedName != ""
	for _, t := range apexTypes {
		f.lookupFindings("apex", t, apex[t], folded)
	}
	for _, t := range wwwTypes {
		f.lookupFindings("www", t, rep.DNS.WWW[t], folded)
	}
	f.zoneKindFindings(rep)
	f.presenceWarnings(rep)
}

// apexMissing reports, and says, when the apex does not exist or has
// nothing at it.
func (f *findings) apexMissing(rep *Report) bool {
	apex := rep.DNS.Apex
	switch {
	case apex["NS"].Status == StatusNXDomain || apex["A"].Status == StatusNXDomain:
		f.fail("apex_nxdomain", "apex", "apex %s does not exist (NXDOMAIN)", rep.Domain)
		return true
	case noRecordsAtAll(apex):
		// The zone denied every type without saying NXDOMAIN, which is
		// what compact denial of existence looks like: Cloudflare and
		// other signed zones answer NODATA rather than admit a name is
		// absent. The name has nothing either way, and the verdict must
		// follow that fact rather than the phrasing of the denial.
		f.fail("apex_empty", "apex", "apex %s has no records of any type", rep.Domain)
		return true
	}
	return false
}

// zoneKindFindings says what kind of name this is when it is not an
// ordinary zone apex, and fails a zone apex without NS records.
func (f *findings) zoneKindFindings(rep *Report) {
	apex := rep.DNS.Apex
	switch {
	case rep.ReservedName != "":
		// A warning, not info: nothing about the name can be checked
		// publicly, and an all-quiet report would read as a healthy domain
		// (2026-10-06 tester report). Not a fail, so ok stays true.
		f.warn("reserved_name", "", "%s is reserved by %s and is not served by the global DNS: delegation and DNSSEC checks do not apply", rep.Domain, rep.ReservedName)
	case rep.NotAZone:
		f.info("not_a_zone", "", "%s is not a zone apex%s: delegation and DNSSEC zone checks skipped", rep.Domain, enclosing(rep.EnclosingZone))
	case rep.Delegation.Status == DelegationChildNoNS, rep.Delegation.Status == DelegationNoChildAnswer:
		// the delegation finding already says the zone has no NS RRset
	case !apex["NS"].HasRecords() && apex["NS"].Answered():
		f.fail("ns_absent", "apex", "apex has no NS records")
	}
}

// noRecordsAtAll reports whether every apex lookup answered and none of
// them returned a record. A name someone created has at least one record
// of some type: a mail-only host still has an MX, a verification host
// still has a TXT. Requiring every lookup to have answered keeps a failed
// probe from being read as an empty name.
func noRecordsAtAll(apex map[string]Lookup) bool {
	for _, t := range apexTypes {
		l := apex[t]
		if !l.Answered() || l.HasRecords() {
			return false
		}
	}
	return true
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
		f.fail("lookup_timeout", label, "%s %s lookup timed out", label, qtype)
	case StatusFailure:
		if !folded {
			f.fail("lookup_failed", label, "%s %s lookup failed: %s", label, qtype, l.Error)
		}
	}
}

// presenceWarnings flags missing records. Only lookups that actually
// answered count; failures and timeouts are reported as errors elsewhere.
func (f *findings) presenceWarnings(rep *Report) {
	apex, www := rep.DNS.Apex, rep.DNS.WWW
	f.addressWarnings("apex", apex["A"], apex["AAAA"])
	if registrableDomain(rep.Domain) {
		f.addressWarnings("www", www["A"], www["AAAA"])
	}
	// Mail-shaped warnings only make sense where a mail section does. A
	// registry suffix, a host inside a zone and a name that cannot exist
	// all have nobody to act on them.
	if rep.Mail == nil {
		return
	}
	switch {
	case apex["MX"].IsNullMX():
		f.info("mx_null", "apex", "apex publishes a null MX (RFC 7505): accepts no mail")
	case apex["MX"].Answered() && !apex["MX"].HasRecords():
		f.info("mx_absent", "apex", "apex has no MX records")
	}
	if apex["TXT"].Answered() && !hasSPF(apex["TXT"].Records) {
		f.warn("spf_absent", "", "no SPF (v=spf1) record in apex TXT")
	}
}

func (f *findings) addressWarnings(label string, a, aaaa Lookup) {
	if !a.Answered() || !aaaa.Answered() {
		return
	}
	switch {
	case a.Status == StatusNXDomain:
		f.info(nxdomainCode(label), label, "%s name does not exist", label)
	case !a.HasRecords() && !aaaa.HasRecords():
		f.noAddress(label)
	case !aaaa.HasRecords():
		f.info("aaaa_absent", label, "%s has no AAAA record", label)
	}
}

// nxdomainCode names a missing host. Only www, or the apex of a reserved
// name, reaches it: a missing apex anywhere else already failed as
// apex_nxdomain.
func nxdomainCode(label string) string {
	if label == "www" {
		return "www_nxdomain"
	}
	return "reserved_nxdomain"
}

// noAddress: an apex with no address serves no web at all, which is worth
// a warning; a www with none is a choice many domains make.
func (f *findings) noAddress(label string) {
	if label == "www" {
		f.info("www_no_address", label, "%s has no A or AAAA records", label)
		return
	}
	f.warn("apex_no_address", label, "%s has no A or AAAA records", label)
}

func hasSPF(txt []string) bool {
	for _, t := range txt {
		if isSPFRecord(t) {
			return true
		}
	}
	return false
}

func (f *findings) dnssecFindings(d DNSSECReport) {
	switch d.State {
	case DNSSECBogus:
		f.fail("dnssec_bogus", "", "DNSSEC validation fails (bogus): %s", firstNonEmpty(d.EDE, d.Detail))
	case DNSSECServfail:
		f.fail("resolver_servfail", "", "resolver returned SERVFAIL: %s", firstNonEmpty(d.EDE, d.Detail))
	case DNSSECIsland:
		f.warn("dnssec_dnskey_no_ds", "", "DNSSEC: %s", d.Detail)
	case DNSSECUnknown:
		f.warn("dnssec_unknown", "", "DNSSEC state unknown: %s", d.Detail)
	}
}

func (f *findings) delegationFindings(rep *Report) {
	d := rep.Delegation
	switch d.Status {
	case DelegationMismatch:
		f.fail("delegation_mismatch", "", "NS delegation mismatch: parent-only %v, child-only %v", d.ParentOnly, d.ChildOnly)
	case DelegationNotDelegated:
		f.fail("not_delegated", "", "domain is not delegated by its parent zone (%s)", d.ParentServer)
	case DelegationNoChildAnswer:
		// NOERROR with an empty answer is an answer. Saying the servers
		// did not respond sends an operator after a reachability problem
		// when the zone simply has no apex NS RRset.
		if rep.DNS.Apex["NS"].Status == StatusNXRRSet {
			f.fail("delegation_nodata", "", "delegated NS servers answered with no NS records (NODATA): the zone has no apex NS RRset")
			break
		}
		f.fail("delegation_no_answer", "", "delegated NS servers did not answer the NS query: %s", firstNonEmpty(d.Error, "no response"))
	case DelegationChildNoNS:
		f.fail("delegation_lame", "", "lame delegation: %s", d.Error)
	case DelegationError:
		f.fail("delegation_trace_failed", "", "delegation trace failed: %s", d.Error)
	}
}

func (f *findings) reachabilityFindings(reach map[string]string) {
	for _, fam := range sortedKeys(reach) {
		if reach[fam] == ReachNo {
			f.fail("resolver_unreachable", "", "resolver not reachable over %s", fam)
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
		f.listenerFindings(label, a)
	}
	f.quicFindings(label, addrs)
}

// listenerFindings reports an address that answered on neither port, or
// on 80 only.
func (f *findings) listenerFindings(label string, a AddrWeb) {
	switch {
	case a.HTTP == PortSkipped && a.HTTPS == PortSkipped:
		// Not a connectivity failure: the probe declined to connect
		// because the address is reserved. Reporting it as "no
		// listener" sends anyone triaging it after a problem that
		// does not exist.
		f.info("address_not_probed_reserved", label, "%s %s: not probed (reserved address)", label, a.IP)
	case a.HTTP != PortOpen && a.HTTPS != PortOpen:
		f.warn("web_no_listener", label, "%s %s: no listener on 80 or 443 (%s/%s)", label, a.IP, a.HTTP, a.HTTPS)
	case a.HTTPS != PortOpen && a.HTTPRes != nil && probeRefused(a.HTTPRes.Status):
		// 80 refused the probe, so 443 failing on the same address is as
		// likely the same refusal (a block on the probe's network drops
		// the TLS handshake too) as a missing HTTPS service. Neither port
		// was verified; say that, not that HTTPS is missing.
		f.info("https_not_verified", label, "%s %s: HTTP on 80 refused the probe (HTTP %d) and HTTPS on 443 did not answer (%s), so neither was verified", label, a.IP, a.HTTPRes.Status, a.HTTPS)
	case a.HTTPS != PortOpen:
		f.warn("https_unreachable", label, "%s %s: HTTP on 80 answers but HTTPS on 443 does not (%s)", label, a.IP, a.HTTPS)
	}
}

// quicFindings notes the addresses without QUIC on a host where another
// address has it.
func (f *findings) quicFindings(label string, addrs []AddrWeb) {
	if !anyQUIC(addrs) {
		return
	}
	for _, a := range addrs {
		if a.QUIC != nil && !a.QUIC.Supported {
			f.info("quic_partial", label, "%s %s: QUIC/h3 works on another probed address of this host but not here", label, a.IP)
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
	apexPreloaded, wwwPreloaded := preloadCovers(rep)
	f.httpFindings("apex", rep.Web.Apex, apexPreloaded)
	f.httpFindings("www", rep.Web.WWW, wwwPreloaded)
	f.consistencyFindings(rep)
	f.mailFindings(rep.Mail, zoneValidationBroken(rep))
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
		f.fail("reserved_address", "", "reserved address published in DNS: %s", r)
	}
}

func (f *findings) wildcardFindings(rep *Report) {
	// www is only probed beside a registrable domain; under a host inside
	// a zone (app.example.com) www.app.example.com is nobody's name.
	if rep.Wildcard != nil && rep.Wildcard.WWWViaWildcard && registrableDomain(rep.Domain) {
		f.info("www_wildcard", "www", "www is answered by a wildcard record, not a real host")
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
	// cert_consistent records whether the leaves are identical. A CDN
	// rotating valid certificates across its fleet serves different leaves
	// to no effect on any client, so only a difference a client would see
	// is a warning: one address's chain failing where another's passes, or
	// covering other names.
	if h.CertConsistent != nil && !*h.CertConsistent && certProfilesDiffer(addrs) {
		f.warn("cert_mismatch_between_addresses", label, "%s: addresses serve certificates that differ in validity or in the names they cover", label)
	}
}

// certProfilesDiffer reports whether addresses differ in what their
// certificates mean to a client: the chain verdict, or whether the leaf
// covers the apex and www.
func certProfilesDiffer(addrs []AddrWeb) bool {
	first := ""
	for _, a := range addrs {
		if a.TLS == nil || a.TLS.Cert == nil {
			continue
		}
		p := fmt.Sprintf("%s/%t/%t", a.TLS.Chain, a.TLS.Cert.CoversApex, a.TLS.Cert.CoversWWW)
		if first != "" && p != first {
			return true
		}
		first = p
	}
	return false
}

// chainFindings reports each distinct chain problem once for the host,
// with the count of addresses it affected, the way the nameserver audit
// reports a failing name. A CDN fleet that all fails the same way is one
// fact, not fourteen; the per-address detail stays in the web section.
// chainLabel names every defect, so a certificate that is both expired and
// served for the wrong name says so in one finding.
func chainLabel(t *TLSResult) string {
	if len(t.Problems) < 2 {
		return strings.ReplaceAll(t.Chain, "_", " ")
	}
	parts := make([]string, 0, len(t.Problems))
	for _, p := range t.Problems {
		parts = append(parts, strings.ReplaceAll(p, "_", " "))
	}
	return strings.Join(parts, " and ")
}

func (f *findings) chainFindings(label string, addrs []AddrWeb) {
	type tally struct {
		code, chain, detail string
		count               int
	}
	byCause := map[string]*tally{}
	var order []string
	for _, a := range addrs {
		if a.TLS.Chain == ChainValid {
			continue
		}
		key := a.TLS.Chain + "\x00" + a.TLS.Error + "\x00" + strings.Join(a.TLS.Problems, ",")
		if byCause[key] == nil {
			byCause[key] = &tally{code: "cert_" + a.TLS.Chain, chain: chainLabel(a.TLS), detail: a.TLS.Error}
			order = append(order, key)
		}
		byCause[key].count++
	}
	for _, key := range order {
		t := byCause[key]
		f.fail(t.code, label, "%s: certificate %s on %d of %d addresses: %s", label,
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
		f.warn("cert_expiry_urgent", label, "%s: certificate expires in %d days (urgent)", label, soonest)
	default:
		f.info("cert_expiry_soon", label, "%s: certificate expires in %d days", label, soonest)
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
			f.warn("cert_sibling_uncovered", label, "%s: certificate does not cover %s, which resolves but has no valid certificate", label, other)
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

func isTrue(b *bool) bool { return b != nil && *b }

// versionFindings aggregates protocol facts per host.
func (f *findings) versionFindings(label string, addrs []AddrWeb) {
	old10, old11, no13, total := 0, 0, 0, 0
	for _, a := range addrs {
		if a.TLS.Chain == ChainHandshakeFailed {
			continue
		}
		total++
		if isTrue(a.TLS.TLS10) {
			old10++
		}
		if isTrue(a.TLS.TLS11) {
			old11++
		}
		if a.TLS.Version != "" && a.TLS.Version != "TLS 1.3" {
			no13++
		}
	}
	if old10+old11 > 0 {
		f.info("tls_legacy_versions", label, "%s: TLS 1.0/1.1 still accepted on %d of %d addresses", label, maxInt(old10, old11), total)
	}
	if no13 > 0 {
		f.info("tls13_absent", label, "%s: no TLS 1.3 on %d of %d addresses", label, no13, total)
	}
}

// httpFindings judges status codes per port, clear-text serving, redirect
// chains and HSTS strength for one host.
//
// preloaded says the HSTS preload list covers this host, so browsers never
// send it a plain-HTTP request and port 80's behaviour is a fact, not a gap.
func (f *findings) httpFindings(label string, h *HostWeb, preloaded bool) {
	if h == nil {
		return
	}
	addrs := h.addrs()
	f.statusFindings(label, "80", addrs, func(a AddrWeb) *HTTPResult { return a.HTTPRes })
	f.statusFindings(label, "443", addrs, func(a AddrWeb) *HTTPResult { return a.HTTPSRes })
	f.cleartextFindings(label, addrs, preloaded)
	f.redirectFindings(label, h.Redirects)
	f.hstsFindings(label, addrs)
}

// statusFindings: every address ≥ 500 is an error, some is a warning, every
// address 4xx is a warning.
func (f *findings) statusFindings(label, port string, addrs []AddrWeb, pick func(AddrWeb) *HTTPResult) {
	t := tallyStatuses(addrs, pick)
	switch {
	case t.total == 0:
	case t.server5xx == t.total:
		f.fail("http_server_error", label, "%s: every address returns a server error on port %s", label, port)
	case t.server5xx > 0:
		f.warn("http_server_error_partial", label, "%s: %d of %d addresses return a server error on port %s", label, t.server5xx, t.total, port)
	case len(t.refusals) == t.total:
		f.info("http_probe_refused", label, "%s: every address refuses the probe on port %s (HTTP %s), so the content was not verified", label, port, distinctStatuses(t.refusals))
	case t.client4xx+len(t.refusals) == t.total:
		f.warn("http_client_error", label, "%s: every address returns a client error on port %s", label, port)
	}
}

// statusTally counts one port's answers across a host's addresses.
// refusals holds the status of each address that refused the probe.
type statusTally struct {
	total, server5xx, client4xx int
	refusals                    []int
}

func tallyStatuses(addrs []AddrWeb, pick func(AddrWeb) *HTTPResult) statusTally {
	var t statusTally
	for _, a := range addrs {
		r := pick(a)
		if r == nil || r.Status == 0 {
			continue
		}
		t.total++
		switch {
		case r.Status >= 500:
			t.server5xx++
		case probeRefused(r.Status):
			t.refusals = append(t.refusals, r.Status)
		case r.Status >= 400:
			t.client4xx++
		}
	}
	return t
}

// distinctStatuses lists the status codes seen, once each, in order.
func distinctStatuses(statuses []int) string {
	sort.Ints(statuses)
	var parts []string
	for i, s := range statuses {
		if i == 0 || s != statuses[i-1] {
			parts = append(parts, strconv.Itoa(s))
		}
	}
	return strings.Join(parts, "/")
}

// probeRefused reports whether a status says the server declined to serve
// this request rather than that the resource is broken: authentication
// demanded, a WAF or bot filter answering 403, or a rate limit. Why it
// declined is not observable from here: a bot filter judging the client, a
// block on the probe's source network (1-800-chase-credit-cards.com refused
// the worker's AWS address with the same request that linserver was served),
// or a page that really is private. So the status says nothing about the
// site's health, and the findings built on it state only what was seen. 404
// and 410 are not here: those are a broken link whoever asks.
func probeRefused(status int) bool {
	switch status {
	case 401, 403, 407, 417, 429:
		return true
	}
	return false
}

// preloadCovers reports whether the HSTS preload list covers the apex and
// the www host. www is covered when the entry that preloads the apex
// includes subdomains: an ancestor entry always does, and the apex's own
// entry does when it says so (every hstspreload.org submission must).
func preloadCovers(rep *Report) (apex, www bool) {
	if rep.HSTSPreload != PreloadPreloaded {
		return false, false
	}
	return true, rep.HSTSPreloadCoveredBy != "" || isTrue(rep.HSTSPreloadIncludeSubdomains)
}

// cleartextFindings warns once per host when port 80 serves content or
// redirects somewhere that is not https.
//
// Serving content in the clear on a preloaded host is info: no browser
// will ever make that request.
func (f *findings) cleartextFindings(label string, addrs []AddrWeb, preloaded bool) {
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
	// A code keeps one severity, so the preloaded case is its own code.
	sev, suffix := SeverityWarn, ""
	if preloaded {
		sev, suffix = SeverityInfo, "_preloaded"
	}
	if served > 0 {
		f.add(sev, "http_cleartext"+suffix, label, "%s: HTTP serves content in the clear instead of redirecting to HTTPS (%d of %d addresses)", label, served, total)
	}
	if elsewhere > 0 {
		f.add(sev, "http_redirect_insecure"+suffix, label, "%s: HTTP redirects to a non-HTTPS URL (%d of %d addresses)", label, elsewhere, total)
	}
}

func (f *findings) redirectFindings(label string, chains map[string]*RedirectChain) {
	// Families whose chains looped the same way are one finding: listing
	// the identical loop once per family only repeats it.
	loops := map[string][]string{}
	var order []string
	for _, fam := range sortedChainKeys(chains) {
		d, looped := f.chainFinding(label, fam, chains[fam])
		if !looped {
			continue
		}
		if _, ok := loops[d]; !ok {
			order = append(order, d)
		}
		loops[d] = append(loops[d], fam)
	}
	f.downgradeFindings(label, chains)
	for _, d := range order {
		// A loop is what the server sent during this run. A server that
		// answers the same URL differently from one request to the next
		// may not loop on another run; http_response_inconsistent says
		// when this run itself saw that.
		f.fail("redirect_loop", label, "%s (%s): redirect loop %s", label, strings.Join(loops[d], ", "), d)
	}
}

// downgradeFindings reports a chain that went from https back to http:
// whatever HSTS and the scheme upgrade protected is given up at that hop.
// Families that downgraded at the same hop are one finding.
func (f *findings) downgradeFindings(label string, chains map[string]*RedirectChain) {
	byHop := map[string][]string{}
	var order []string
	for _, fam := range sortedChainKeys(chains) {
		hop := downgradeHop(chains[fam].Hops)
		if hop == "" {
			continue
		}
		if _, ok := byHop[hop]; !ok {
			order = append(order, hop)
		}
		byHop[hop] = append(byHop[hop], fam)
	}
	for _, hop := range order {
		f.warn("redirect_downgrade", label, "%s (%s): redirect from https to http: %s", label, strings.Join(byHop[hop], ", "), hop)
	}
}

// downgradeHop is the first hop whose https URL redirected to an http
// one, as "from -> to", or "".
func downgradeHop(hops []RedirectHop) string {
	for _, h := range hops {
		from, err := url.Parse(h.URL)
		if err != nil || from.Scheme != "https" || !isRedirect(h.Status) || h.Location == "" {
			continue
		}
		to, err := from.Parse(h.Location)
		if err == nil && to.Scheme == "http" {
			return h.URL + " -> " + to.String()
		}
	}
	return ""
}

// chainFinding reports how one family's chain ended. A loop is returned
// rather than reported, so that identical loops can be merged.
func (f *findings) chainFinding(label, fam string, c *RedirectChain) (loop string, looped bool) {
	switch {
	case len(c.Hops) == 0:
		// The entry point did not answer; port 80's state already says so.
	case c.Loop || c.Ended == RedirectLoop:
		return describeHops(c.Hops) + loopTarget(c.Hops), true
	case c.Ended == RedirectHopLimit:
		// We stopped following, so whether the chain ends is unknown.
		// Asserting a fault from that is the vacuous negative again.
		f.warn("redirect_hop_limit", label, "%s (%s): still redirecting after %d hops, so the destination is unknown: %s", label, fam, len(c.Hops), describeHops(c.Hops))
	case c.Error != "":
		f.warn("redirect_broken", label, "%s (%s): redirect chain broke: %s", label, fam, c.Error)
	case probeRefused(c.Hops[len(c.Hops)-1].Status):
		f.info("http_probe_refused", label, "%s (%s): redirect chain ends in HTTP %d at %s: the server refused the probe, so the destination was not verified", label, fam, c.Hops[len(c.Hops)-1].Status, c.FinalURL)
	case c.Hops[len(c.Hops)-1].Status >= 400:
		f.warn("redirect_ends_error", label, "%s (%s): redirect chain ends in HTTP %d at %s", label, fam, c.Hops[len(c.Hops)-1].Status, c.FinalURL)
	}
	return "", false
}

// consistencyFindings compares every response the run saw for one URL:
// the per-address probes and the redirect-chain hops ask the same
// question, and a server that gives more than one answer to it is
// reported, as is a probe sent back to the URL it asked for. Nothing is
// fetched again; this is the run's own evidence.
func (f *findings) consistencyFindings(rep *Report) {
	for _, g := range collectWebObservations(rep.Domain, rep.Web) {
		if tally := answerTally(g.obs); len(tally) > 1 {
			f.warn("http_response_inconsistent", g.host, "%s: %s answered differently within one run: %s", g.host, g.url, strings.Join(tally, "; "))
		}
		if self, probes := selfRedirects(g.obs); len(self) > 0 {
			f.fail("redirect_self", g.host, "%s: %s redirects to itself on %s", g.host, g.url, describeSources(self, probes))
		}
	}
}

// loopTarget names where the last hop pointed, the URL already visited,
// so the message shows the cycle closing rather than leaving it implied.
func loopTarget(hops []RedirectHop) string {
	if len(hops) == 0 || hops[len(hops)-1].Location == "" {
		return ""
	}
	return " -> " + hops[len(hops)-1].Location
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
		f.info("hsts_short_max_age", label, "%s: HSTS max-age %d is under 180 days", label, shortest)
	}
}

// mailFindings covers DMARC, SPF, MX, DKIM and MTA-STS.
// zoneValidationBroken reports a bogus or SERVFAIL DNSSEC verdict: every
// lookup inside the zone fails for that one reason, already reported.
func zoneValidationBroken(rep *Report) bool {
	return rep.DNSSEC.State == DNSSECBogus || rep.DNSSEC.State == DNSSECServfail
}

// mailFindings judges the mail posture. zoneBroken folds a DMARC lookup that
// did not complete into the DNSSEC verdict: _dmarc.<domain> is inside the
// zone, so its failure only restates it (2026-10-06 tester report). MX
// targets and SPF includes usually live in other zones, so theirs stand.
func (f *findings) mailFindings(m *MailReport, zoneBroken bool) {
	if m == nil {
		return
	}
	if !(zoneBroken && m.DMARC.Unresolved) {
		f.dmarcFindings(m.DMARC)
	}
	f.spfFindings(m.SPF)
	for _, mx := range m.MX {
		for _, p := range mx.Problems {
			if mx.Unresolved && p == mxUnresolvedProblem {
				f.warn("mx_target_unresolved", mx.Host, "MX %s: %s", mx.Host, p)
				continue
			}
			f.fail(mxProblemCode(p), mx.Host, "MX %s: %s", mx.Host, p)
		}
	}
	if m.DKIM.Wildcard {
		f.warn("dkim_wildcard", "", "the zone answers every _domainkey selector (wildcard), so no selector could be verified")
	}
	for _, sel := range m.DKIM.Revoked {
		f.warn("dkim_selector_revoked", "", "DKIM selector %s publishes a revoked (empty) key", sel)
	}
	f.mtaSTSFindings(m.MTASTS)
}

func (f *findings) dmarcFindings(d DMARC) {
	switch {
	case d.Unresolved:
		f.warn("dmarc_unknown", "", "the DMARC lookup did not complete, so whether a record exists is unknown")
	case !d.Present:
		f.warn("dmarc_absent", "", "no DMARC record")
		return
	case d.Policy == "none":
		f.info("dmarc_policy_none", "", "DMARC policy is p=none (monitor only)")
	}
	if d.Pct < 100 {
		f.info("dmarc_partial_pct", "", "DMARC applies to only %d%% of mail (pct=%d)", d.Pct, d.Pct)
	}
	for _, p := range d.Problems {
		code, sev := dmarcProblemClass(p)
		f.add(sev, code, "", "DMARC: %s", p)
	}
}

// spfFindings maps evaluator problems to codes and severities: anything
// that makes SPF fail outright or authorise everyone fails.
func (f *findings) spfFindings(s SPFResult) {
	for _, p := range s.Problems {
		code, sev := spfProblemClass(p)
		f.add(sev, code, "", "SPF: %s", p)
	}
}

// spfClass gives a code and severity to the evaluator problems that start
// with prefix and contain substr (either may be empty).
type spfClass struct {
	prefix, substr, code, sev string
}

// spfClasses covers every problem the SPF evaluator emits, first match
// wins. Failing outright (permerror) or authorising every sender fails;
// the RFC 7208 §3.4 answer size is a fact about resolvers without EDNS and
// is recorded as info.
var spfClasses = []spfClass{
	{prefix: "multiple SPF records", code: "spf_multiple", sev: SeverityFail},
	{substr: "DNS lookups exceed the limit", code: "spf_lookup_limit", sev: SeverityFail},
	{substr: "void lookups exceed the limit", code: "spf_void_limit", sev: SeverityWarn},
	{prefix: "record has no all mechanism", code: "spf_no_all", sev: SeverityWarn},
	{prefix: "ptr mechanism is deprecated", code: "spf_ptr_deprecated", sev: SeverityWarn},
	{prefix: "unknown mechanism", code: "spf_unknown_mechanism", sev: SeverityFail},
	{prefix: "+all", code: "spf_pass_all", sev: SeverityFail},
	{prefix: "?all", code: "spf_neutral_all", sev: SeverityWarn},
	{prefix: "apex TXT answer is", substr: ", over the ", code: "spf_txt_over_udp_limit", sev: SeverityInfo},
	{prefix: "apex TXT answer is", code: "spf_txt_near_udp_limit", sev: SeverityInfo},
	{prefix: "include:", substr: " TXT answer is ", code: "spf_include_txt_over_udp_limit", sev: SeverityInfo},
	{prefix: "include:", substr: " is not a valid domain name", code: "spf_include_invalid", sev: SeverityWarn},
	{prefix: "include:", substr: " has no SPF record", code: "spf_include_missing", sev: SeverityWarn},
	{prefix: "include:", substr: " could not be checked", code: "spf_include_unchecked", sev: SeverityWarn},
	{prefix: "include loop ", code: "spf_include_loop", sev: SeverityFail},
}

// spfProblemClass returns the code and severity of one SPF problem. An
// unrecognised problem keeps the rule this replaced: permerror fails, the
// rest warn.
func spfProblemClass(p string) (code, sev string) {
	for _, c := range spfClasses {
		if strings.HasPrefix(p, c.prefix) && strings.Contains(p, c.substr) {
			return c.code, c.sev
		}
	}
	if strings.Contains(p, "permerror") {
		return "spf_invalid", SeverityFail
	}
	return "spf_problem", SeverityWarn
}

// mxProblemCode names one MX problem; every one of them fails.
func mxProblemCode(p string) string {
	switch {
	case strings.HasPrefix(p, "null MX mixed"):
		return "mx_null_mixed"
	case strings.HasPrefix(p, "MX target is not a valid hostname"):
		return "mx_target_invalid"
	case strings.HasPrefix(p, "MX target is an IP literal"):
		return "mx_target_ip_literal"
	case strings.HasPrefix(p, "MX target is a CNAME"):
		return "mx_target_cname"
	case p == "MX target does not exist":
		return "mx_target_nxdomain"
	case p == "MX target has no address":
		return "mx_target_no_address"
	}
	return "mx_invalid"
}

// dmarcProblemClass names one DMARC record problem and its severity.
// A malformed pct or sp leaves the record's policy in force, so those are
// warnings; anything that makes receivers ignore the record fails.
func dmarcProblemClass(p string) (code, sev string) {
	switch {
	case strings.HasPrefix(p, "multiple DMARC records"):
		return "dmarc_multiple", SeverityFail
	case p == "missing p= tag":
		return "dmarc_policy_missing", SeverityFail
	case strings.HasPrefix(p, "unknown policy"):
		return "dmarc_policy_unknown", SeverityFail
	case strings.HasPrefix(p, "unknown subdomain policy"):
		return "dmarc_subdomain_policy_unknown", SeverityWarn
	case strings.HasPrefix(p, "invalid pct="):
		return "dmarc_pct_invalid", SeverityWarn
	}
	return "dmarc_invalid", SeverityFail
}

func (f *findings) mtaSTSFindings(m *MTASTS) {
	if m == nil || !m.Record {
		return
	}
	// A code keeps one severity, so enforce mode has its own codes.
	sev, prefix := SeverityWarn, "mta_sts_"
	if m.Mode == "enforce" {
		sev, prefix = SeverityFail, "mta_sts_enforce_"
	}
	switch {
	case m.Error != "":
		f.add(sev, prefix+"failed", "", "MTA-STS: %s", m.Error)
	case !m.MXCovered && m.Mode != "none":
		// mode none withdraws the policy (RFC 8461 §5): its mx lines
		// govern nothing.
		f.add(sev, prefix+"mx_uncovered", "", "MTA-STS policy mx patterns do not cover every MX host")
	}
}

// nsFindings covers count, resolution, per-server behaviour, serials,
// diversity and glue.
func (f *findings) nsFindings(n *NSReport) {
	if n == nil {
		return
	}
	if n.Count < 2 {
		f.fail("ns_count_low", "", "only %d nameserver (at least two required)", n.Count)
	}
	for _, name := range n.NSCNAME {
		f.fail("ns_cname", name, "nameserver %s is a CNAME (RFC 2181 §10.3)", name)
	}
	for _, name := range n.Unresolvable {
		f.fail("ns_no_address", name, "nameserver %s has no address", name)
	}
	for _, name := range n.Unresolved {
		f.warn("ns_unaudited", name, "nameserver %s: the address lookup did not complete, so it was not audited", name)
	}
	if len(n.Servers) == 0 {
		f.warn("ns_none_reached", "", "no nameserver was reached, so none of the per-server checks ran")
	}
	f.serverFindings(n.Servers)
	if n.SerialsConsistent != nil && !*n.SerialsConsistent {
		f.info("soa_serial_differs", "", "SOA serial differs between nameservers: %s", serialList(n.Servers))
	}
	f.diversityFindings(n)
	f.glueFindings(n.Glue)
}

// nsTally counts the addresses of one nameserver name, keeping the two
// kinds of failure apart: a server that answered and disclaimed authority
// is a different fact from one that said nothing at all.
type nsTally struct {
	total    int
	lame     int    // answered, and not authoritative
	silent   int    // never answered
	reserved int    // a reserved address, not queried
	reason   string // why the lame ones are lame
	resWhy   string // why the reserved ones are reserved
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
		case s.Reserved != "":
			t.reserved++
			t.resWhy = firstNonEmpty(t.resWhy, s.Reserved)
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
	if t.reserved > 0 {
		f.fail("ns_reserved_address", name, "nameserver %s: reserved address (%s) on %d of %d addresses, not queried", name, t.resWhy, t.reserved, t.total)
	}
	if t.lame > 0 {
		f.fail("ns_lame", name, "nameserver %s: %s on %d of %d addresses", name, t.reason, t.lame, t.total)
	}
	switch {
	case t.silent > 0 && t.silent == t.total:
		f.fail("ns_no_answer", name, "nameserver %s: no answer on %d of %d addresses", name, t.silent, t.total)
	case t.silent > 0:
		f.warn("ns_partial_answer", name, "nameserver %s: no answer on %d of %d addresses, the others are authoritative", name, t.silent, t.total)
	}
}

func (f *findings) serverWarnings(s NSServer) {
	if !s.TCP {
		f.warn("ns_no_tcp", s.Name, "nameserver %s (%s): no answer over TCP", s.Name, s.IP)
	}
	if !s.EDNS {
		f.warn("ns_no_edns", s.Name, "nameserver %s (%s): no EDNS support", s.Name, s.IP)
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
// serverFamilies counts the audited nameserver addresses per family.
func serverFamilies(servers []NSServer) (v4, v6 int) {
	for _, s := range servers {
		ip, err := netip.ParseAddr(s.IP)
		switch {
		case err != nil:
		case ip.Is4():
			v4++
		default:
			v6++
		}
	}
	return v4, v6
}

func (f *findings) diversityFindings(n *NSReport) {
	if n.IPv4Prefixes24 == nil || n.IPv6Prefixes48 == nil {
		return
	}
	v4, v6 := serverFamilies(n.Servers)
	if v4 >= 2 && *n.IPv4Prefixes24 == 1 {
		f.warn("ns_same_v4_24", "", "all IPv4 nameserver addresses share one /24")
	}
	if v6 >= 2 && *n.IPv6Prefixes48 == 1 {
		f.info("ns_same_v6_48", "", "all IPv6 nameserver addresses share one /48")
	}
}

func (f *findings) glueFindings(g *GlueReport) {
	if g == nil {
		return
	}
	for _, name := range g.Missing {
		f.fail("glue_missing", name, "no glue at the parent for in-bailiwick nameserver %s", name)
	}
	for _, m := range g.Mismatch {
		f.warn("glue_differs", "", "glue at the parent differs from the zone for %s", m)
	}
}

func (f *findings) caaFindings(c *CAAReport) {
	if c == nil {
		return
	}
	for _, label := range []string{"apex", "www"} {
		if v := c.Hosts[label]; v != nil && v.Permitted != nil && !*v.Permitted {
			f.fail("caa_issuer_denied", label, "%s: CAA records do not permit the certificate issuer %q", label, v.Issuer)
		}
	}
}

// preloadMinAge is the max-age the HSTS preload list requires.
const preloadMinAge = 31536000

// preloadFindings cross-checks the preload-list status with the header
// actually served on the apex.
func (f *findings) preloadFindings(rep *Report) {
	h := servedHSTS(rep.Web.Apex)
	switch rep.HSTSPreload {
	case PreloadPreloaded:
		f.preloadedFindings(rep, h)
	case PreloadAbsent:
		if h != nil && h.Preload && !meetsPreload(h) {
			f.info("hsts_preload_directive_unmet", "apex", "HSTS header carries the preload directive but does not meet the preload requirements (max-age >= 1 year, includeSubDomains)")
		}
	case PreloadUnknown:
		f.info("hsts_preload_unknown", "", "HSTS preload list could not be consulted: %s", rep.HSTSPreloadError)
	}
}

// preloadedFindings holds a preloaded domain to the header requirement,
// which only entries submitted through hstspreload.org carry. Hand-kept
// entries (policy google, custom, public-suffix) stay preloaded whatever
// they serve, so a missing header there is a fact in the report and not a
// warning.
func (f *findings) preloadedFindings(rep *Report, h *HSTS) {
	// The header requirement belongs to the entry. A name covered by an
	// ancestor's include_subdomains owes nothing on its own response.
	if !headerRequired(rep.HSTSPreloadPolicy) || rep.HSTSPreloadCoveredBy != "" {
		return
	}
	first := firstHTTPSResponse(rep.Web.Apex)
	switch {
	case h == nil && first == nil:
		// Nothing answered on 443, so there is no response to have carried
		// a header and nothing to report either way.
	case h == nil:
		// "No longer meets" implies a header we could measure. Saying so
		// when none was served points at the wrong fix.
		f.warn("hsts_preload_header_missing", "apex", "domain is on the HSTS preload list but serves no HSTS header on this response (%s)", responseScope(rep.Domain, first))
	case !meetsPreload(h):
		f.warn("hsts_preload_header_weak", "apex", "domain is on the HSTS preload list but the served header does not meet the preload requirements (max-age >= 1 year, includeSubDomains, preload)")
	}
}

// responseScope says which response the header was looked for on. Redirects
// are not followed, and the text says why that is right: a reader who finds
// the header on the redirect target would otherwise take this for a
// misread. The Location value is left out; it is the server's text and the
// https object already carries it.
func responseScope(domain string, r *HTTPResult) string {
	if isRedirect(r.Status) {
		return fmt.Sprintf("https://%s/ answered with a %d redirect; HSTS is per-host, so a header served by the redirect target does not count", domain, r.Status)
	}
	return fmt.Sprintf("https://%s/ answered %d", domain, r.Status)
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

// firstHTTPSResponse returns the first response any address of the host
// gave on 443, or nil when none answered. A result without a status is a
// request that failed (a read timeout, a reset): no head was read, so it
// says nothing about which headers the server sends.
func firstHTTPSResponse(h *HostWeb) *HTTPResult {
	for _, a := range h.addrs() {
		if a.HTTPSRes != nil && a.HTTPSRes.Status > 0 {
			return a.HTTPSRes
		}
	}
	return nil
}

func meetsPreload(h *HSTS) bool {
	return h != nil && h.Preload && h.IncludeSubdomains && h.MaxAge >= preloadMinAge
}

func (f *findings) tlsaFindings(t *TLSAReport) {
	// unknown means the TLSA lookups did not complete: no record was seen,
	// so there is nothing to call unsigned.
	if t == nil || t.Result == TLSANone || t.Result == TLSAUnknown {
		return
	}
	if !t.Signed {
		f.info("tlsa_unsigned_zone", "", "TLSA records are published in an unsigned zone (DANE clients ignore them)")
	}
	if t.Result == TLSAMismatch {
		f.fail("tlsa_mismatch", "", "no TLSA record matches the certificate served (DANE validation fails)")
	}
}
