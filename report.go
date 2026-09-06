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
	NotAZone       bool         `json:"not_a_zone,omitempty"`
	EnclosingZone  string       `json:"enclosing_zone,omitempty"`
	Resolver       string       `json:"resolver"`
	Families       []string     `json:"families"`
	TimeoutSec     int          `json:"timeout_sec"`
	TCPTimeoutSec  int          `json:"tcp_timeout_sec"`
	QuicTimeoutSec int          `json:"quic_timeout_sec"`
	DNS            DNSSection   `json:"dns"`
	DNSSEC         DNSSECReport `json:"dnssec"`
	Delegation     Delegation   `json:"delegation"`
	Web            WebSection   `json:"web"`
	Errors         []string     `json:"errors"`
	Warnings       []string     `json:"warnings"`
	OK             bool         `json:"ok"`
	ElapsedMs      int64        `json:"elapsed_ms"`
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
	SameAsApex bool      `json:"same_as_apex,omitempty"`
	IPv4       []AddrWeb `json:"ipv4,omitempty"`
	IPv6       []AddrWeb `json:"ipv6,omitempty"`
}

// AddrWeb is the probe outcome for one address.
type AddrWeb struct {
	IP    string      `json:"ip"`
	HTTP  PortState   `json:"80"`
	HTTPS PortState   `json:"443"`
	QUIC  *QUICResult `json:"quic,omitempty"`
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
	bogus := rep.DNSSEC.State == DNSSECBogus
	for _, t := range apexTypes {
		f.lookupFindings("apex", t, apex[t], bogus)
	}
	for _, t := range wwwTypes {
		f.lookupFindings("www", t, rep.DNS.WWW[t], bogus)
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
// suppressed when DNSSEC is bogus, since that finding explains them.
func (f *findings) lookupFindings(label, qtype string, l Lookup, bogus bool) {
	switch l.Status {
	case StatusTimeout:
		f.errorf("%s %s lookup timed out", label, qtype)
	case StatusFailure:
		if !bogus {
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
