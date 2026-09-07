package main

import (
	"context"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// NSServer is the audit result for one nameserver address.
type NSServer struct {
	Name    string `json:"name"`
	IP      string `json:"ip"`
	AA      bool   `json:"aa"`
	Rcode   string `json:"rcode,omitempty"`
	Serial  int64  `json:"serial,omitempty"`
	TCP     bool   `json:"tcp"`
	EDNS    bool   `json:"edns"`
	Retries int    `json:"retries,omitempty"` // attempts that got no answer before this one
	Error   string `json:"error,omitempty"`
}

// GlueReport compares the parent's glue with the child's own addresses.
type GlueReport struct {
	Required []string `json:"required"` // in-bailiwick NS names
	Missing  []string `json:"missing"`
	Mismatch []string `json:"mismatch"`
}

// NSReport is the nameservers section of the report. Every aggregate is a
// pointer so that a check which examined nothing reports null instead of a
// pass: an empty server list must never be able to read as a clean audit.
type NSReport struct {
	Count             int         `json:"count"`
	Servers           []NSServer  `json:"servers"`
	SerialsConsistent *bool       `json:"serials_consistent"` // null: no server answered authoritatively
	IPv4Prefixes24    *int        `json:"ipv4_prefixes_24"`   // null: no address was examined
	IPv6Prefixes48    *int        `json:"ipv6_prefixes_48"`
	Glue              *GlueReport `json:"glue,omitempty"` // absent: nothing could be checked
	NSCNAME           []string    `json:"ns_cname"`
	Unresolvable      []string    `json:"unresolvable"` // answered, and the name has no address
	Unresolved        []string    `json:"unresolved"`   // the address lookup did not complete
	addrs             map[string][]netip.Addr
}

// nsNames returns the sorted, lower-cased NS targets of an NS lookup.
func nsNames(ns Lookup) []string {
	var out []string
	for _, r := range ns.Records {
		out = append(out, strings.ToLower(strings.TrimSuffix(r, "."))+".")
	}
	sort.Strings(out)
	return out
}

// resolveNS looks up every NS name, separating names the resolver denied an
// address for from names whose lookup never completed.
func resolveNS(names []string, lookup lookupFn) NSReport {
	rep := NSReport{Count: len(names), addrs: map[string][]netip.Addr{}, Servers: []NSServer{}, NSCNAME: []string{}, Unresolvable: []string{}, Unresolved: []string{}}
	type answer struct{ a, aaaa Lookup }
	answers := make([]answer, len(names))
	var tasks []func()
	for i, n := range names {
		tasks = append(tasks,
			func() { answers[i].a = lookup(n, "A") },
			func() { answers[i].aaaa = lookup(n, "AAAA") },
		)
	}
	parallel(tasks...)
	for i, n := range names {
		a, aaaa := answers[i].a, answers[i].aaaa
		if len(a.CNAME) > 0 || len(aaaa.CNAME) > 0 {
			rep.NSCNAME = append(rep.NSCNAME, n)
		}
		addrs := append(a.Addrs(), aaaa.Addrs()...)
		switch {
		case !a.Answered() || !aaaa.Answered():
			// An unanswered query is not a denial, so it must not be
			// recorded as the name having no address.
			rep.Unresolved = append(rep.Unresolved, n)
		case len(addrs) == 0:
			rep.Unresolvable = append(rep.Unresolvable, n)
		default:
			rep.addrs[n] = addrs
		}
	}
	rep.setDiversity()
	return rep
}

// setDiversity counts distinct prefixes, leaving both counts null when no
// address was examined so that zero cannot be read as a diversity finding.
func (r *NSReport) setDiversity() {
	addrs := r.allAddrs()
	if len(addrs) == 0 {
		r.IPv4Prefixes24, r.IPv6Prefixes48 = nil, nil
		return
	}
	v4, v6 := prefixDiversity(addrs)
	r.IPv4Prefixes24, r.IPv6Prefixes48 = &v4, &v6
}

func (r NSReport) allAddrs() []netip.Addr {
	var out []netip.Addr
	for _, n := range sortedAddrKeys(r.addrs) {
		out = append(out, r.addrs[n]...)
	}
	return out
}

func sortedAddrKeys(m map[string][]netip.Addr) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// prefixDiversity counts distinct /24 (IPv4) and /48 (IPv6) prefixes.
func prefixDiversity(addrs []netip.Addr) (v4, v6 int) {
	seen4, seen6 := map[netip.Prefix]bool{}, map[netip.Prefix]bool{}
	for _, ip := range addrs {
		if ip.Is4() {
			p, _ := ip.Prefix(24)
			seen4[p] = true
		} else {
			p, _ := ip.Prefix(48)
			seen6[p] = true
		}
	}
	return len(seen4), len(seen6)
}

// nsAuditArgs builds one dig invocation with three queries: SOA over UDP,
// SOA over TCP, and SOA with EDNS/DNSSEC, all non-recursive.
func nsAuditArgs(ip netip.Addr, domain string, timeoutSec int) []string {
	args := []string{"+yaml", "+norecurse", "+tries=1", "+time=" + strconv.Itoa(maxInt(1, timeoutSec))}
	if ip.Is6() {
		args = append(args, "-6")
	} else {
		args = append(args, "-4")
	}
	return append(args, "@"+ip.String(), domain, "SOA", domain, "SOA", "+tcp", domain, "SOA", "+dnssec")
}

// auditServer runs the three-query dig against one address, retrying once
// when the first attempt got no answer at all. A single dropped UDP query
// is not a broken nameserver, and it would otherwise be an error that
// fails an entirely healthy domain; the record lookups already retry the
// same way. A server that answered, even to refuse, is not retried.
func auditServer(ctx context.Context, r Runner, digPath, name string, ip netip.Addr, domain string, timeoutSec int) NSServer {
	first, cancel := firstAttemptContext(ctx)
	s := auditOnce(first, r, digPath, name, ip, domain, timeoutSec)
	cancel()
	if unanswered(s.Error) && ctx.Err() == nil {
		s = auditOnce(ctx, r, digPath, name, ip, domain, timeoutSec)
		s.Retries = 1
	}
	return s
}

func auditOnce(ctx context.Context, r Runner, digPath, name string, ip netip.Addr, domain string, timeoutSec int) NSServer {
	s := NSServer{Name: name, IP: ip.String()}
	msgs := runDig(ctx, r, digPath, nsAuditArgs(ip, domain, timeoutSec)...)
	if len(msgs) == 0 || msgs[0].Error != "" {
		s.Error = firstNonEmpty(msgs[0].Error, "no response")
		return s
	}
	interpretAudit(&s, msgs)
	return s
}

// unanswered reports whether an audit failure means no answer arrived, as
// opposed to an answer we did not like: only the former is worth a retry.
func unanswered(errText string) bool {
	if errText == "" {
		return false
	}
	for _, s := range []string{"timed out", "no servers could be reached", "no response", "communications error", "unreachable", "connection refused"} {
		if strings.Contains(errText, s) {
			return true
		}
	}
	return false
}

// interpretAudit fills the server verdict from the UDP, TCP and EDNS
// answers of one audit run.
func interpretAudit(s *NSServer, msgs []digMessage) {
	udp := msgs[0]
	s.Rcode = udp.Status
	s.AA = udp.hasFlag("aa") && udp.Status == "NOERROR"
	s.EDNS = udp.OPT
	if soa := udp.records("SOA"); len(soa) > 0 {
		s.Serial = soaSerial(soa[0].RData)
	}
	s.TCP = len(msgs) > 1 && msgs[1].Error == "" && msgs[1].Status == "NOERROR"
	if len(msgs) > 2 && msgs[2].OPT {
		s.EDNS = true
	}
	if !s.AA {
		s.Error = "not authoritative (" + udp.Status + ")"
	}
}

// soaSerial extracts the serial from SOA rdata "mname rname serial ...".
func soaSerial(rdata string) int64 {
	f := strings.Fields(rdata)
	if len(f) < 3 {
		return 0
	}
	n, _ := strconv.ParseInt(f[2], 10, 64)
	return n
}

// auditAll runs auditServer for every address of every NS in parallel and
// fills the serial consistency verdict.
func auditAll(ctx context.Context, r Runner, digPath string, rep *NSReport, domain string, families []string, timeoutSec int) {
	var mu sync.Mutex
	var tasks []func()
	for _, name := range sortedAddrKeys(rep.addrs) {
		for _, ip := range rep.addrs[name] {
			if !containsString(families, familyOf(ip)) {
				continue
			}
			tasks = append(tasks, func() {
				s := auditServer(ctx, r, digPath, name, ip, domain, timeoutSec)
				mu.Lock()
				rep.Servers = append(rep.Servers, s)
				mu.Unlock()
			})
		}
	}
	parallel(tasks...)
	sort.Slice(rep.Servers, func(i, j int) bool {
		if rep.Servers[i].Name != rep.Servers[j].Name {
			return rep.Servers[i].Name < rep.Servers[j].Name
		}
		return rep.Servers[i].IP < rep.Servers[j].IP
	})
	rep.SerialsConsistent = serialsConsistent(rep.Servers)
}

// serialsConsistent compares the serials of the servers that answered
// authoritatively. It returns nil when none did, because a comparison over
// nothing is unknown rather than agreement.
func serialsConsistent(servers []NSServer) *bool {
	var first int64
	seen := false
	for _, s := range servers {
		if !s.AA || s.Serial == 0 {
			continue
		}
		if seen && s.Serial != first {
			return boolPtr(false)
		}
		first, seen = s.Serial, true
	}
	if !seen {
		return nil
	}
	return boolPtr(true)
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// glueArgs asks the parent zone's server for the delegation with its glue.
func glueArgs(parentServer, family string, timeoutSec int, domain string) []string {
	args := []string{"+yaml", "+norecurse", "+tries=1", "+time=" + strconv.Itoa(maxInt(1, timeoutSec))}
	if family == familyIPv6 {
		args = append(args, "-6")
	} else {
		args = append(args, "-4")
	}
	return append(args, "@"+parentServer, domain, "NS")
}

// checkGlue compares the parent's ADDITIONAL glue with the child's own
// addresses for in-bailiwick nameservers (names ending in the domain).
func checkGlue(msgs []digMessage, domain string, addrs map[string][]netip.Addr) *GlueReport {
	if len(msgs) == 0 || msgs[0].Error != "" {
		return nil
	}
	g := &GlueReport{Required: []string{}, Missing: []string{}, Mismatch: []string{}}
	glue := glueAddresses(msgs[0])
	suffix := "." + strings.ToLower(strings.TrimSuffix(domain, ".")) + "."
	for _, n := range sortedAddrKeys(addrs) {
		if !strings.HasSuffix(n, suffix) {
			continue
		}
		g.Required = append(g.Required, n)
		if len(glue[n]) == 0 {
			g.Missing = append(g.Missing, n)
			continue
		}
		g.Mismatch = append(g.Mismatch, glueMismatches(n, addrs[n], glue[n])...)
		g.Mismatch = nonNil(g.Mismatch)
	}
	return g
}

// glueAddresses indexes the A/AAAA glue of a referral by owner name.
func glueAddresses(m digMessage) map[string]map[string]bool {
	glue := map[string]map[string]bool{}
	for _, rr := range m.Additional {
		if rr.Type != "A" && rr.Type != "AAAA" {
			continue
		}
		if glue[rr.Owner] == nil {
			glue[rr.Owner] = map[string]bool{}
		}
		glue[rr.Owner][rr.RData] = true
	}
	return glue
}

func glueMismatches(name string, addrs []netip.Addr, glue map[string]bool) []string {
	var out []string
	for _, ip := range addrs {
		if !glue[ip.String()] {
			out = append(out, name+" "+ip.String())
		}
	}
	return out
}
