package main

import (
	"context"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Delegation status values.
const (
	DelegationMatch         = "match"
	DelegationMismatch      = "mismatch"
	DelegationNotDelegated  = "not_delegated"
	DelegationNoChildAnswer = "no_child_answer"
	DelegationSameServers   = "same_servers" // parent zone's servers also host the child
	DelegationChildNoNS     = "child_no_ns"  // child answers with SOA but no NS RRset
	DelegationNotAZone      = "not_a_zone"   // the name is a host inside a zone, not an apex
	DelegationError         = "error"
)

// Delegation compares the NS set the parent zone delegates to with the NS
// set the zone itself serves.
type Delegation struct {
	Status       string   `json:"status"`
	ParentNS     []string `json:"parent_ns,omitempty"`
	ParentServer string   `json:"parent_server,omitempty"`
	ChildNS      []string `json:"child_ns,omitempty"`
	ChildServer  string   `json:"child_server,omitempty"`
	ParentOnly   []string `json:"parent_only,omitempty"`
	ChildOnly    []string `json:"child_only,omitempty"`
	Error        string   `json:"error,omitempty"`
}

// traceBlock is one response in `dig +trace` output: the RRs printed
// followed by a ";; Received ... from IP#port(name)" line.
type traceBlock struct {
	RRs    []RR
	Server string // server name from the Received line
	IP     string
}

// nsFor returns the sorted, lower-cased NS targets in the block owned by
// fqdn (which must carry a trailing dot).
func (b traceBlock) nsFor(fqdn string) []string {
	var out []string
	for _, rr := range b.RRs {
		if rr.Type == "NS" && rr.Owner == fqdn {
			out = append(out, strings.ToLower(rr.RData))
		}
	}
	sort.Strings(out)
	return out
}

func (b traceBlock) hasSOA() bool {
	for _, rr := range b.RRs {
		if rr.Type == "SOA" {
			return true
		}
	}
	return false
}

// hasSOAFor reports whether the block carries a SOA owned by fqdn.
func (b traceBlock) hasSOAFor(fqdn string) bool {
	for _, rr := range b.RRs {
		if rr.Type == "SOA" && rr.Owner == fqdn {
			return true
		}
	}
	return false
}

var receivedRe = regexp.MustCompile(`^;; Received \d+ bytes from (\S+?)#\d+\((\S+)\)`)

// parseTrace splits dig +trace output into blocks and collects the
// ";; ..." diagnostics (communication errors) it printed.
func parseTrace(out string) (blocks []traceBlock, diags []string) {
	var cur traceBlock
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, ";; Received"):
			if m := receivedRe.FindStringSubmatch(line); m != nil {
				cur.IP, cur.Server = m[1], m[2]
			}
			blocks = append(blocks, cur)
			cur = traceBlock{}
		case strings.HasPrefix(line, ";; communications error"),
			strings.HasPrefix(line, ";; connection timed out"),
			strings.HasPrefix(line, ";; no servers could be reached"):
			diags = append(diags, strings.TrimPrefix(line, ";; "))
		case strings.HasPrefix(line, ";"):
			continue
		default:
			if rr, ok := parseRR(line); ok {
				cur.RRs = append(cur.RRs, rr)
			}
		}
	}
	if len(cur.RRs) > 0 {
		blocks = append(blocks, cur)
	}
	return blocks, diags
}

// compareDelegation finds the parent referral and the child's own NS answer
// for domain and reports how they differ.
func compareDelegation(blocks []traceBlock, diags []string, domain string) Delegation {
	fqdn := strings.ToLower(strings.TrimSuffix(domain, ".")) + "."
	var withNS []traceBlock
	lastNS := -1
	for i, b := range blocks {
		if len(b.nsFor(fqdn)) > 0 {
			withNS = append(withNS, b)
			lastNS = i
		}
	}
	d := Delegation{}
	if len(diags) > 0 {
		d.Error = strings.Join(diags, "; ")
	}
	switch len(withNS) {
	case 0:
		return classifyNoNS(d, blocks)
	case 1:
		if child := soaOnlyChild(blocks[lastNS+1:], fqdn); child != nil {
			return classifyChildNoNS(d, withNS[0], *child, fqdn)
		}
		return classifySingleBlock(d, withNS[0], fqdn)
	}
	parent, child := withNS[0], withNS[len(withNS)-1]
	d.ParentNS, d.ParentServer = parent.nsFor(fqdn), parent.Server
	d.ChildNS, d.ChildServer = child.nsFor(fqdn), child.Server
	d.ParentOnly, d.ChildOnly = setDiff(d.ParentNS, d.ChildNS), setDiff(d.ChildNS, d.ParentNS)
	if len(d.ParentOnly) == 0 && len(d.ChildOnly) == 0 {
		d.Status = DelegationMatch
	} else {
		d.Status = DelegationMismatch
	}
	return d
}

// soaOnlyChild returns the first block after the parent referral in which a
// delegated server answered with the domain's own SOA (but no NS, or it
// would have counted as an NS block), or nil.
func soaOnlyChild(after []traceBlock, fqdn string) *traceBlock {
	for i := range after {
		if after[i].hasSOAFor(fqdn) {
			return &after[i]
		}
	}
	return nil
}

// classifyChildNoNS reports a lame zone: the delegated server is
// authoritative (it returns the apex SOA) but the zone has no NS RRset.
func classifyChildNoNS(d Delegation, parent, child traceBlock, fqdn string) Delegation {
	d.Status = DelegationChildNoNS
	d.ParentNS, d.ParentServer = parent.nsFor(fqdn), parent.Server
	d.ChildServer = child.Server
	d.ParentOnly = d.ParentNS
	if d.Error == "" {
		d.Error = "zone at " + child.Server + " has a SOA but no NS records"
	}
	return d
}

// classifySingleBlock handles a trace with exactly one NS answer for the
// domain. When the answering server is itself one of those NS names, the
// parent zone's server also hosts the child and answered authoritatively
// instead of referring, so the delegation cannot be observed separately.
// Otherwise the referral was received but no child server answered.
func classifySingleBlock(d Delegation, b traceBlock, fqdn string) Delegation {
	ns := b.nsFor(fqdn)
	server := strings.ToLower(strings.TrimSuffix(b.Server, ".")) + "."
	for _, n := range ns {
		if n == server {
			d.Status = DelegationSameServers
			d.ParentNS, d.ParentServer = ns, b.Server
			d.ChildNS, d.ChildServer = ns, b.Server
			return d
		}
	}
	d.Status = DelegationNoChildAnswer
	d.ParentNS, d.ParentServer = ns, b.Server
	return d
}

func classifyNoNS(d Delegation, blocks []traceBlock) Delegation {
	if len(blocks) == 0 {
		d.Status = DelegationError
		if d.Error == "" {
			d.Error = "dig +trace produced no responses"
		}
		return d
	}
	last := blocks[len(blocks)-1]
	if last.hasSOA() {
		d.Status = DelegationNotDelegated
		d.ParentServer = last.Server
		return d
	}
	d.Status = DelegationError
	if d.Error == "" {
		d.Error = "trace ended at " + last.Server + " without an NS answer for the domain"
	}
	return d
}

// setDiff returns the sorted elements of a that are not in b.
func setDiff(a, b []string) []string {
	in := make(map[string]bool, len(b))
	for _, s := range b {
		in[s] = true
	}
	var out []string
	for _, s := range a {
		if !in[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

const rootServer = "a.root-servers.net"

// traceArgs builds argv for the delegation trace. Each query gets half the
// budget so that one unresponsive root or TLD server still leaves dig time
// to fail over to another; runTrace bounds the whole trace separately.
func traceArgs(family string, timeoutSec int, domain string) []string {
	args := []string{"+trace", "+nodnssec", "+tries=1", "+time=" + strconv.Itoa(maxInt(1, timeoutSec/2))}
	if family == familyIPv6 {
		args = append(args, "-6")
	} else {
		args = append(args, "-4")
	}
	return append(args, "@"+rootServer, domain, "NS")
}

// traceDelegation runs dig +trace and compares parent and child NS sets.
// When the trace ends with a single NS answer, the answering server is
// asked directly: an authoritative (aa) answer means the parent zone's
// server also hosts the child, not that the child failed to answer.
func traceDelegation(ctx context.Context, r Runner, digPath, family string, timeoutSec int, domain string) Delegation {
	stdout, stderr, err := r.Run(ctx, digPath, traceArgs(family, timeoutSec, domain)...)
	blocks, diags := parseTrace(string(stdout))
	if isTimeout(ctx, err) {
		diags = append(diags, "dig +trace timed out")
	} else if err != nil && len(blocks) == 0 {
		diags = append(diags, "dig: "+err.Error()+" "+strings.TrimSpace(string(stderr)))
	}
	d := compareDelegation(blocks, diags, domain)
	if d.Status == DelegationNoChildAnswer && d.ParentServer != "" && ctx.Err() == nil {
		out, _, _ := r.Run(ctx, digPath, authArgs(d.ParentServer, family, timeoutSec, domain)...)
		if digAuthoritative(string(out)) {
			d.Status = DelegationSameServers
			d.ChildNS, d.ChildServer = d.ParentNS, d.ParentServer
		}
	}
	return d
}

// authArgs builds argv for a non-recursive NS query at one server, used to
// learn whether that server answers authoritatively for the domain.
func authArgs(server, family string, timeoutSec int, domain string) []string {
	args := []string{"+norecurse", "+yaml", "+tries=1", "+time=" + strconv.Itoa(maxInt(1, timeoutSec/2))}
	if family == familyIPv6 {
		args = append(args, "-6")
	} else {
		args = append(args, "-4")
	}
	return append(args, "@"+server, domain, "NS")
}

var digFlagsRe = regexp.MustCompile(`(?m)^\s*flags:\s*(.*)$`)

// digAuthoritative reports whether a `dig +yaml` response carries the aa
// flag. The EDNS pseudo-section has its own flags line, which never holds
// aa, so every flags line is inspected.
func digAuthoritative(out string) bool {
	for _, m := range digFlagsRe.FindAllStringSubmatch(out, -1) {
		for _, f := range strings.Fields(m[1]) {
			if f == "aa" {
				return true
			}
		}
	}
	return false
}
