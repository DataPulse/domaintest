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
	for _, b := range blocks {
		if len(b.nsFor(fqdn)) > 0 {
			withNS = append(withNS, b)
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
		d.Status = DelegationNoChildAnswer
		d.ParentNS, d.ParentServer = withNS[0].nsFor(fqdn), withNS[0].Server
		return d
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
func traceDelegation(ctx context.Context, r Runner, digPath, family string, timeoutSec int, domain string) Delegation {
	stdout, stderr, err := r.Run(ctx, digPath, traceArgs(family, timeoutSec, domain)...)
	blocks, diags := parseTrace(string(stdout))
	if isTimeout(ctx, err) {
		diags = append(diags, "dig +trace timed out")
	} else if err != nil && len(blocks) == 0 {
		diags = append(diags, "dig: "+err.Error()+" "+strings.TrimSpace(string(stderr)))
	}
	return compareDelegation(blocks, diags, domain)
}
