package main

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Trust is the DNSSEC trust level delv assigned to an answer.
type Trust string

const (
	TrustSecure   Trust = "secure"
	TrustInsecure Trust = "insecure"
	TrustBogus    Trust = "bogus"
)

// LookupStatus is the normalised outcome of one delv query.
type LookupStatus string

const (
	StatusOK       LookupStatus = "ok"
	StatusNXRRSet  LookupStatus = "nxrrset"
	StatusNXDomain LookupStatus = "nxdomain"
	StatusFailure  LookupStatus = "failure"
	StatusTimeout  LookupStatus = "timeout"
)

// RR is one resource record parsed from delv's presentation format.
type RR struct {
	Owner    string
	TTL      int64
	Type     string
	RData    string
	Negative bool // a "\-TYPE ;-$NXRRSET" / ";-$NXDOMAIN" marker line
}

// Lookup is the parsed result of one `delv +yaml name type` invocation.
type Lookup struct {
	Name    string       `json:"-"`
	Type    string       `json:"-"`
	Status  LookupStatus `json:"status"`
	Trust   Trust        `json:"trust,omitempty"`
	Records []string     `json:"records,omitempty"` // rdata of RRs of the queried type
	CNAME   []string     `json:"cname,omitempty"`   // CNAME chain targets, in order
	Error   string       `json:"error,omitempty"`
	Retries int          `json:"retries,omitempty"` // attempts that timed out before this result
	rrs     []RR
}

// Addrs returns the IP addresses in an A or AAAA lookup.
func (l Lookup) Addrs() []netip.Addr {
	var out []netip.Addr
	for _, rec := range l.Records {
		if ip, err := netip.ParseAddr(rec); err == nil {
			out = append(out, ip.Unmap())
		}
	}
	return out
}

// Answered reports whether the resolver produced a definite answer,
// positive or negative, rather than failing or timing out.
func (l Lookup) Answered() bool {
	return l.Status == StatusOK || l.Status == StatusNXRRSet || l.Status == StatusNXDomain
}

// HasRecords reports whether the lookup returned at least one record of the
// queried type.
func (l Lookup) HasRecords() bool {
	return l.Status == StatusOK && len(l.Records) > 0
}

// delvArgs builds the argv for one delv query.
func delvArgs(server, family, name, qtype string) []string {
	args := []string{"+yaml"}
	switch family {
	case familyIPv4:
		args = append(args, "-4")
	case familyIPv6:
		args = append(args, "-6")
	}
	if server != "" {
		args = append(args, "@"+server)
	}
	return append(args, name, qtype)
}

// minAttempt is the shortest first-attempt deadline delvLookup will use.
const minAttempt = time.Second

// delvLookup runs delv for name/qtype and parses the result. family may be
// empty (let delv choose) or familyIPv4/familyIPv6 to force the transport.
//
// A single dropped UDP query would otherwise cost the whole budget, so the
// first attempt gets half the remaining time and is retried once with the
// rest if it times out while ctx is still alive.
func delvLookup(ctx context.Context, r Runner, delvPath, server, family, name, qtype string) Lookup {
	first, cancel := firstAttemptContext(ctx)
	l := delvOnce(first, r, delvPath, server, family, name, qtype)
	cancel()
	if l.Status == StatusTimeout && ctx.Err() == nil {
		l = delvOnce(ctx, r, delvPath, server, family, name, qtype)
		l.Retries = 1
	}
	return l
}

// firstAttemptContext derives a deadline of half the time left in ctx (but
// at least minAttempt) so that a retry fits inside the overall budget.
func firstAttemptContext(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return context.WithCancel(ctx)
	}
	half := time.Until(deadline) / 2
	if half < minAttempt {
		half = minAttempt
	}
	return context.WithTimeout(ctx, half)
}

func delvOnce(ctx context.Context, r Runner, delvPath, server, family, name, qtype string) Lookup {
	stdout, stderr, err := r.Run(ctx, delvPath, delvArgs(server, family, name, qtype)...)
	if isTimeout(ctx, err) {
		return Lookup{Name: name, Type: qtype, Status: StatusTimeout, Error: "delv timed out"}
	}
	if err != nil {
		return Lookup{Name: name, Type: qtype, Status: StatusFailure,
			Error: fmt.Sprintf("delv: %v: %s", err, strings.TrimSpace(string(stderr)))}
	}
	l := parseDelvYAML(string(stdout), qtype)
	l.Name = name
	return l
}

// parseDelvYAML parses delv's +yaml output. The shape is fixed:
//
//	type: DELV_RESULT
//	query_name: X
//	status: S
//	records:
//	  - <trust key>:
//	    - 'RR in presentation format'
func parseDelvYAML(out, qtype string) Lookup {
	l := Lookup{Type: qtype}
	var trust Trust
	sawStatus := false
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "status:"):
			sawStatus = true
			l.Status, l.Error = mapDelvStatus(strings.TrimSpace(strings.TrimPrefix(line, "status:")))
		case strings.HasPrefix(line, "- '"):
			if rr, ok := parseRR(unquoteYAML(line[2:])); ok {
				l.addRR(rr, trust)
			}
		case strings.HasPrefix(line, "- ") && strings.HasSuffix(line, ":"):
			trust = trustForKey(strings.TrimSuffix(line[2:], ":"))
		}
	}
	if !sawStatus {
		l.Status = StatusFailure
		l.Error = "unrecognised delv output: " + firstLine(out)
	}
	return l
}

func (l *Lookup) addRR(rr RR, trust Trust) {
	l.rrs = append(l.rrs, rr)
	if trust != "" && l.Trust == "" {
		l.Trust = trust
	}
	if rr.Negative {
		return
	}
	switch rr.Type {
	case l.Type:
		l.Records = append(l.Records, rr.RData)
	case "CNAME":
		l.CNAME = append(l.CNAME, rr.RData)
	}
}

func mapDelvStatus(s string) (LookupStatus, string) {
	switch s {
	case "success":
		return StatusOK, ""
	case "ncache nxrrset":
		return StatusNXRRSet, ""
	case "ncache nxdomain":
		return StatusNXDomain, ""
	case "timed out":
		return StatusTimeout, "delv: timed out"
	case "failure":
		return StatusFailure, "delv: resolution failed"
	default:
		return StatusFailure, "delv: " + s
	}
}

func trustForKey(key string) Trust {
	switch key {
	case "fully_validated", "negative_response_fully_validated":
		return TrustSecure
	case "unsigned_answer", "negative_response_unsigned_answer":
		return TrustInsecure
	default:
		return ""
	}
}

// unquoteYAML strips a YAML single-quoted scalar; a doubled single quote
// inside it is an escaped quote.
func unquoteYAML(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		s = s[1 : len(s)-1]
	}
	return strings.ReplaceAll(s, "''", "'")
}

// parseRR parses "owner [ttl] [IN] TYPE rdata" as printed by delv. TTL and
// class are optional because delv abbreviates records in negative answers
// ("org. RRSIG SOA ...").
func parseRR(text string) (RR, bool) {
	f := strings.Fields(text)
	if len(f) < 2 {
		return RR{}, false
	}
	rr := RR{Owner: strings.ToLower(f[0])}
	i := 1
	if ttl, err := strconv.ParseInt(f[i], 10, 64); err == nil {
		rr.TTL = ttl
		i++
	}
	if i < len(f) && f[i] == "IN" {
		i++
	}
	if i >= len(f) {
		return RR{}, false
	}
	rr.Type = f[i]
	i++
	if strings.HasPrefix(rr.Type, `\-`) {
		rr.Negative = true
		rr.Type = strings.TrimPrefix(rr.Type, `\-`)
	}
	rr.RData = strings.Join(f[i:], " ")
	if rr.Type == "TXT" {
		rr.RData = joinTXT(rr.RData)
	}
	return rr, true
}

// joinTXT concatenates the quoted character-strings of a TXT rdata into one
// unquoted string, honouring backslash escapes.
func joinTXT(rdata string) string {
	var b strings.Builder
	inQuote, escaped := false, false
	for _, c := range rdata {
		switch {
		case escaped:
			b.WriteRune(c)
			escaped = false
		case c == '\\' && inQuote:
			escaped = true
		case c == '"':
			inQuote = !inQuote
		case inQuote:
			b.WriteRune(c)
		}
	}
	if b.Len() == 0 && !strings.Contains(rdata, `"`) {
		return rdata
	}
	return b.String()
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
