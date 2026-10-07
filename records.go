package main

import (
	"net/netip"
	"strconv"
	"strings"
)

// Trust is the DNSSEC trust level of an answer: the validating resolver's
// verdict, read from the AD bit of its response. Empty means no verdict
// (the lookup failed, or the resolver does not validate).
type Trust string

const (
	TrustSecure   Trust = "secure"
	TrustInsecure Trust = "insecure"
	TrustBogus    Trust = "bogus"
)

// LookupStatus is the normalised outcome of one DNS query.
type LookupStatus string

const (
	StatusOK       LookupStatus = "ok"
	StatusNXRRSet  LookupStatus = "nxrrset"
	StatusNXDomain LookupStatus = "nxdomain"
	StatusFailure  LookupStatus = "failure"
	StatusTimeout  LookupStatus = "timeout"
)

// RR is one resource record: from dog's JSON, or from dig's presentation
// format.
type RR struct {
	Owner string
	TTL   int64
	Type  string
	RData string
	RDLen int // wire length of the rdata; computed for TXT and CNAME only
}

// Lookup is the parsed result of one dog query.
type Lookup struct {
	Name    string       `json:"-"`
	Type    string       `json:"-"`
	Status  LookupStatus `json:"status"`
	Trust   Trust        `json:"trust,omitempty"`
	Records []string     `json:"records,omitempty"` // rdata of RRs of the queried type
	CNAME   []string     `json:"cname,omitempty"`   // CNAME chain targets, in order
	Error   string       `json:"error,omitempty"`
	Retries int          `json:"retries,omitempty"` // attempts that timed out before this result
	// unqueryable: dog refused to encode the name, so no query was sent
	// and the failure says nothing about the resolver or the zone.
	unqueryable bool
	rrs         []RR
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

// SOAOwner returns the owner of a SOA carried in the answer (the zone the
// resolver consulted for a negative response), or "".
func (l Lookup) SOAOwner() string {
	for _, rr := range l.rrs {
		if rr.Type == "SOA" {
			return rr.Owner
		}
	}
	return ""
}

// IsNullMX reports whether the MX RRset is the RFC 7505 null MX ("0 ."),
// which declares that the domain accepts no mail.
func (l Lookup) IsNullMX() bool {
	if !l.HasRecords() {
		return false
	}
	for _, rec := range l.Records {
		if strings.Join(strings.Fields(rec), " ") != "0 ." {
			return false
		}
	}
	return true
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

// parseRR parses "owner [ttl] [IN] TYPE rdata" as dig prints it. TTL and
// class are optional because +trace output abbreviates some records.
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
	// The rdata is taken from the line as printed, not rebuilt from its
	// fields: rejoining them collapsed runs of spaces inside a quoted TXT
	// or CAA value, changing the record and undercounting its length.
	rr.RData = afterFields(text, i)
	switch rr.Type {
	case "TXT":
		strs := txtStrings(rr.RData)
		rr.RData = strings.Join(strs, "")
		for _, str := range strs {
			rr.RDLen += 1 + len(str)
		}
	case "CNAME":
		rr.RDLen = wireNameLen(rr.RData)
	}
	return rr, true
}

// afterFields returns text with its first n whitespace-separated fields
// and the whitespace around them removed, everything after kept verbatim.
func afterFields(text string, n int) string {
	rest := text
	for k := 0; k < n; k++ {
		rest = strings.TrimLeft(rest, " \t")
		j := strings.IndexAny(rest, " \t")
		if j < 0 {
			return ""
		}
		rest = rest[j:]
	}
	return strings.TrimSpace(rest)
}

// joinTXT concatenates the quoted character-strings of a TXT rdata into one
// unquoted string, honouring backslash escapes.
func joinTXT(rdata string) string {
	return strings.Join(txtStrings(rdata), "")
}

// txtStrings splits a TXT rdata in presentation format into its
// character-strings, decoding \" \\ and \DDD escapes so each element is the
// exact byte sequence carried on the wire. An unquoted rdata (dig prints a
// single token without quotes) is one string.
func txtStrings(rdata string) []string {
	if !strings.Contains(rdata, `"`) {
		return []string{rdata}
	}
	var out []string
	var b strings.Builder
	inQuote := false
	for i := 0; i < len(rdata); i++ {
		c := rdata[i]
		switch {
		case c == '"':
			if inQuote {
				out = append(out, b.String())
				b.Reset()
			}
			inQuote = !inQuote
		case !inQuote:
		case c == '\\':
			i = decodeEscape(rdata, i, &b)
		default:
			b.WriteByte(c)
		}
	}
	return out
}

// decodeEscape writes the byte the escape at rdata[i] stands for (\DDD or
// \X) and returns the index of the escape's last character. A backslash
// with nothing after it is kept as itself.
func decodeEscape(rdata string, i int, b *strings.Builder) int {
	switch {
	case i+3 < len(rdata) && isDigits(rdata[i+1:i+4]):
		n, _ := strconv.Atoi(rdata[i+1 : i+4])
		b.WriteByte(byte(n))
		return i + 3
	case i+1 < len(rdata):
		b.WriteByte(rdata[i+1])
		return i + 1
	}
	b.WriteByte('\\')
	return i
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// wireNameLen is the uncompressed wire length of a domain name: one length
// octet per label plus the terminating root octet.
func wireNameLen(name string) int {
	name = strings.TrimSuffix(name, ".") // dpdomain: not normalisation — wire-length arithmetic on an owner name as the resolver returned it (may be a wildcard)
	if name == "" {
		return 1
	}
	return len(name) + 2
}

// udpAnswerOctets estimates the size of the DNS response a resolver without
// EDNS would receive for this lookup: header, question, and every positive
// record of the queried type plus any CNAME chain, with owner names
// compressed to a pointer. RRSIGs are excluded because a non-EDNS query
// cannot set DO. This is the quantity RFC 7208 §3.4 bounds at 512 octets;
// it is exact for TXT and CNAME answers and 0 for other types.
func (l Lookup) udpAnswerOctets() int {
	if l.Type != "TXT" {
		return 0
	}
	name := l.Name
	if name == "" && len(l.rrs) > 0 {
		name = l.rrs[0].Owner
	}
	const header, rrFixed = 12, 12 // rrFixed: 2-octet name pointer + type, class, ttl, rdlength
	size := header + wireNameLen(name) + 4
	for _, rr := range l.rrs {
		if rr.Type != l.Type && rr.Type != "CNAME" {
			continue
		}
		size += rrFixed + rr.RDLen
	}
	return size
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
