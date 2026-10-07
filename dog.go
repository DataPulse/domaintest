package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Every DNS lookup goes to the resolver through dog, the client the rest of
// the DataPulse stack (live DNS) uses, and takes its DNSSEC verdict from the
// resolver: AD set means the validating resolver authenticated the whole
// answer, CNAME chain and denial of existence included. Until 2026-10-07
// each lookup ran delv, which validated by itself. delv cost about 36 ms of
// CPU per lookup, almost all of it process start-up, and a run makes about
// 44; on a two-vCPU worker running five domains that starved the run of
// CPU, and lookups that missed their budget were reported as the domain's
// faults. dog costs about 2 ms. delv's own verdicts also disagreed with the
// resolver's (opt-out denials, reserved names, zones whose servers only the
// resolver could reach), which made the two tools contradict each other.

// dogArgs builds the argv for one dog query. -Z ad asks the resolver to
// report whether it authenticated the answer (RFC 6840 §5.7) without
// asking for signatures, which keep answers small. timeoutSec is dog's own
// per-attempt wait; the context deadline is what actually ends the attempt.
func dogArgs(server string, timeoutSec int, name, qtype string) []string {
	args := []string{"-J", "-Z", "ad", "--timeout", strconv.Itoa(maxInt(1, timeoutSec))}
	if server != "" {
		args = append(args, "-n", server)
	}
	return append(args, "-q", name, "-t", qtype)
}

// minAttempt is the shortest first-attempt deadline dnsLookup will use.
const minAttempt = time.Second

// dnsLookup runs dog for name/qtype against server ("" for the system
// resolver) and parses the result.
//
// A single dropped UDP query would otherwise cost the whole budget, so the
// first attempt gets half the remaining time and is retried once with the
// rest if it times out while ctx is still alive.
func dnsLookup(ctx context.Context, r Runner, dogPath, server string, timeoutSec int, name, qtype string) Lookup {
	first, cancel := firstAttemptContext(ctx)
	l := dogOnce(first, r, dogPath, server, timeoutSec, name, qtype)
	cancel()
	if l.Status == StatusTimeout && ctx.Err() == nil {
		l = dogOnce(ctx, r, dogPath, server, timeoutSec, name, qtype)
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

func dogOnce(ctx context.Context, r Runner, dogPath, server string, timeoutSec int, name, qtype string) Lookup {
	stdout, stderr, err := r.Run(ctx, dogPath, dogArgs(server, timeoutSec, name, qtype)...)
	if isTimeout(ctx, err) {
		return Lookup{Name: name, Type: qtype, Status: StatusTimeout, Error: "dns lookup timed out"}
	}
	l := parseDogOutput(stdout, stderr, err, qtype)
	l.Name = name
	if exitCode(err) == dogOptionsError {
		// dog validates names before sending them and refuses a label that
		// is not a valid IDN. dpdomain refuses the case first seen,
		// xn--bad (punycode for two control characters), at input since
		// 2026-10-07; this is the backstop for any other name the two
		// libraries judge differently.
		l.unqueryable = true
		l.Error = "dog cannot query the name: " + strings.TrimPrefix(firstLine(strings.TrimSpace(string(stderr))), "dog: ")
	}
	return l
}

// dogOptionsError is dog's exit status for an argument it refuses, which
// includes a name it cannot encode.
const dogOptionsError = 3

// exitCode returns the process exit status in err, or -1 when err is not
// an exit.
func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// dogOutput is one JSON document dog prints: the responses on stdout, or an
// error object on stderr for a query that got no response at all.
type dogOutput struct {
	Responses    []dogResponse `json:"responses"`
	Error        bool          `json:"error"`
	ErrorMessage string        `json:"error_message"`
}

type dogResponse struct {
	Flags struct {
		AD    bool   `json:"ad"`
		Rcode string `json:"rcode"`
	} `json:"flags"`
	Answers     []dogRecord `json:"answers"`
	Authorities []dogRecord `json:"authorities"`
}

type dogRecord struct {
	Name string                     `json:"name"`
	TTL  int64                      `json:"ttl"`
	Type string                     `json:"type"`
	Data map[string]json.RawMessage `json:"data"`
}

// parseDogOutput reads one dog -J run: the response from stdout, or, for a
// query that got no response at all, the error document dog writes to
// stderr (exiting 1).
func parseDogOutput(stdout, stderr []byte, runErr error, qtype string) Lookup {
	l := Lookup{Type: qtype}
	if resp := firstDogResponse(stdout); resp != nil {
		fillFromResponse(&l, resp)
		return l
	}
	if msg := dogErrorMessage(stderr); msg != "" {
		l.Status, l.Error = networkStatus(msg)
		return l
	}
	l.Status = StatusFailure
	l.Error = "dog: " + firstNonEmpty(firstLine(strings.TrimSpace(string(stderr))), errText(runErr), "no response")
	return l
}

// firstDogResponse returns the first response in dog's JSON output, or nil.
func firstDogResponse(out []byte) *dogResponse {
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var doc dogOutput
		if err := dec.Decode(&doc); err != nil {
			return nil
		}
		if len(doc.Responses) > 0 {
			return &doc.Responses[0]
		}
	}
}

// dogErrorMessage returns the message of the first error document on dog's
// stderr, or "".
func dogErrorMessage(stderr []byte) string {
	dec := json.NewDecoder(bytes.NewReader(stderr))
	for {
		var doc dogOutput
		if err := dec.Decode(&doc); err != nil {
			return ""
		}
		if doc.Error && doc.ErrorMessage != "" {
			return doc.ErrorMessage
		}
	}
}

// networkStatus classifies dog's error message for a query that got no
// response.
func networkStatus(msg string) (LookupStatus, string) {
	if strings.Contains(strings.ToLower(msg), "timed out") {
		return StatusTimeout, "dns lookup timed out"
	}
	return StatusFailure, "dog: " + msg
}

// fillFromResponse sets the records, status and trust from one response.
func fillFromResponse(l *Lookup, resp *dogResponse) {
	addAnswers(l, resp.Answers)
	for _, rec := range resp.Authorities {
		if rr, ok := dogRR(rec); ok && rr.Type == "SOA" {
			l.rrs = append(l.rrs, rr)
		}
	}
	setStatus(l, resp)
}

// addAnswers keeps the records of the queried type and the CNAME chain.
func addAnswers(l *Lookup, answers []dogRecord) {
	for _, rec := range answers {
		rr, ok := dogRR(rec)
		if !ok {
			continue // a type domaintest never reads, such as a DNAME
		}
		l.rrs = append(l.rrs, rr)
		switch rr.Type {
		case l.Type:
			l.Records = append(l.Records, rr.RData)
		case "CNAME":
			l.CNAME = append(l.CNAME, rr.RData)
		}
	}
}

// setStatus maps the rcode to a status and, for an answer, the AD bit to
// a trust level.
func setStatus(l *Lookup, resp *dogResponse) {
	switch rcode := resp.Flags.Rcode; {
	case rcode == "NXDOMAIN":
		l.Status = StatusNXDomain
	case rcode != "NOERROR":
		l.Status, l.Error = StatusFailure, "resolver answered "+rcode
		return
	case len(l.Records) > 0:
		l.Status = StatusOK
	default:
		l.Status = StatusNXRRSet
	}
	l.Trust = TrustInsecure
	if resp.Flags.AD {
		l.Trust = TrustSecure
	}
}

// dogRR converts one record from dog's JSON into an RR whose rdata is the
// presentation form BIND tools print, which is what the report has always
// carried.
func dogRR(rec dogRecord) (RR, bool) {
	rr := RR{Owner: strings.ToLower(rec.Name), TTL: rec.TTL, Type: rec.Type}
	render, ok := rdataRenderers[rec.Type]
	if !ok {
		return RR{}, false
	}
	d := dogData(rec.Data)
	rr.RData = render(d)
	switch rr.Type {
	case "TXT":
		for _, s := range d.strs("messages") {
			rr.RDLen += len(s) + txtLengthOctets(len(s))
		}
	case "CNAME":
		rr.RDLen = wireNameLen(rr.RData)
	}
	return rr, true
}

// txtLengthOctets is how many character-string length octets carried a dog
// TXT message of n bytes. dog joins a 255-byte character-string with the
// one after it (its reader treats 255 as "continued"), so a message longer
// than 255 bytes was several strings on the wire: osu.edu's 360-byte SPF
// record is 255 + 105, two length octets, and counting one made the answer
// an octet short. A non-zero multiple of 255 is taken to have ended the
// record; an empty message is one empty string.
func txtLengthOctets(n int) int {
	if n == 0 {
		return 1
	}
	return (n + 254) / 255
}

// dogData reads the fields of one record's data object.
type dogData map[string]json.RawMessage

func (d dogData) str(k string) string {
	var s string
	if err := json.Unmarshal(d[k], &s); err != nil {
		return ""
	}
	return s
}

func (d dogData) num(k string) int64 {
	var n int64
	if err := json.Unmarshal(d[k], &n); err != nil {
		return 0
	}
	return n
}

func (d dogData) flag(k string) bool {
	var b bool
	return json.Unmarshal(d[k], &b) == nil && b
}

func (d dogData) strs(k string) []string {
	var ss []string
	if err := json.Unmarshal(d[k], &ss); err != nil {
		return nil
	}
	return ss
}

// rdataRenderers render each record type domaintest reads in BIND's
// presentation format. Hex digests are upper case, as BIND prints them.
// A TXT record is its character-strings joined, as the checks read it.
var rdataRenderers = map[string]func(dogData) string{
	"A":     func(d dogData) string { return d.str("address") },
	"AAAA":  func(d dogData) string { return d.str("address") },
	"NS":    func(d dogData) string { return d.str("nameserver") },
	"CNAME": func(d dogData) string { return d.str("domain") },
	"PTR":   func(d dogData) string { return d.str("cname") },
	"MX": func(d dogData) string {
		return fmt.Sprintf("%d %s", d.num("preference"), d.str("exchange"))
	},
	"TXT": func(d dogData) string { return strings.Join(d.strs("messages"), "") },
	"CAA": func(d dogData) string {
		flags := 0
		if d.flag("critical") {
			flags = 128
		}
		return fmt.Sprintf("%d %s %s", flags, d.str("tag"), strconv.Quote(d.str("value")))
	},
	"TLSA": func(d dogData) string {
		return fmt.Sprintf("%d %d %d %s", d.num("certificate_usage"), d.num("selector"), d.num("matching_type"), strings.ToUpper(d.str("certificate_data")))
	},
	"DS": func(d dogData) string {
		return fmt.Sprintf("%d %d %d %s", d.num("key_tag"), d.num("algorithm"), d.num("digest_type"), strings.ToUpper(d.str("digest")))
	},
	"DNSKEY": func(d dogData) string {
		return fmt.Sprintf("%d %d %d %s", d.num("flags"), d.num("protocol"), d.num("algorithm"), d.str("public_key"))
	},
	"SOA": func(d dogData) string {
		return fmt.Sprintf("%s %s %d %d %d %d %d", d.str("mname"), d.str("rname"), d.num("serial"), d.num("refresh"), d.num("retry"), d.num("expire"), d.num("minimum"))
	},
}
