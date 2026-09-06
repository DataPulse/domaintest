package main

import (
	"context"
	"strings"
)

// digMessage is one response (or error) in `dig +yaml` output. A single dig
// invocation may carry several queries and therefore several messages.
type digMessage struct {
	Status     string   // rcode: NOERROR, REFUSED, ...
	Flags      []string // header flags: qr aa rd ra ad
	Protocol   string   // UDP or TCP
	Answer     []RR
	Authority  []RR
	Additional []RR
	OPT        bool     // an EDNS OPT pseudo-record was present
	EDNSFlags  []string // e.g. "do"
	Error      string   // set for DIG_ERROR entries ("no servers could be reached")
}

// hasFlag reports whether the header carried flag f (e.g. "aa").
func (m digMessage) hasFlag(f string) bool {
	for _, x := range m.Flags {
		if x == f {
			return true
		}
	}
	return false
}

// records returns the RRs of one type from the answer section.
func (m digMessage) records(rtype string) []RR {
	var out []RR
	for _, rr := range m.Answer {
		if rr.Type == rtype {
			out = append(out, rr)
		}
	}
	return out
}

// parseDigYAML turns dig's +yaml stream into messages. It is a small state
// machine over the fixed indentation dig uses; sections are recognised by
// their keys and record lines by the "- '" prefix.
func parseDigYAML(out string) []digMessage {
	var msgs []digMessage
	var cur *digMessage
	section := ""
	inEDNS := false
	inError := false
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "- type: MESSAGE":
			msgs = append(msgs, digMessage{})
			cur, section, inEDNS, inError = &msgs[len(msgs)-1], "", false, false
		case line == "- type: DIG_ERROR":
			msgs = append(msgs, digMessage{})
			cur, section, inEDNS, inError = &msgs[len(msgs)-1], "", false, true
		case cur == nil:
			continue
		case inError:
			if !strings.HasPrefix(line, "message:") && line != "" {
				cur.Error = strings.TrimSpace(cur.Error + " " + line)
			}
		default:
			parseDigLine(cur, line, &section, &inEDNS)
		}
	}
	return msgs
}

// parseDigLine updates the current message from one trimmed line.
func parseDigLine(m *digMessage, line string, section *string, inEDNS *bool) {
	switch {
	case strings.HasPrefix(line, "socket_protocol:"):
		m.Protocol = strings.TrimSpace(strings.TrimPrefix(line, "socket_protocol:"))
	case strings.HasPrefix(line, "status:"):
		m.Status = strings.TrimSpace(strings.TrimPrefix(line, "status:"))
	case line == "OPT_PSEUDOSECTION:":
		*inEDNS = true
	case line == "EDNS:":
		m.OPT = true
	case strings.HasPrefix(line, "flags:"):
		fields := strings.Fields(strings.TrimPrefix(line, "flags:"))
		if *inEDNS {
			m.EDNSFlags = fields
		} else {
			m.Flags = fields
		}
	case strings.HasSuffix(line, "_SECTION:"):
		*section = strings.TrimSuffix(line, "_SECTION:")
		*inEDNS = false
	case strings.HasPrefix(line, "- '"):
		if rr, ok := parseRR(unquoteYAML(line[2:])); ok {
			appendSection(m, *section, rr)
		}
	}
}

func appendSection(m *digMessage, section string, rr RR) {
	switch section {
	case "ANSWER":
		m.Answer = append(m.Answer, rr)
	case "AUTHORITY":
		m.Authority = append(m.Authority, rr)
	case "ADDITIONAL":
		m.Additional = append(m.Additional, rr)
	}
}

// runDig executes dig and parses its +yaml output. A timeout yields a single
// synthetic error message so callers see one shape.
func runDig(ctx context.Context, r Runner, digPath string, args ...string) []digMessage {
	stdout, stderr, err := r.Run(ctx, digPath, args...)
	if isTimeout(ctx, err) {
		return []digMessage{{Error: "dig timed out"}}
	}
	msgs := parseDigYAML(string(stdout))
	if len(msgs) == 0 {
		detail := strings.TrimSpace(string(stderr))
		if err != nil && detail == "" {
			detail = err.Error()
		}
		return []digMessage{{Error: firstNonEmpty(detail, "dig produced no output")}}
	}
	return msgs
}
