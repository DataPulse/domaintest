package main

import (
	"context"
	"testing"
	"time"
)

func TestParseDigYAML_MultiQuery(t *testing.T) {
	msgs := parseDigYAML(fixture(t, "dig/ns/jschmidt_at_ns-507.yaml"))
	check(t, "three messages", len(msgs), 3)
	check(t, "udp first", msgs[0].Protocol, "UDP")
	check(t, "tcp second", msgs[1].Protocol, "TCP")
	check(t, "aa on every answer", msgs[0].hasFlag("aa") && msgs[1].hasFlag("aa") && msgs[2].hasFlag("aa"), true)
	check(t, "status", msgs[0].Status, "NOERROR")
	check(t, "OPT present", msgs[0].OPT, true)
	check(t, "do flag on the dnssec query", msgs[2].EDNSFlags, []string{"do"})
	check(t, "no do flag on the plain query", len(msgs[0].EDNSFlags), 0)
	soa := msgs[0].records("SOA")
	check(t, "one SOA", len(soa), 1)
	check(t, "serial", soaSerial(soa[0].RData), int64(1))
	check(t, "RRSIG in dnssec answer", len(msgs[2].records("RRSIG")), 1)
}

func TestParseDigYAML_RefusedAndError(t *testing.T) {
	msgs := parseDigYAML(fixture(t, "dig/ns/jschmidt_at_ns1_google_refused.yaml"))
	check(t, "messages", len(msgs) >= 1, true)
	check(t, "refused", msgs[0].Status, "REFUSED")
	check(t, "not aa", msgs[0].hasFlag("aa"), false)

	errs := parseDigYAML(fixture(t, "dig/ns/unreachable.yaml"))
	check(t, "one error entry", len(errs), 1)
	check(t, "error text", errs[0].Error, "no servers could be reached")
	check(t, "empty input", len(parseDigYAML("")), 0)
}

func TestParseDigYAML_Sections(t *testing.T) {
	msgs := parseDigYAML(fixture(t, "dig/ns/glue_google_at_gtld.yaml"))
	check(t, "one message", len(msgs), 1)
	m := msgs[0]
	check(t, "referral has no answer", len(m.Answer), 0)
	check(t, "authority NS", len(m.Authority) >= 4, true)
	check(t, "authority type", m.Authority[0].Type, "NS")
	var a, aaaa int
	for _, rr := range m.Additional {
		switch rr.Type {
		case "A":
			a++
		case "AAAA":
			aaaa++
		}
	}
	check(t, "glue A records", a, 4)
	check(t, "glue AAAA records", aaaa, 4)
	check(t, "flags", m.Flags, []string{"qr"})
}

func TestRunDig(t *testing.T) {
	r := newFakeRunner()
	r.on("dig", []string{"x"}, fakeCall{stdout: fixture(t, "dig/ns/jschmidt_at_ns-507.yaml")})
	r.on("dig", []string{"bad"}, fakeCall{stderr: "dig: couldn't get address", err: errFake})
	r.on("dig", []string{"slow"}, fakeCall{delay: time.Second})
	check(t, "parsed", len(runDig(context.Background(), r, "dig", "x")), 3)
	bad := runDig(context.Background(), r, "dig", "bad")
	check(t, "stderr surfaces", bad[0].Error, "dig: couldn't get address")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	check(t, "timeout", runDig(ctx, r, "dig", "slow")[0].Error, "dig timed out")
	check(t, "unknown call", runDig(context.Background(), r, "dig", "nothing")[0].Error != "", true)
}
