package main

import (
	"testing"
)

func TestParseRR(t *testing.T) {
	cases := []struct {
		in   string
		want RR
		ok   bool
	}{
		{"jschmidt.org. 3020 IN MX 0 mail.example.", RR{Owner: "jschmidt.org.", TTL: 3020, Type: "MX", RData: "0 mail.example."}, true},
		{"org. RRSIG SOA ...", RR{Owner: "org.", Type: "RRSIG", RData: "SOA ..."}, true},
		{"jschmidt.org. SOA ns1. host. 1 2 3 4 5", RR{Owner: "jschmidt.org.", Type: "SOA", RData: "ns1. host. 1 2 3 4 5"}, true},
		{`Example.COM. 60 IN TXT "v=spf1" " -all"`, RR{Owner: "example.com.", TTL: 60, Type: "TXT", RData: "v=spf1 -all", RDLen: 13}, true}, // 1+6 and 1+5
		{"x.", RR{}, false},
		{"", RR{}, false},
		{"x. 300 IN", RR{}, false},
	}
	for _, c := range cases {
		got, ok := parseRR(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("parseRR(%q) = %+v,%v; want %+v,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestJoinTXT(t *testing.T) {
	cases := map[string]string{
		`"v=spf1 include:outlook.com ~all"`: "v=spf1 include:outlook.com ~all",
		`"abc" "def"`:                       "abcdef",
		`"say \"hi\" \\ done"`:              `say "hi" \ done`,
		`"tab\009here" "\195\169"`:          "tab\there\u00e9", // dig's \DDD escapes are single octets
		`unquoted`:                          "unquoted",
		`""`:                                "",
	}
	for in, want := range cases {
		if got := joinTXT(in); got != want {
			t.Errorf("joinTXT(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTXTStrings(t *testing.T) {
	// amazonses.com's SPF as dig prints it: two character-strings.
	rd := `"v=spf1 ip4:199.255.192.0/22 " "ip4:98.77.0.0/16 -all"`
	strs := txtStrings(rd)
	check(t, "two strings", len(strs), 2)
	check(t, "second", strs[1], "ip4:98.77.0.0/16 -all")
	rr, _ := parseRR(`amazonses.com. 900 IN TXT ` + rd)
	check(t, "rdlen counts a length octet per string", rr.RDLen, 1+len(strs[0])+1+len(strs[1]))
	check(t, "joined", rr.RData, strs[0]+strs[1])
	c, _ := parseRR(`a.example. 60 IN CNAME b.example.`)
	check(t, "cname rdlen", c.RDLen, 11)
	check(t, "unquoted single string", txtStrings("plain"), []string{"plain"})
}

func TestWireNameLen(t *testing.T) {
	check(t, "root", wireNameLen("."), 1)
	check(t, "empty", wireNameLen(""), 1)
	check(t, "apex", wireNameLen("datapulse.global."), 18)
	check(t, "no dot", wireNameLen("datapulse.global"), 18)
}

func TestUDPAnswerOctets(t *testing.T) {
	// Expected sizes are what dig +noedns reported for the live answers the
	// fixtures were captured from.
	cases := []struct {
		file string
		name string
		want int
	}{
		{"dog/mail/spf_datapulse_global.json", "datapulse.global", 413},
		{"dog/mail/spf_jasadvisors_com.json", "jasadvisors.com", 250},
		{"dog/mail/spf_spf_jasadvisors_com.json", "spf.jasadvisors.com", 155},
		{"dog/mail/spf_datapulse_jitbit_com.json", "datapulse.jitbit.com", 128},
		{"dog/mail/spf_amazonses_com.json", "amazonses.com", 523},
	}
	for _, c := range cases {
		l := dogFixture(t, c.file, "TXT")
		l.Name = c.name
		check(t, c.file, l.udpAnswerOctets(), c.want)
		l.Name = "" // falls back to the first record's owner
		check(t, c.file+" (owner fallback)", l.udpAnswerOctets(), c.want)
	}
	// A CNAME chain counts: 12 + question (9+2+4) + CNAME (12+11) + TXT (12+2).
	chain := Lookup{Type: "TXT", rrs: []RR{
		{Owner: "a.example.", Type: "CNAME", RData: "b.example.", RDLen: wireNameLen("b.example.")},
		{Owner: "b.example.", Type: "TXT", RData: "x", RDLen: 2},
	}}
	chain.Name = "a.example"
	check(t, "cname chain", chain.udpAnswerOctets(), 64)
	// Negative answers and other types size to nothing useful.
	neg := dogFixture(t, "dog/jschmidt_aaaa_nxrrset.json", "TXT")
	neg.Name = "jschmidt.org"
	check(t, "nxrrset", neg.udpAnswerOctets(), 12+18)
	a := dogFixture(t, "dog/google_a_unsigned.json", "A")
	check(t, "non-TXT", a.udpAnswerOctets(), 0)
}

func TestUnquoteYAML(t *testing.T) {
	if got := unquoteYAML(`'it''s "x"'`); got != `it's "x"` {
		t.Errorf("got %q", got)
	}
	if got := unquoteYAML("plain"); got != "plain" {
		t.Errorf("got %q", got)
	}
}

func TestLookupPredicates(t *testing.T) {
	ok := Lookup{Status: StatusOK, Records: []string{"x"}}
	empty := Lookup{Status: StatusOK}
	neg := Lookup{Status: StatusNXRRSet}
	fail := Lookup{Status: StatusFailure}
	if !ok.HasRecords() || empty.HasRecords() || neg.HasRecords() {
		t.Error("HasRecords wrong")
	}
	if !ok.Answered() || !neg.Answered() || fail.Answered() || (Lookup{}).Answered() {
		t.Error("Answered wrong")
	}
	if len((Lookup{Records: []string{"not-an-ip", "::ffff:1.2.3.4"}}).Addrs()) != 1 {
		t.Error("Addrs should skip non-IP rdata and unmap v4-mapped")
	}
}

// A TXT or CAA value is kept as printed. Rebuilding the rdata from its
// fields collapsed the double space inside the quotes below, so the record
// read back differently and its wire length came out short.
func TestParseRR_KeepsSpacesInsideQuotes(t *testing.T) {
	rr, ok := parseRR(`example.com. 300 IN TXT "a  b" "c	d"`)
	check(t, "parsed", ok, true)
	check(t, "txt", rr.RData, "a  bc\td")
	check(t, "wire length", rr.RDLen, 1+4+1+3)

	rr, _ = parseRR(`example.com. 300 IN CAA 0 iodef "mailto:a  b@example.com"`)
	check(t, "caa", rr.RData, `0 iodef "mailto:a  b@example.com"`)

	rr, _ = parseRR(`org. RRSIG SOA 8 1 900 20260101000000 20251201000000 1 org. AAAA`)
	check(t, "abbreviated record", []string{rr.Type, rr.RData}, []string{"RRSIG", "SOA 8 1 900 20260101000000 20251201000000 1 org. AAAA"})
	check(t, "fields helper at the end", afterFields("a b", 2), "")
}
