package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestParseArgs_Forms(t *testing.T) {
	cases := []struct {
		args     []string
		domain   string
		server   string
		families []string
		timeout  int
		dnsFam   string
	}{
		{[]string{"jschmidt.org"}, "jschmidt.org", "system", []string{familyIPv4, familyIPv6}, 3, ""},
		{[]string{"jschmidt.org", "@8.8.8.8"}, "jschmidt.org", "8.8.8.8", []string{familyIPv4, familyIPv6}, 3, familyIPv4},
		{[]string{"jschmidt.org", "@127.0.0.1:5353"}, "jschmidt.org", "127.0.0.1:5353", []string{familyIPv4, familyIPv6}, 3, familyIPv4},
		{[]string{"jschmidt.org", "@[::1]:5353"}, "jschmidt.org", "[::1]:5353", []string{familyIPv4, familyIPv6}, 3, familyIPv6},
		{[]string{"jschmidt.org", "@localhost:5353"}, "jschmidt.org", "localhost:5353", []string{familyIPv4, familyIPv6}, 3, ""},
		{[]string{"münchen.de"}, "xn--mnchen-3ya.de", "system", []string{familyIPv4, familyIPv6}, 3, ""},
		{[]string{"XN--MNCHEN-3YA.DE."}, "xn--mnchen-3ya.de", "system", []string{familyIPv4, familyIPv6}, 3, ""},
		{[]string{"@8.8.8.8", "jschmidt.org", "-t", "10"}, "jschmidt.org", "8.8.8.8", []string{familyIPv4, familyIPv6}, 10, familyIPv4},
		{[]string{"-t", "3", "jschmidt.org", "@8.8.8.8"}, "jschmidt.org", "8.8.8.8", []string{familyIPv4, familyIPv6}, 3, familyIPv4},
		{[]string{"-6", "@2001:4860:4860::8888", "Example.COM."}, "example.com", "2001:4860:4860::8888", []string{familyIPv6}, 3, familyIPv6},
		{[]string{"-4", "osu.edu"}, "osu.edu", "system", []string{familyIPv4}, 3, ""},
		{[]string{"-4", "-6", "osu.edu"}, "osu.edu", "system", []string{familyIPv4, familyIPv6}, 3, ""},
		{[]string{"osu.edu", "@dns.google"}, "osu.edu", "dns.google", []string{familyIPv4, familyIPv6}, 3, ""},
		{[]string{"-t=7", "osu.edu"}, "osu.edu", "system", []string{familyIPv4, familyIPv6}, 7, ""},
	}
	for _, c := range cases {
		cfg, err := parseArgs(c.args)
		if err != nil {
			t.Errorf("%v: %v", c.args, err)
			continue
		}
		if cfg.Domain != c.domain || cfg.Resolver.String() != c.server || cfg.TimeoutSec != c.timeout || cfg.dnsFamily != c.dnsFam {
			t.Errorf("%v: got %+v", c.args, cfg)
		}
		if !reflect.DeepEqual(cfg.Families, c.families) {
			t.Errorf("%v: families %v, want %v", c.args, cfg.Families, c.families)
		}
	}
}

func TestParseArgs_FlagsAndPaths(t *testing.T) {
	cfg, err := parseArgs([]string{"-pretty", "-quicprobe", "/opt/qp", "-delv", "/opt/delv", "-dig", "/opt/dig", "x.org"})
	if err != nil {
		t.Fatal(err)
	}
	check(t, "default quic timeout", cfg.QuicTimeoutSec, defaultQuicTimeoutSec)
	qcfg, err := parseArgs([]string{"x.org", "-quic-timeout", "7", "@1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	check(t, "quic timeout flag", qcfg.QuicTimeoutSec, 7)
	check(t, "domain after value flag", qcfg.Domain, "x.org")
	if !cfg.Pretty || cfg.QuicPath != "/opt/qp" || cfg.DelvPath != "/opt/delv" || cfg.DigPath != "/opt/dig" {
		t.Errorf("got %+v", cfg)
	}
	check(t, "default tcp timeout", cfg.TCPTimeoutSec, defaultTCPTimeoutSec)
	check(t, "tcp timeout duration", cfg.tcpTimeout(), 2*time.Second)
	tcfg, err := parseArgs([]string{"-tcp-timeout", "4", "x.org"})
	if err != nil {
		t.Fatal(err)
	}
	check(t, "tcp timeout flag", tcfg.TCPTimeoutSec, 4)
	if !cfg.wantsFamily(familyIPv4) || cfg.timeout().Seconds() != 3 {
		t.Errorf("helpers wrong: %+v", cfg)
	}
}

func TestParseArgs_Errors(t *testing.T) {
	cases := [][]string{
		{},
		{"-t", "3"},
		{"a.org", "b.org"},
		{"@1.1.1.1", "@8.8.8.8", "a.org"},
		{"-t", "x", "a.org"},
		{"-t", "0", "a.org"},
		{"-t", "-2", "a.org"},
		{"-quic-timeout", "0", "a.org"},
		{"-quic-timeout", "x", "a.org"},
		{"-tcp-timeout", "0", "a.org"},
		{"@127.0.0.1:0", "a.org"},
		{"@127.0.0.1:99999", "a.org"},
		{"@127.0.0.1:abc", "a.org"},
		{"@", "a.org"},
		{"xn--zzzz-invalid-punycode-9999999.com"},
		{"ex@mple.com"},
		{"-bogus", "a.org"},
		{"-bad.com"},
		{"a..b"},
		{"exa mple.com"},
		{"."},
		{strings.Repeat("a", 64) + ".com"},
		{strings.Repeat("abcdefghij.", 30) + "com"},
		{"-t"},
	}
	for _, args := range cases {
		if _, err := parseArgs(args); err == nil {
			t.Errorf("expected error for %v", args)
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	cases := []struct{ in, ascii, unicode string }{
		{"JSCHMIDT.ORG.", "jschmidt.org", ""},
		{" osu.edu ", "osu.edu", ""},
		{"_dmarc.x.org", "_dmarc.x.org", ""},
		{"a-b.c-d.org", "a-b.c-d.org", ""},
		// IDN: U-label in, A-label out, U-label reported.
		{"münchen.de", "xn--mnchen-3ya.de", "münchen.de"},
		{"MÜNCHEN.DE.", "xn--mnchen-3ya.de", "münchen.de"},
		{"bücher.ch", "xn--bcher-kva.ch", "bücher.ch"},
		{"日本.jp", "xn--wgv71a.jp", "日本.jp"},
		{"www.münchen.de", "www.xn--mnchen-3ya.de", "www.münchen.de"},
		// IDN: A-label in, unchanged out, U-label reported.
		{"xn--mnchen-3ya.de", "xn--mnchen-3ya.de", "münchen.de"},
		{"XN--MCROSOFT-C2A.COM", "xn--mcrosoft-c2a.com", "mícrosoft.com"},
		// Mixed labels.
		{"shop.münchen.de", "shop.xn--mnchen-3ya.de", "shop.münchen.de"},
	}
	for _, c := range cases {
		ascii, unicode, err := normalizeDomain(c.in)
		if err != nil {
			t.Errorf("normalizeDomain(%q): %v", c.in, err)
			continue
		}
		check(t, "ascii for "+c.in, ascii, c.ascii)
		check(t, "unicode for "+c.in, unicode, c.unicode)
	}
	// U+200B (zero-width space) is an ignored code point under UTS 46 mapping,
	// so "exa\u200bmple.com" quietly becomes example.com rather than failing.
	if got, _, err := normalizeDomain("exa\u200bmple.com"); err != nil || got != "example.com" {
		t.Errorf("zero-width space should be dropped by mapping, got %q %v", got, err)
	}
	for _, bad := range []string{"", ".", "-bad.com", "a..b", "exa mple.com", "ex@mple.com", "xn--a.com", "xn--zzzz-invalid-punycode-9999999.com", strings.Repeat("ü", 60) + ".de"} {
		if _, _, err := normalizeDomain(bad); err == nil {
			t.Errorf("normalizeDomain(%q) should fail", bad)
		}
	}
}

func TestParseResolver(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
		args string
		text string
	}{
		{"8.8.8.8", "8.8.8.8", 0, "@8.8.8.8", "8.8.8.8"},
		{"127.0.0.1:5353", "127.0.0.1", 5353, "@127.0.0.1 -p 5353", "127.0.0.1:5353"},
		{"2001:4860:4860::8888", "2001:4860:4860::8888", 0, "@2001:4860:4860::8888", "2001:4860:4860::8888"},
		{"[2001:db8::1]:5353", "2001:db8::1", 5353, "@2001:db8::1 -p 5353", "[2001:db8::1]:5353"},
		{"dns.google", "dns.google", 0, "@dns.google", "dns.google"},
		{"localhost:5353", "localhost", 5353, "@localhost -p 5353", "localhost:5353"},
	}
	for _, c := range cases {
		r, err := parseResolver(c.in)
		if err != nil {
			t.Errorf("parseResolver(%q): %v", c.in, err)
			continue
		}
		check(t, "host "+c.in, r.Host, c.host)
		check(t, "port "+c.in, r.Port, c.port)
		check(t, "args "+c.in, strings.Join(r.args(), " "), c.args)
		check(t, "string "+c.in, r.String(), c.text)
	}
	check(t, "system resolver args", resolver{}.args(), []string(nil))
	check(t, "system resolver string", resolver{}.String(), "system")
	// "::1:5353" is a valid IPv6 literal, so it is an address, not ::1 plus a port.
	if r, err := parseResolver("::1:5353"); err != nil || r.Port != 0 || r.Host != "::1:5353" {
		t.Errorf("::1:5353 should parse as a bare IPv6 address, got %+v %v", r, err)
	}
	for _, bad := range []string{"", "1.2.3.4:", "1.2.3.4:0", "1.2.3.4:65536", "1.2.3.4:x", "[::1]", "a:b:c"} {
		if _, err := parseResolver(bad); err == nil {
			t.Errorf("parseResolver(%q) should fail", bad)
		}
	}
}

func TestSplitArgs(t *testing.T) {
	flags, pos, server, err := splitArgs([]string{"-t", "3", "a.org", "@1.1.1.1", "-pretty", "-quicprobe=/x", "-"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(flags, []string{"-t", "3", "-pretty", "-quicprobe=/x"}) {
		t.Errorf("flags %v", flags)
	}
	if !reflect.DeepEqual(pos, []string{"a.org", "-"}) || server != "1.1.1.1" {
		t.Errorf("pos %v server %q", pos, server)
	}
}

func TestServerFamily(t *testing.T) {
	cases := map[string]string{"8.8.8.8": familyIPv4, "::ffff:8.8.8.8": familyIPv4, "2001:4860:4860::8888": familyIPv6, "dns.google": "", "": ""}
	for in, want := range cases {
		if got := serverFamily(in); got != want {
			t.Errorf("serverFamily(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRealMain_UsageAndMissingTools(t *testing.T) {
	var out, errBuf bytes.Buffer
	if rc := realMain(nil, &out, &errBuf); rc != 2 || !strings.Contains(errBuf.String(), "usage:") || out.Len() != 0 {
		t.Errorf("no args: rc %d stdout %q stderr %q", rc, out.String(), errBuf.String())
	}
	errBuf.Reset()
	if rc := realMain([]string{"-t", "x", "a.org"}, &out, &errBuf); rc != 2 {
		t.Errorf("bad -t: rc %d", rc)
	}
	errBuf.Reset()
	rc := realMain([]string{"-delv", "/nonexistent/delv", "a.org"}, &out, &errBuf)
	if rc != 2 || !strings.Contains(errBuf.String(), "not found") {
		t.Errorf("missing delv: rc %d stderr %q", rc, errBuf.String())
	}
	errBuf.Reset()
	t.Setenv("PATH", t.TempDir())
	t.Chdir(t.TempDir()) // keep the ../quicprobe sibling fallback out of reach
	rc = realMain([]string{"-delv", "/bin/true", "-dig", "/bin/true", "a.org"}, &out, &errBuf)
	if rc != 2 || !strings.Contains(errBuf.String(), "quicprobe") {
		t.Errorf("missing quicprobe: rc %d stderr %q", rc, errBuf.String())
	}
}

func TestWriteReport(t *testing.T) {
	rep := &Report{Domain: "x.org", Errors: []string{}, Warnings: []string{}, OK: true}
	var compact, pretty bytes.Buffer
	if err := writeReport(&compact, rep, false); err != nil {
		t.Fatal(err)
	}
	if err := writeReport(&pretty, rep, true); err != nil {
		t.Fatal(err)
	}
	if strings.Count(compact.String(), "\n") != 1 {
		t.Errorf("compact output should be a single line: %q", compact.String())
	}
	if !strings.Contains(pretty.String(), "\n  \"domain\"") {
		t.Errorf("pretty output should be indented: %q", pretty.String())
	}
	var back Report
	if err := json.Unmarshal(compact.Bytes(), &back); err != nil || back.Domain != "x.org" {
		t.Errorf("round trip failed: %v", err)
	}
}

func TestParseArgs_HSTSCacheAndWarm(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", "/tmp/example-cache")
	cfg, err := parseArgs([]string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	check(t, "default cache path", cfg.HSTSCache, "/tmp/example-cache/domaintest/hsts-preload.tsv")
	check(t, "warm off", cfg.WarmHSTSCache, false)
	check(t, "preload on", cfg.HSTSPreload, true)

	cfg, err = parseArgs([]string{"-hsts-cache", "/var/tmp/x.tsv", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	check(t, "explicit cache path", cfg.HSTSCache, "/var/tmp/x.tsv")

	cfg, err = parseArgs([]string{"-warm-hsts-cache"})
	if err != nil {
		t.Fatal(err)
	}
	check(t, "warm needs no domain", cfg.WarmHSTSCache, true)
	check(t, "warm still resolves the cache path", cfg.HSTSCache, "/tmp/example-cache/domaintest/hsts-preload.tsv")

	for _, args := range [][]string{{"-warm-hsts-cache", "example.com"}, {"-hsts-cache"}} {
		if _, err := parseArgs(args); err == nil {
			t.Errorf("expected an error for %v", args)
		}
	}
}

func TestRealMain_WarmMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hsts-preload.tsv")
	stubList(t, &preloadList{entries: map[string]bool{"app": true}}, nil)
	var out, errBuf bytes.Buffer
	rc := realMain([]string{"-warm-hsts-cache", "-hsts-cache", path}, &out, &errBuf)
	check(t, "exit 0", rc, 0)
	check(t, "nothing on stdout", out.String(), "")
	check(t, "cache written", fileExists(path), true)
	check(t, "stderr names the cache", strings.Contains(errBuf.String(), path), true)
	check(t, "stderr names the lock", strings.Contains(errBuf.String(), "lock"), true)

	stubList(t, nil, errors.New("fetch failed on 10.0.0.2:53"))
	errBuf.Reset()
	rc = realMain([]string{"-warm-hsts-cache", "-hsts-cache", filepath.Join(dir, "other.tsv")}, &out, &errBuf)
	check(t, "exit 2 on failure", rc, 2)
	check(t, "reason on stderr", strings.Contains(errBuf.String(), "fetch failed"), true)
	check(t, "resolver scrubbed", strings.Contains(errBuf.String(), "10.0.0.2"), false)
}

func TestParseArgs_DNSConcurrency(t *testing.T) {
	cfg, err := parseArgs([]string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	check(t, "default is CPU-scaled", cfg.DNSConcurrency, defaultDNSConcurrency())
	check(t, "default never below 4", defaultDNSConcurrency() >= 4, true)
	check(t, "default is even multiple of CPUs or the floor", defaultDNSConcurrency() == maxInt(4, 2*runtime.NumCPU()), true)

	cfg, err = parseArgs([]string{"-dns-concurrency", "3", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	check(t, "explicit cap", cfg.DNSConcurrency, 3)

	cfg, err = parseArgs([]string{"-dns-concurrency", "0", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	check(t, "zero means unlimited", cfg.DNSConcurrency, 0)

	if _, err := parseArgs([]string{"-dns-concurrency", "-2", "example.com"}); err == nil {
		t.Error("a negative cap should be rejected")
	}
}

// A top-level domain is never all digits (RFC 3696 §2), which is what
// separates a hostname from a dotted-quad address. A leading digit
// elsewhere is fine and common: RFC 1123 §2.1 relaxed the old letter-first
// rule, and 29 names in the portdb corpus start with one.
func TestNormalizeDomain_AllNumericTLD(t *testing.T) {
	for _, bad := range []string{"1.1.1.1", "8.8.8.8", "192.168.0.1", "3.14", "255.255.255.255"} {
		if _, _, err := normalizeDomain(bad); err == nil {
			t.Errorf("%q accepted as a domain, want rejected", bad)
		}
	}
	for _, good := range []string{"333oracle.xyz", "1password.com", "7-eleven.com", "4chan.org", "365oracle.com", "1.example.com"} {
		if _, _, err := normalizeDomain(good); err != nil {
			t.Errorf("%q rejected: %v", good, err)
		}
	}
}

func TestAllDigits(t *testing.T) {
	for _, s := range []string{"1", "42", "0000"} {
		check(t, "digits: "+s, allDigits(s), true)
	}
	for _, s := range []string{"", "a", "1a", "a1", "1-2", "xn--0zwm56d"} {
		check(t, "not all digits: "+s, allDigits(s), false)
	}
}

// The full table of what is and is not a domain this tool will accept.
// Every rule is enforced in one place, so it is checked in one place.
func TestNormalizeDomain_Table(t *testing.T) {
	long63 := strings.Repeat("a", 63)
	for _, c := range []struct {
		in     string
		ascii  string // "" means the input must be rejected
		reason string
	}{
		// Accepted, with the normalisation applied.
		{"example.com", "example.com", "plain"},
		{"EXAMPLE.COM", "example.com", "lower-cased"},
		{"example.com.", "example.com", "trailing dot stripped"},
		{"  example.com  ", "example.com", "surrounding space trimmed"},
		{"münchen.de", "xn--mnchen-3ya.de", "u-label to A-label"},
		{"xn--mnchen-3ya.de", "xn--mnchen-3ya.de", "A-label kept"},
		{"com", "com", "a public suffix is a valid input"},
		{"co.uk", "co.uk", "multi-label suffix"},
		{long63 + ".com", long63 + ".com", "63-character label is the maximum"},
		{"a.b.c.d.e.f.example.com", "a.b.c.d.e.f.example.com", "deep names are fine"},
		{"_dmarc.example.com", "_dmarc.example.com", "underscore service label"},
		{"_443._tcp.example.com", "_443._tcp.example.com", "several service labels"},
		{"1password.com", "1password.com", "leading digit (RFC 1123 §2.1)"},
		{"333oracle.xyz", "333oracle.xyz", "leading digits, real corpus name"},
		{"7-eleven.com", "7-eleven.com", "digit and hyphen"},
		{"x--y.com", "x--y.com", "double hyphen inside a label"},

		// Rejected.
		{"", "", "empty"},
		{"   ", "", "only whitespace"},
		{".", "", "bare dot"},
		{".com", "", "empty first label"},
		{"a..b.com", "", "empty middle label"},
		{"a b.com", "", "space inside a label"},
		{"-bad.com", "", "label starts with a hyphen"},
		{"bad-.com", "", "label ends with a hyphen"},
		{"sub.-bad.com", "", "inner label starts with a hyphen"},
		{"sub.bad-.com", "", "inner label ends with a hyphen"},
		{strings.Repeat("a", 64) + ".com", "", "64-character label"},
		{strings.Repeat("a.", 127) + "com", "", "longer than 253 octets"},
		{"1.1.1.1", "", "all-numeric TLD is an address"},
		{"192.168.0.1", "", "all-numeric TLD is an address"},
		{"3.14", "", "all-numeric TLD"},
		{"foo._com", "", "underscore in the TLD"},
		{"example.c om", "", "space in the TLD"},
		{"2606:4700::1111", "", "IPv6 literal"},
	} {
		ascii, _, err := normalizeDomain(c.in)
		if c.ascii == "" {
			if err == nil {
				t.Errorf("%s: %q accepted as %q, want rejected", c.reason, c.in, ascii)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %q rejected: %v", c.reason, c.in, err)
			continue
		}
		check(t, c.reason+": "+c.in, ascii, c.ascii)
	}
}

func TestBadTLD(t *testing.T) {
	check(t, "all digits", badTLD("1") != "", true)
	check(t, "all digits, longer", badTLD("4700") != "", true)
	check(t, "underscore", badTLD("_com") != "", true)
	check(t, "underscore inside", badTLD("co_uk") != "", true)
	for _, ok := range []string{"com", "uk", "xn--p1ai", "museum", "co", "a1"} {
		check(t, "valid TLD: "+ok, badTLD(ok), "")
	}
}

// A domain beginning with a hyphen must say so rather than be reported as
// an unknown flag, and real flags must still parse.
func TestHyphenDomain(t *testing.T) {
	var cfg config
	fs, _, _, _ := newFlagSet(&cfg)
	for _, bad := range []string{"-badstart.com", "--badstart.com", "-sub.example.com"} {
		if err := hyphenDomain(fs, []string{bad}); err == nil {
			t.Errorf("%q: expected a domain error", bad)
		} else {
			check(t, "names the real problem: "+bad, strings.Contains(err.Error(), "must not start with a hyphen"), true)
		}
	}
	for _, good := range [][]string{
		{"-4"}, {"-6"}, {"-t", "3"}, {"-t=3"}, {"-pretty"},
		{"-quicprobe=/usr/local/bin/quicprobe.bin"}, // a known flag whose value has a dot
		{"example.com"}, {"-"}, {"--"},
	} {
		if err := hyphenDomain(fs, good); err != nil {
			t.Errorf("%v: unexpected error %v", good, err)
		}
	}
}
