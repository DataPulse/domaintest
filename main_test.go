package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
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
		{[]string{"jschmidt.org"}, "jschmidt.org", "", []string{familyIPv4, familyIPv6}, 5, ""},
		{[]string{"jschmidt.org", "@8.8.8.8"}, "jschmidt.org", "8.8.8.8", []string{familyIPv4, familyIPv6}, 5, familyIPv4},
		{[]string{"@8.8.8.8", "jschmidt.org", "-t", "10"}, "jschmidt.org", "8.8.8.8", []string{familyIPv4, familyIPv6}, 10, familyIPv4},
		{[]string{"-t", "3", "jschmidt.org", "@8.8.8.8"}, "jschmidt.org", "8.8.8.8", []string{familyIPv4, familyIPv6}, 3, familyIPv4},
		{[]string{"-6", "@2001:4860:4860::8888", "Example.COM."}, "example.com", "2001:4860:4860::8888", []string{familyIPv6}, 5, familyIPv6},
		{[]string{"-4", "osu.edu"}, "osu.edu", "", []string{familyIPv4}, 5, ""},
		{[]string{"-4", "-6", "osu.edu"}, "osu.edu", "", []string{familyIPv4, familyIPv6}, 5, ""},
		{[]string{"osu.edu", "@dns.google"}, "osu.edu", "dns.google", []string{familyIPv4, familyIPv6}, 5, ""},
		{[]string{"-t=7", "osu.edu"}, "osu.edu", "", []string{familyIPv4, familyIPv6}, 7, ""},
	}
	for _, c := range cases {
		cfg, err := parseArgs(c.args)
		if err != nil {
			t.Errorf("%v: %v", c.args, err)
			continue
		}
		if cfg.Domain != c.domain || cfg.Server != c.server || cfg.TimeoutSec != c.timeout || cfg.dnsFamily != c.dnsFam {
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
	if !cfg.Pretty || cfg.QuicPath != "/opt/qp" || cfg.DelvPath != "/opt/delv" || cfg.DigPath != "/opt/dig" {
		t.Errorf("got %+v", cfg)
	}
	if !cfg.wantsFamily(familyIPv4) || cfg.timeout().Seconds() != 5 {
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
	good := map[string]string{
		"JSCHMIDT.ORG.": "jschmidt.org",
		" osu.edu ":     "osu.edu",
		"_dmarc.x.org":  "_dmarc.x.org",
		"xn--bcher-kva": "xn--bcher-kva",
		"a-b.c-d.org":   "a-b.c-d.org",
	}
	for in, want := range good {
		if got, err := normalizeDomain(in); err != nil || got != want {
			t.Errorf("normalizeDomain(%q) = %q, %v; want %q", in, got, err, want)
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
