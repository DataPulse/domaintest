package main

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseQUIC_Fixtures(t *testing.T) {
	cases := []struct {
		file      string
		supported bool
		alpn      string
		errPrefix string
	}{
		{"quicprobe/google_supported.json", true, "h3", ""},
		{"quicprobe/example_unsupported.json", false, "", "CRYPTO_ERROR"},
		{"quicprobe/nxdomain_error.json", false, "", "lookup nxdomain-quictest.invalid"},
		{"quicprobe/usage_error.json", false, "", "usage:"},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			q := parseQUIC([]byte(fixture(t, c.file)))
			check(t, "supported", q.Supported, c.supported)
			check(t, "alpn", q.ALPN, c.alpn)
			check(t, "error prefix", strings.HasPrefix(q.Error, c.errPrefix), true)
			if c.supported {
				check(t, "tls", q.TLSVersion, "TLS 1.3")
				check(t, "server_addr set", q.ServerAddr != "", true)
				check(t, "handshake_ms positive", q.HandshakeMs > 0, true)
			}
		})
	}
}

func TestParseQUIC_NewFieldsAndGarbage(t *testing.T) {
	in := `{"supported":true,"alpn":"h3","family":"ipv6","target_ip":"2001:db8::1","handshake_ms":9}`
	q := parseQUIC([]byte(in))
	if q.Family != familyIPv6 || q.TargetIP != "2001:db8::1" {
		t.Errorf("family/target not parsed: %+v", q)
	}
	out, _ := json.Marshal(q)
	if strings.Contains(string(out), "target_ip") || strings.Contains(string(out), "family") {
		t.Errorf("family/target_ip must be hidden in the report: %s", out)
	}
	for _, bad := range []string{"", "   \n", "not json", "{"} {
		if q := parseQUIC([]byte(bad)); q.Supported || q.Error == "" {
			t.Errorf("%q: expected error, got %+v", bad, q)
		}
	}
}

func TestQuicArgs(t *testing.T) {
	got := strings.Join(quicArgs("www.example.com", netip.MustParseAddr("2001:db8::1"), 4), " ")
	if got != "-ip 2001:db8::1 -t 4 www.example.com" {
		t.Errorf("got %q", got)
	}
	if !strings.Contains(strings.Join(quicArgs("x", netip.MustParseAddr("1.2.3.4"), 0), " "), "-t 1") {
		t.Error("timeout floor of 1s not applied")
	}
}

func TestProbeQUIC_FakeRunner(t *testing.T) {
	ip := netip.MustParseAddr("142.251.32.14")
	r := newFakeRunner()
	r.on("quicprobe", quicArgs("google.com", ip, 5), fakeCall{stdout: fixture(t, "quicprobe/google_supported.json")})
	r.on("quicprobe", quicArgs("broken.example", ip, 5), fakeCall{stderr: "boom", err: errFake})
	r.on("quicprobe", quicArgs("slow.example", ip, 5), fakeCall{delay: time.Second})

	if q := probeQUIC(context.Background(), r, "quicprobe", "google.com", ip, 5); !q.Supported {
		t.Errorf("unexpected %+v", q)
	}
	if q := probeQUIC(context.Background(), r, "quicprobe", "broken.example", ip, 5); q.Supported || !strings.Contains(q.Error, "boom") {
		t.Errorf("unexpected %+v", q)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if q := probeQUIC(ctx, r, "quicprobe", "slow.example", ip, 5); !strings.Contains(q.Error, "timed out") {
		t.Errorf("unexpected %+v", q)
	}
}

// fakeQuicprobe writes an executable stub named quicprobe into dir.
func fakeQuicprobe(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, quicprobeName)
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho '{}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFindQuicprobe_Explicit(t *testing.T) {
	fake := fakeQuicprobe(t, t.TempDir())
	p, err := findQuicprobe(fake)
	check(t, "err", err, nil)
	check(t, "path", p, fake)
	_, err = findQuicprobe(filepath.Join(t.TempDir(), "missing"))
	check(t, "missing explicit path errors", err != nil, true)
}

func TestFindQuicprobe_PATH(t *testing.T) {
	dir := t.TempDir()
	fake := fakeQuicprobe(t, dir)
	t.Setenv("PATH", dir)
	p, err := findQuicprobe("")
	check(t, "err", err, nil)
	check(t, "path", p, fake)
}

func TestFindQuicprobe_SiblingAndMissing(t *testing.T) {
	// Sibling directory relative to cwd: <cwd>/../quicprobe/quicprobe.
	t.Setenv("PATH", t.TempDir())
	root := t.TempDir()
	sibBin := fakeQuicprobe(t, filepath.Join(root, "quicprobe"))
	work := filepath.Join(root, "domaintest")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)
	p, err := findQuicprobe("")
	check(t, "err", err, nil)
	check(t, "path", p, sibBin)

	if err := os.Remove(sibBin); err != nil {
		t.Fatal(err)
	}
	_, err = findQuicprobe("")
	if err == nil {
		t.Fatal("expected not-found error")
	}
	check(t, "hint", strings.Contains(err.Error(), "-quicprobe"), true)
}

func TestIsExecutable(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if isExecutable(plain) || isExecutable(dir) || isExecutable(filepath.Join(dir, "nope")) {
		t.Error("non-executable, directory or missing path reported executable")
	}
}
