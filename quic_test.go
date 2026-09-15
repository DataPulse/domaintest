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
		reason    string
		alert     string
		alertCode int
		errPrefix string
	}{
		{"quicprobe/google_supported.json", true, "h3", "", "", 0, ""},
		{"quicprobe/cloudfront_h3_enabled.json", true, "h3", "", "", 0, ""},
		// Captured before quicprobe learned to classify failures: no reason.
		{"quicprobe/example_unsupported.json", false, "", "", "", 0, "CRYPTO_ERROR"},
		{"quicprobe/cloudfront_h3_disabled.json", false, "", "tls_rejected", "handshake failure", 40, "CRYPTO_ERROR 0x128"},
		{"quicprobe/blackhole_timeout.json", false, "", "timeout", "", 0, "context deadline exceeded"},
		{"quicprobe/nxdomain_error.json", false, "", "resolve_failed", "", 0, "lookup nxdomain-quictest.invalid"},
		{"quicprobe/usage_error.json", false, "", "invalid_args", "", 0, "usage:"},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			q := parseQUIC([]byte(fixture(t, c.file)))
			check(t, "supported", q.Supported, c.supported)
			check(t, "alpn", q.ALPN, c.alpn)
			check(t, "reason", q.Reason, c.reason)
			check(t, "tls_alert", q.TLSAlert, c.alert)
			check(t, "tls_alert_code", q.TLSAlertCode, c.alertCode)
			check(t, "error prefix", strings.HasPrefix(q.Error, c.errPrefix), true)
			if c.supported {
				check(t, "tls", q.TLSVersion, "TLS 1.3")
				check(t, "server_addr set", q.ServerAddr != "", true)
				check(t, "handshake_ms positive", q.HandshakeMs > 0, true)
			}
		})
	}
}

func TestQUICResult_ReportJSON(t *testing.T) {
	// The classification survives into the report, and the fields stay out
	// of a successful or legacy entry.
	q := parseQUIC([]byte(fixture(t, "quicprobe/cloudfront_h3_disabled.json")))
	out, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"reason":"tls_rejected"`, `"tls_alert":"handshake failure"`, `"tls_alert_code":40`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("report JSON lacks %s: %s", want, out)
		}
	}
	for _, f := range []string{"quicprobe/google_supported.json", "quicprobe/example_unsupported.json"} {
		out, _ := json.Marshal(parseQUIC([]byte(fixture(t, f))))
		for _, absent := range []string{"reason", "tls_alert"} {
			if strings.Contains(string(out), absent) {
				t.Errorf("%s: %s must be omitted when empty: %s", f, absent, out)
			}
		}
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
