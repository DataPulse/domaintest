package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Integration tests hit the real delv, dig, quicprobe and the network.
// They are skipped under -short.

func integrationConfig(t *testing.T, args ...string) config {
	t.Helper()
	if testing.Short() {
		t.Skip("network test skipped in -short mode")
	}
	cfg, err := parseArgs(args)
	if err != nil {
		t.Fatal(err)
	}
	if err := resolveTools(&cfg); err != nil {
		t.Skipf("tools not available: %v", err)
	}
	return cfg
}

func TestIntegration_SignedDomainWithoutWeb(t *testing.T) {
	cfg := integrationConfig(t, "jschmidt.org")
	rep := run(context.Background(), cfg, execRunner{}, &netDialer{})
	if !rep.OK {
		t.Errorf("errors %v", rep.Errors)
	}
	if rep.DNSSEC.State != DNSSECSecure || rep.Delegation.Status != DelegationMatch {
		t.Errorf("dnssec %+v delegation %+v", rep.DNSSEC, rep.Delegation)
	}
	if !rep.DNS.Apex["MX"].HasRecords() || !hasSPF(rep.DNS.Apex["TXT"].Records) {
		t.Errorf("apex records %+v", rep.DNS.Apex)
	}
	if rep.DNS.ResolverReachable[familyIPv4] != ReachYes {
		t.Errorf("reachability %v", rep.DNS.ResolverReachable)
	}
}

func TestIntegration_WebDomain(t *testing.T) {
	cfg := integrationConfig(t, "google.com")
	rep := run(context.Background(), cfg, execRunner{}, &netDialer{})
	check(t, "errors", rep.Errors, []string{})
	check(t, "dnssec (google.com is unsigned)", rep.DNSSEC.State, DNSSECInsecure)
	if rep.Web.Apex == nil || len(rep.Web.Apex.IPv4) == 0 {
		t.Fatalf("expected apex web results, got %+v", rep.Web)
	}
	assertLiveWeb(t, "ipv4", rep.Web.Apex.IPv4[0])
	if len(rep.Web.Apex.IPv6) > 0 {
		assertLiveWeb(t, "ipv6", rep.Web.Apex.IPv6[0])
	}
}

// assertLiveWeb checks that a real web address answers on both ports and
// negotiated h3 over QUIC.
func assertLiveWeb(t *testing.T, label string, a AddrWeb) {
	t.Helper()
	check(t, label+" 80", a.HTTP, PortOpen)
	check(t, label+" 443", a.HTTPS, PortOpen)
	if a.QUIC == nil {
		t.Fatalf("%s: QUIC result missing", label)
	}
	check(t, label+" quic supported", a.QUIC.Supported, true)
	check(t, label+" alpn", a.QUIC.ALPN, "h3")
}

func TestIntegration_BogusZone(t *testing.T) {
	cfg := integrationConfig(t, "dnssec-failed.org", "@8.8.8.8")
	rep := run(context.Background(), cfg, execRunner{}, &netDialer{})
	if rep.OK || rep.DNSSEC.State != DNSSECBogus || !strings.Contains(rep.DNSSEC.EDE, "DNSKEY") {
		t.Errorf("expected bogus with EDE, got ok=%v dnssec %+v errors %v", rep.OK, rep.DNSSEC, rep.Errors)
	}
	if rep.DNS.ResolverReachable[familyIPv4] != ReachYes {
		t.Errorf("resolver should still be reachable: %v", rep.DNS.ResolverReachable)
	}
}

func TestIntegration_ParentServesChild(t *testing.T) {
	// The .cz servers also host nic.cz and answer authoritatively.
	cfg := integrationConfig(t, "nic.cz")
	rep := run(context.Background(), cfg, execRunner{}, &netDialer{})
	check(t, "delegation", rep.Delegation.Status, DelegationSameServers)
	check(t, "errors", rep.Errors, []string{})
}

func TestIntegration_NXDomain(t *testing.T) {
	cfg := integrationConfig(t, "nosuch-domaintest-zzz-qq.org")
	rep := run(context.Background(), cfg, execRunner{}, &netDialer{})
	if rep.OK || !contains(rep.Errors, "NXDOMAIN") {
		t.Errorf("errors %v", rep.Errors)
	}
}

func TestIntegration_DeadResolverHonoursTimeout(t *testing.T) {
	cfg := integrationConfig(t, "jschmidt.org", "@192.0.2.1", "-t", "2")
	start := time.Now()
	rep := run(context.Background(), cfg, execRunner{}, &netDialer{})
	elapsed := time.Since(start)
	if elapsed > 8*time.Second {
		t.Errorf("run took %v with -t 2", elapsed)
	}
	if rep.OK || !contains(rep.Errors, "timed out") {
		t.Errorf("errors %v", rep.Errors)
	}
}

func buildDomaintest(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("binary test skipped in -short mode")
	}
	bin := filepath.Join(t.TempDir(), "domaintest_test_bin")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

// runBinary executes the built domaintest and returns its exit code and
// stdout.
func runBinary(t *testing.T, bin string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil && cmd.ProcessState == nil {
		t.Fatalf("could not run binary: %v", err)
	}
	t.Logf("%v: exit %d stderr %q", args, cmd.ProcessState.ExitCode(), stderr.String())
	return cmd.ProcessState.ExitCode(), stdout.String()
}

func TestIntegration_Binary(t *testing.T) {
	bin := buildDomaintest(t)
	if _, err := os.Stat(filepath.Join("..", "quicprobe", "quicprobe")); err != nil {
		t.Skipf("sibling quicprobe binary missing: %v", err)
	}

	rc, out := runBinary(t, bin, "-t", "3", "jschmidt.org")
	check(t, "healthy exit", rc, 0)
	var rep Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out)
	}
	check(t, "ok", rep.OK, true)
	check(t, "domain", rep.Domain, "jschmidt.org")
	check(t, "single line", strings.Count(out, "\n"), 1)

	rc, _ = runBinary(t, bin, "dnssec-failed.org", "@8.8.8.8")
	check(t, "bogus zone exit", rc, 1)

	rc, out = runBinary(t, bin)
	check(t, "usage exit", rc, 2)
	check(t, "no stdout on usage error", out, "")
}
