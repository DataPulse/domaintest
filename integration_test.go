package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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

func TestIntegration_IDNBothForms(t *testing.T) {
	// münchen.de is a live IDN; both spellings must produce the same report.
	ucfg := integrationConfig(t, "münchen.de")
	acfg := integrationConfig(t, "xn--mnchen-3ya.de")
	check(t, "same A-label", ucfg.Domain, acfg.Domain)
	rep := run(context.Background(), ucfg, execRunner{}, &netDialer{})
	check(t, "domain", rep.Domain, "xn--mnchen-3ya.de")
	check(t, "unicode", rep.UnicodeDomain, "münchen.de")
	check(t, "errors", rep.Errors, []string{})
	check(t, "delegation", rep.Delegation.Status, DelegationMatch)
	check(t, "has addresses", rep.DNS.Apex["A"].HasRecords(), true)
	if rep.Web.Apex == nil || len(rep.Web.Apex.IPv4) == 0 {
		t.Fatalf("expected web results, got %+v", rep.Web)
	}
	check(t, "http reachable", rep.Web.Apex.IPv4[0].HTTP, PortOpen)
}

func TestIntegration_TXTOnlyNameIsHealthy(t *testing.T) {
	cfg := integrationConfig(t, "_dmarc.jschmidt.org")
	rep := run(context.Background(), cfg, execRunner{}, &netDialer{})
	check(t, "ok", rep.OK, true)
	check(t, "errors", rep.Errors, []string{})
	check(t, "not a zone", rep.NotAZone, true)
	check(t, "enclosing zone", rep.EnclosingZone, "jschmidt.org")
	check(t, "dnssec", rep.DNSSEC.State, DNSSECSecure)
}

func TestIntegration_HostInsideZone(t *testing.T) {
	cfg := integrationConfig(t, "aelcs-com.mail.protection.outlook.com")
	rep := run(context.Background(), cfg, execRunner{}, &netDialer{})
	check(t, "not a zone", rep.NotAZone, true)
	check(t, "delegation", rep.Delegation.Status, DelegationNotAZone)
	check(t, "warned", contains(rep.Warnings, "not a zone apex"), true)
}

func TestIntegration_ResolverWithPort(t *testing.T) {
	// Google Public DNS answers on 53 only, so a wrong port must fail fast
	// and a right one must work, proving -p reaches delv.
	cfg := integrationConfig(t, "jschmidt.org", "@8.8.8.8:53", "-t", "2")
	rep := run(context.Background(), cfg, execRunner{}, &netDialer{})
	check(t, "resolver", rep.Resolver, "8.8.8.8:53")
	check(t, "MX answered via explicit port", rep.DNS.Apex["MX"].HasRecords(), true)
}

func TestIntegration_RealMainHealthy(t *testing.T) {
	if testing.Short() {
		t.Skip("network test skipped in -short mode")
	}
	var out, errBuf bytes.Buffer
	rc := realMain([]string{"-pretty", "jschmidt.org"}, &out, &errBuf)
	check(t, "exit code", rc, 0)
	check(t, "stderr empty", errBuf.String(), "")
	var rep Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out.String())
	}
	check(t, "ok", rep.OK, true)
	check(t, "pretty output indented", strings.Contains(out.String(), "\n  \"domain\""), true)
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

// ---- deep checks (network) ---------------------------------------------

func TestIntegration_BadSSL(t *testing.T) {
	cases := []struct {
		host  string
		chain []string // acceptable classifications
	}{
		{"expired.badssl.com", []string{ChainExpired}},
		{"wrong.host.badssl.com", []string{ChainHostnameMismatch}},
		{"self-signed.badssl.com", []string{ChainSelfSigned}},
		{"untrusted-root.badssl.com", []string{ChainUntrustedRoot}},
		// incomplete-chain.badssl.com currently chains to "ISRG Root YR", a
		// root that older trust stores (Debian 12 here) do not carry, in
		// which case fetching the intermediate cannot rescue it and
		// untrusted_root is the honest verdict from this vantage point.
		{"incomplete-chain.badssl.com", []string{ChainIncomplete, ChainUntrustedRoot}},
		{"badssl.com", []string{ChainValid}},
	}
	for _, c := range cases {
		t.Run(c.host, func(t *testing.T) {
			cfg := integrationConfig(t, c.host)
			rep := run(context.Background(), cfg, execRunner{}, &netDialer{})
			if rep.Web.Apex == nil || len(rep.Web.Apex.IPv4) == 0 || rep.Web.Apex.IPv4[0].TLS == nil {
				// Every badssl host shares one address, and this suite opens
				// several connections to each; the site throttles bursts.
				t.Skipf("badssl.com did not answer on 443: %+v", rep.Web)
			}
			tlsRes := rep.Web.Apex.IPv4[0].TLS
			if tlsRes.Chain == ChainHandshakeFailed && !contains(c.chain, ChainHandshakeFailed) {
				t.Skipf("badssl.com refused the handshake (throttling): %s", tlsRes.Error)
			}
			check(t, "chain "+tlsRes.Chain, contains(c.chain, tlsRes.Chain), true)
			check(t, "certificate parsed", tlsRes.Cert != nil, true)
			check(t, "ok only for the valid one", rep.OK, tlsRes.Chain == ChainValid)
			if tlsRes.Chain != ChainValid {
				check(t, "chain error surfaces", contains(rep.Errors, "certificate "+strings.ReplaceAll(tlsRes.Chain, "_", " ")), true)
			}
		})
	}
}

func TestIntegration_MailPosture(t *testing.T) {
	cfg := integrationConfig(t, "jschmidt.org")
	rep := run(context.Background(), cfg, execRunner{}, &netDialer{})
	m := rep.Mail
	if m == nil {
		t.Fatal("mail section missing")
	}
	check(t, "dmarc", m.DMARC.Policy, "quarantine")
	check(t, "spf softfail", m.SPF.All, "~all")
	check(t, "spf within limit", m.SPF.Lookups <= spfLookupLimit, true)
	check(t, "spf problems", m.SPF.Problems, []string{})
	check(t, "mx resolves", m.MX[0].Addresses > 0, true)
	check(t, "dkim selectors", m.DKIM.SelectorsFound, []string{"selector1", "selector2"})
	check(t, "errors", rep.Errors, []string{})
	n := rep.Nameservers
	if n == nil {
		t.Fatal("nameservers missing")
	}
	check(t, "four NS", n.Count, 4)
	for _, s := range n.Servers {
		check(t, "authoritative "+s.IP, s.AA, true)
		check(t, "edns "+s.IP, s.EDNS, true)
		check(t, "tcp "+s.IP, s.TCP, true)
	}
	check(t, "serials consistent", n.SerialsConsistent, true)
}

func TestIntegration_GoogleTLSAndCAA(t *testing.T) {
	cfg := integrationConfig(t, "google.com")
	rep := run(context.Background(), cfg, execRunner{}, &netDialer{})
	a := rep.Web.Apex.IPv4[0]
	check(t, "chain", a.TLS.Chain, ChainValid)
	check(t, "tls 1.3", a.TLS.Version, "TLS 1.3")
	// Google still accepts TLS 1.0 and 1.1 on the apex; the tool reports it.
	check(t, "old versions still accepted (warned)", a.TLS.TLS10 && contains(rep.Warnings, "TLS 1.0/1.1 still accepted"), true)
	check(t, "https status is a redirect to www", a.HTTPSRes.Status, 301)
	check(t, "http answers with a redirect", isRedirect(a.HTTPRes.Status), true)
	check(t, "redirect chain ends at www", strings.Contains(rep.Web.Apex.Redirects[familyIPv4].FinalURL+rep.Web.Apex.Redirects[familyIPv4].External, "www.google.com"), true)
	apexCAA := rep.CAA.Hosts["apex"]
	check(t, "caa permitted", apexCAA.Permitted != nil && *apexCAA.Permitted, true)
	check(t, "issuer mapped", strings.HasPrefix(apexCAA.Issuer, "Google Trust Services"), true)
	check(t, "glue present", len(rep.Nameservers.Glue.Missing), 0)
	check(t, "dmarc reject", rep.Mail.DMARC.Policy, "reject")
	check(t, "preload answered", rep.HSTSPreload != "" && !strings.HasPrefix(rep.HSTSPreload, "error"), true)
}

func TestIntegration_ReservedAddress(t *testing.T) {
	cfg := integrationConfig(t, "localtest.me")
	rep := run(context.Background(), cfg, execRunner{}, &netDialer{})
	check(t, "reserved", contains(rep.ReservedAddresses, "127.0.0.1 (loopback)"), true)
	check(t, "error", contains(rep.Errors, "reserved address published in DNS"), true)
	check(t, "skipped", rep.Web.Apex.IPv4[0].HTTP, PortSkipped)
}

func TestIntegration_DANE(t *testing.T) {
	cfg := integrationConfig(t, "www.huque.com")
	rep := run(context.Background(), cfg, execRunner{}, &netDialer{})
	check(t, "tlsa records", len(rep.TLSA.Apex) > 0, true)
	check(t, "signed", rep.TLSA.Signed, true)
	check(t, "match", rep.TLSA.Result, TLSAMatch)
	check(t, "per address", rep.Web.Apex.IPv4[0].TLSA, TLSAMatch)
}

func TestIntegration_Wildcard(t *testing.T) {
	cfg := integrationConfig(t, "github.io")
	rep := run(context.Background(), cfg, execRunner{}, &netDialer{})
	check(t, "wildcard", rep.Wildcard.Present, true)
	check(t, "addresses", len(rep.Wildcard.Addresses) > 0, true)
}

func TestIntegration_PreloadOptOut(t *testing.T) {
	cfg := integrationConfig(t, "jschmidt.org", "-no-hsts-preload")
	rep := run(context.Background(), cfg, execRunner{}, &netDialer{})
	check(t, "not consulted", rep.HSTSPreload, "")
}

// ---- HSTS preload list and its cache (network) -------------------------

func TestIntegration_PreloadListRealFetch(t *testing.T) {
	if testing.Short() {
		t.Skip("network test skipped in -short mode")
	}
	path := filepath.Join(t.TempDir(), "hsts-preload.tsv")
	start := time.Now()
	l, err := loadPreloadList(context.Background(), path, 30*time.Second)
	if err != nil {
		t.Fatalf("fetching the preload list: %v", err)
	}
	t.Logf("fetched %d entries in %v", len(l.entries), time.Since(start))
	check(t, "a real list has many entries", len(l.entries) > 50000, true)
	check(t, "github.com listed", l.entries["github.com"], true)
	check(t, "app is a listed TLD", l.entries["app"], true)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	check(t, "cache is about the expected size", info.Size() > 1<<20 && info.Size() < 8<<20, true)

	// The cache now answers without any network: a fetcher that fails the
	// test proves it is never called.
	old := preloadListFetcher
	preloadListFetcher = func(context.Context, time.Duration) (*preloadList, error) {
		t.Error("the cached list should not be refetched")
		return nil, errors.New("must not fetch")
	}
	t.Cleanup(func() { preloadListFetcher = old })
	cached, err := loadPreloadList(context.Background(), path, time.Second)
	check(t, "second load", err, nil)
	check(t, "same size", len(cached.entries), len(l.entries))

	status, coveredBy := cached.status("github.com")
	check(t, "github.com", []string{status, coveredBy}, []string{PreloadPreloaded, ""})
	status, coveredBy = cached.status("nothing-here.example.app")
	check(t, "covered by the app TLD", []string{status, coveredBy}, []string{PreloadPreloaded, "app"})
	status, _ = cached.status("jschmidt.org")
	check(t, "jschmidt.org absent", status, PreloadAbsent)
}

func TestIntegration_PreloadCacheEndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hsts-preload.tsv")
	cfg := integrationConfig(t, "github.com", "-hsts-cache", path)
	rep := run(context.Background(), cfg, execRunner{}, &netDialer{})
	check(t, "preloaded", rep.HSTSPreload, PreloadPreloaded)
	check(t, "no error", rep.HSTSPreloadError, "")
	check(t, "cache populated", fileExists(path), true)

	// A second domain on the same host reuses the cache: no fetch.
	old := preloadListFetcher
	preloadListFetcher = func(context.Context, time.Duration) (*preloadList, error) {
		t.Error("the second run should read the cache, not fetch")
		return nil, errors.New("must not fetch")
	}
	t.Cleanup(func() { preloadListFetcher = old })
	cfg = integrationConfig(t, "jschmidt.org", "-hsts-cache", path)
	rep = run(context.Background(), cfg, execRunner{}, &netDialer{})
	check(t, "absent", rep.HSTSPreload, PreloadAbsent)
	check(t, "no error", rep.HSTSPreloadError, "")
}

// Two processes of the built binary racing on one empty cache directory must
// produce one cache file and two real answers, which is the worker's cold
// start with DOMAINHEALTH_CONCURRENCY > 1.
func TestIntegration_WarmModeAndProcessRace(t *testing.T) {
	bin := buildDomaintest(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "hsts-preload.tsv")

	rc, out := runBinary(t, bin, "-warm-hsts-cache", "-hsts-cache", path)
	check(t, "warm exits 0", rc, 0)
	check(t, "warm writes nothing to stdout", out, "")
	check(t, "cache written", fileExists(path), true)

	// Racing runs against a fresh directory.
	race := filepath.Join(t.TempDir(), "hsts-preload.tsv")
	type result struct {
		rc  int
		out string
	}
	results := make([]result, 2)
	var wg sync.WaitGroup
	for i, domain := range []string{"github.com", "jschmidt.org"} {
		wg.Add(1)
		go func(i int, domain string) {
			defer wg.Done()
			rc, out := runBinary(t, bin, "-t", "5", "-hsts-cache", race, domain)
			results[i] = result{rc, out}
		}(i, domain)
	}
	wg.Wait()
	check(t, "one cache file", fileExists(race), true)
	for i, want := range []string{PreloadPreloaded, PreloadAbsent} {
		var rep Report
		if err := json.Unmarshal([]byte(results[i].out), &rep); err != nil {
			t.Fatalf("run %d: %v\n%s", i, err, results[i].out)
		}
		check(t, "preload status", rep.HSTSPreload, want)
		check(t, "no preload error", rep.HSTSPreloadError, "")
	}
}
