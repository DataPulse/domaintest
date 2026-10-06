package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// dialServer opens a plain TCP connection to a test server.
func dialServer(t *testing.T, srv *httptest.Server) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(strings.TrimPrefix(srv.URL, "https://"), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestProbeTLS_ValidChain(t *testing.T) {
	ca := newTestCA(t, "root")
	withRoots(t, ca.pool)
	leaf, key := ca.issue(t, certSpec{sans: []string{"example.test", "www.example.test"}, issuer: ca, org: "Example Org"})
	srv := tlsServer(t, okHandler(nil), []*x509.Certificate{leaf, ca.cert}, key, tls.VersionTLS12, tls.VersionTLS13)

	tc, res := probeTLS(context.Background(), dialServer(t, srv), "example.test", "example.test", "www.example.test", time.Now().Add(2*time.Second))
	if tc == nil {
		t.Fatalf("handshake failed: %+v", res)
	}
	check(t, "chain", res.Chain, ChainValid)
	check(t, "version", res.Version, "TLS 1.3")
	check(t, "alpn", res.ALPN, "http/1.1")
	check(t, "chain length", res.ChainLength, 2)
	check(t, "pkix valid", res.pkixValid, true)
	c := res.Cert
	check(t, "subject", c.Subject, "example.test")
	check(t, "issuer", c.Issuer, "root")
	check(t, "covers apex", c.CoversApex, true)
	check(t, "covers www", c.CoversWWW, true)
	check(t, "wildcard", c.Wildcard, false)
	check(t, "key", c.Key, "ECDSA P-256")
	check(t, "days", c.DaysRemaining >= 89 && c.DaysRemaining <= 90, true)
	check(t, "fingerprint length", len(c.Fingerprint), 64)
	check(t, "sans", c.SANs, []string{"example.test", "www.example.test"})
}

func TestClassifyChain_Problems(t *testing.T) {
	ca := newTestCA(t, "root")
	withRoots(t, ca.pool)
	other := newTestCA(t, "other root")
	now := time.Now()
	expired, _ := ca.issue(t, certSpec{sans: []string{"example.test"}, issuer: ca, notBefore: now.Add(-48 * time.Hour), notAfter: now.Add(-time.Hour)})
	future, _ := ca.issue(t, certSpec{sans: []string{"example.test"}, issuer: ca, notBefore: now.Add(time.Hour), notAfter: now.Add(48 * time.Hour)})
	wrong, _ := ca.issue(t, certSpec{sans: []string{"other.test"}, issuer: ca})
	self, _ := ca.issue(t, certSpec{sans: []string{"example.test"}})
	untrusted, _ := other.issue(t, certSpec{sans: []string{"example.test"}, issuer: other})
	wildcard, _ := ca.issue(t, certSpec{sans: []string{"*.example.test"}, issuer: ca})

	cases := []struct {
		name  string
		chain []*x509.Certificate
		host  string
		want  string
	}{
		{"expired", []*x509.Certificate{expired, ca.cert}, "example.test", ChainExpired},
		{"not yet valid", []*x509.Certificate{future, ca.cert}, "example.test", ChainNotYetValid},
		{"hostname mismatch", []*x509.Certificate{wrong, ca.cert}, "example.test", ChainHostnameMismatch},
		{"self-signed", []*x509.Certificate{self}, "example.test", ChainSelfSigned},
		{"untrusted root", []*x509.Certificate{untrusted, other.cert}, "example.test", ChainUntrustedRoot},
		{"wildcard covers host", []*x509.Certificate{wildcard, ca.cert}, "www.example.test", ChainValid},
		{"wildcard does not cover apex", []*x509.Certificate{wildcard, ca.cert}, "example.test", ChainHostnameMismatch},
	}
	for _, c := range cases {
		got, detail := classifyChain(context.Background(), c.chain, c.host)
		check(t, c.name, got, c.want)
		if got != ChainValid && detail == "" {
			t.Errorf("%s: expected a detail message", c.name)
		}
	}
	info := certInfo(wildcard, "example.test", "www.example.test")
	check(t, "wildcard flag", info.Wildcard, true)
	check(t, "wildcard covers www only", []bool{info.CoversApex, info.CoversWWW}, []bool{false, true})
}

func TestClassifyChain_IncompleteViaAIA(t *testing.T) {
	ca := newTestCA(t, "root")
	withRoots(t, ca.pool)
	inter, interKey := ca.issue(t, certSpec{sans: []string{"Intermediate CA"}, issuer: ca, isCA: true})
	interCA := &testCA{cert: inter, key: interKey}
	leaf, _ := interCA.issue(t, certSpec{sans: []string{"example.test"}, issuer: interCA})
	// The leaf must carry an AIA URL; re-create it with one.
	leaf.IssuingCertificateURL = []string{"http://aia.test/inter.der"}

	old := aiaFetch
	fetched := ""
	aiaFetch = func(ctx context.Context, url string) (*x509.Certificate, error) {
		fetched = url
		return inter, nil
	}
	t.Cleanup(func() { aiaFetch = old })

	got, detail := classifyChain(context.Background(), []*x509.Certificate{leaf}, "example.test")
	check(t, "incomplete chain", got, ChainIncomplete)
	check(t, "aia url used", fetched, "http://aia.test/inter.der")
	check(t, "detail names AIA", strings.Contains(detail, "AIA"), true)

	aiaFetch = func(context.Context, string) (*x509.Certificate, error) { return nil, errors.New("unreachable") }
	got, _ = classifyChain(context.Background(), []*x509.Certificate{leaf}, "example.test")
	check(t, "untrusted when AIA fails", got, ChainUntrustedRoot)

	leaf.IssuingCertificateURL = nil
	got, _ = classifyChain(context.Background(), []*x509.Certificate{leaf}, "example.test")
	check(t, "untrusted without AIA", got, ChainUntrustedRoot)
}

func TestProbeTLS_HandshakeFailure(t *testing.T) {
	srv := plainServer(t, okHandler(nil)) // speaks HTTP, not TLS
	tc, res := probeTLS(context.Background(), dialServer(t, srv), "example.test", "example.test", "www.example.test", time.Now().Add(2*time.Second))
	check(t, "no conn", tc == nil, true)
	check(t, "chain", res.Chain, ChainHandshakeFailed)
	check(t, "error set", res.Error != "", true)
}

func TestProbeOldVersions(t *testing.T) {
	ca := newTestCA(t, "root")
	leaf, key := ca.issue(t, certSpec{sans: []string{"example.test"}, issuer: ca})
	oldSrv := tlsServer(t, okHandler(nil), []*x509.Certificate{leaf, ca.cert}, key, tls.VersionTLS10, tls.VersionTLS13)
	modern := tlsServer(t, okHandler(nil), []*x509.Certificate{leaf, ca.cert}, key, tls.VersionTLS12, tls.VersionTLS13)

	d := newMappedDialer()
	ip := netip.MustParseAddr("192.0.2.10")
	d.mapTarget(ip.String(), 443, oldSrv)
	tls10, tls11 := probeOldVersions(context.Background(), d, ip, "example.test", 2*time.Second)
	check(t, "old server accepts 1.0 and 1.1", []any{tls10, tls11}, []any{boolPtr(true), boolPtr(true)})

	d.mapTarget(ip.String(), 443, modern)
	tls10, tls11 = probeOldVersions(context.Background(), d, ip, "example.test", 2*time.Second)
	check(t, "modern rejects 1.0 and 1.1", []any{tls10, tls11}, []any{boolPtr(false), boolPtr(false)})

	// A connection that could not be made never asked the question: that
	// is not a refusal, and must not read as one.
	unmapped := netip.MustParseAddr("192.0.2.11")
	tls10, tls11 = probeOldVersions(context.Background(), d, unmapped, "example.test", time.Second)
	check(t, "untested is null", tls10 == nil && tls11 == nil, true)

	// Nor is a handshake nobody answered before the deadline.
	silent := &silentDialer{t: t}
	tls10 = acceptsVersion(context.Background(), silent, netip.MustParseAddr("192.0.2.12"), "example.test", tls.VersionTLS10, 200*time.Millisecond)
	check(t, "unanswered is null", tls10 == nil, true)
}

func TestFormatTLSVersionAndKeys(t *testing.T) {
	check(t, "1.3", formatTLSVersion(tls.VersionTLS13), "TLS 1.3")
	check(t, "1.2", formatTLSVersion(tls.VersionTLS12), "TLS 1.2")
	check(t, "1.1", formatTLSVersion(tls.VersionTLS11), "TLS 1.1")
	check(t, "1.0", formatTLSVersion(tls.VersionTLS10), "TLS 1.0")
	check(t, "unknown", formatTLSVersion(0x0300), "0x0300")
	chain := loadChain(t, "www_huque_com")
	check(t, "live leaf key described", strings.HasPrefix(keyDescription(chain[0]), "RSA ") || strings.HasPrefix(keyDescription(chain[0]), "ECDSA ") || keyDescription(chain[0]) == "Ed25519", true)
	check(t, "issuer org non-empty", issuerOrg(chain[0]) != "", true)
	if _, err := parseCertificate([]byte("garbage")); err == nil {
		t.Error("garbage should not parse")
	}
	if c, err := parseCertificate(chain[0].Raw); err != nil || c.Subject.String() != chain[0].Subject.String() {
		t.Errorf("DER should parse: %v", err)
	}
}

// chain names only the most urgent defect, so a certificate with two
// problems under-reports: an operator who renewed badssl's SNI fallback
// would still be serving a certificate that does not cover the name.
func TestChainProblems_MultipleDefects(t *testing.T) {
	ca := newTestCA(t, "multi-defect test CA")
	past := time.Now().Add(-48 * time.Hour)

	// Expired and issued for a different name.
	both, _ := ca.issue(t, certSpec{sans: []string{"other.example"}, issuer: ca, notBefore: past.Add(-time.Hour), notAfter: past})
	check(t, "both defects, headline first", chainProblems(ChainExpired, both, "example.com"),
		[]string{ChainExpired, ChainHostnameMismatch})

	// Expired but otherwise correct: one problem.
	expired, _ := ca.issue(t, certSpec{sans: []string{"example.com"}, issuer: ca, notBefore: past.Add(-time.Hour), notAfter: past})
	check(t, "one defect", chainProblems(ChainExpired, expired, "example.com"), []string{ChainExpired})

	// Self-signed and for the wrong name.
	self, _ := ca.issue(t, certSpec{sans: []string{"other.example"}, notBefore: past, notAfter: time.Now().Add(24 * time.Hour)})
	got := chainProblems(ChainSelfSigned, self, "example.com")
	check(t, "self-signed headline", got[0], ChainSelfSigned)
	check(t, "mismatch also reported", contains(got, ChainHostnameMismatch), true)

	// A valid certificate has nothing to report and never null.
	good, _ := ca.issue(t, certSpec{sans: []string{"example.com"}, issuer: ca, notBefore: past, notAfter: time.Now().Add(24 * time.Hour)})
	check(t, "clean", chainProblems(ChainValid, good, "example.com"), []string{})
}

// silentDialer connects to a peer that accepts the connection and then
// never reads or writes, like a server stalled behind a middlebox.
type silentDialer struct{ t *testing.T }

func (d *silentDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	c1, c2 := net.Pipe()
	d.t.Cleanup(func() { _ = c2.Close() })
	return c1, nil
}

// TestClassifyChain_RepairFollowsAIAUpTheChain uses the real certificates of
// incomplete-chain.badssl.com, captured 2026-10-06. Its leaf names Let's
// Encrypt YR1, which is signed by ISRG Root YR; only YR1's own AIA leads to
// Root YR cross-signed by ISRG Root X1, the root the store holds. One fetch
// was not enough, so the chain was reported as an untrusted root.
func TestClassifyChain_RepairFollowsAIAUpTheChain(t *testing.T) {
	leaf := loadChain(t, "incomplete-chain_badssl_com-leaf")[0]
	yr1 := loadChain(t, "lencr_yr1")[0]
	rootYR := loadChain(t, "lencr_root_yr_cross_x1")[0]
	roots := x509.NewCertPool()
	roots.AddCert(loadChain(t, "isrg_root_x1")[0])
	withRoots(t, roots)
	oldTime := verifyTime
	verifyTime = time.Date(2026, 10, 6, 3, 52, 46, 0, time.UTC)
	t.Cleanup(func() { verifyTime = oldTime })

	issuers := map[string]*x509.Certificate{
		"http://yr1.i.lencr.org/": yr1,
		"http://yr.i.lencr.org/":  rootYR,
	}
	old := aiaFetch
	var fetched []string
	aiaFetch = func(_ context.Context, url string) (*x509.Certificate, error) {
		fetched = append(fetched, url)
		if c, ok := issuers[url]; ok {
			return c, nil
		}
		return nil, errors.New("no such issuer")
	}
	t.Cleanup(func() { aiaFetch = old })

	got, detail := classifyChain(context.Background(), []*x509.Certificate{leaf}, "incomplete-chain.badssl.com")
	check(t, "incomplete, repaired two levels up", got, ChainIncomplete)
	check(t, "both issuer URLs fetched in order", fetched, []string{"http://yr1.i.lencr.org/", "http://yr.i.lencr.org/"})
	check(t, "detail names both", strings.Contains(detail, "yr1.i.lencr.org") && strings.Contains(detail, "yr.i.lencr.org"), true)

	// With only the first level reachable, the chain stays unverified.
	delete(issuers, "http://yr.i.lencr.org/")
	fetched = nil
	got, _ = classifyChain(context.Background(), []*x509.Certificate{leaf}, "incomplete-chain.badssl.com")
	check(t, "untrusted when the second fetch fails", got, ChainUntrustedRoot)

	// The full chain the server should have sent verifies as is, no fetch.
	fetched = nil
	got, _ = classifyChain(context.Background(), []*x509.Certificate{leaf, yr1, rootYR}, "incomplete-chain.badssl.com")
	check(t, "full chain valid", got, ChainValid)
	check(t, "no fetch for a full chain", len(fetched), 0)
}

func TestCompleteViaAIA_StopsAtDepth(t *testing.T) {
	// An issuer that keeps naming another issuer never ends the walk early.
	ca := newTestCA(t, "root")
	withRoots(t, x509.NewCertPool()) // nothing trusted: the walk can only give up
	leaf, _ := ca.issue(t, certSpec{sans: []string{"example.test"}, issuer: ca})
	leaf.IssuingCertificateURL = []string{"http://aia.test/0"}
	old := aiaFetch
	calls := 0
	aiaFetch = func(context.Context, string) (*x509.Certificate, error) {
		calls++
		next, _ := ca.issue(t, certSpec{sans: []string{"Loop CA"}, issuer: ca, isCA: true})
		next.IssuingCertificateURL = []string{"http://aia.test/next"}
		return next, nil
	}
	t.Cleanup(func() { aiaFetch = old })

	fetched, ok := completeViaAIA(context.Background(), leaf, nil, "example.test")
	check(t, "not completed", ok, false)
	check(t, "fetches capped", calls, maxAIADepth)
	check(t, "urls reported", len(fetched), maxAIADepth)
}

func TestHoistCertNames_OneListPerCertificate(t *testing.T) {
	sans := []string{"example.test", "www.example.test", "*.example.test"}
	cert := func(fp string) *TLSResult {
		return &TLSResult{Chain: ChainValid, Cert: &CertInfo{Fingerprint: fp, SANs: append([]string{}, sans...), CoversApex: true}}
	}
	rep := &Report{Web: WebSection{
		Apex: &HostWeb{IPv4: []AddrWeb{{IP: "192.0.2.1", TLS: cert("aa")}, {IP: "192.0.2.2", TLS: cert("aa")}},
			IPv6: []AddrWeb{{IP: "2001:db8::1", TLS: cert("bb")}}},
		WWW: &HostWeb{IPv4: []AddrWeb{{IP: "192.0.2.1", TLS: cert("aa")}, {IP: "192.0.2.3"}}},
	}}
	hoistCertNames(rep)
	check(t, "one entry per fingerprint", len(rep.Certificates), 2)
	check(t, "names kept", rep.Certificates["aa"].SANs, sans)
	for _, a := range append(rep.Web.Apex.addrs(), rep.Web.WWW.addrs()...) {
		if a.TLS != nil {
			check(t, a.IP+" has no list of its own", a.TLS.Cert.SANs == nil, true)
			check(t, a.IP+" keeps the rest", a.TLS.Cert.CoversApex, true)
		}
	}
	out, _ := json.Marshal(rep)
	check(t, "each name once per certificate", strings.Count(string(out), `"*.example.test"`), 2)
	check(t, "no per-address sans key", strings.Count(string(out), `"sans"`), 2)

	empty := &Report{}
	hoistCertNames(empty)
	out, _ = json.Marshal(empty)
	check(t, "no certificates key without TLS", strings.Contains(string(out), `"certificates"`), false)
}
