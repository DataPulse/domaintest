package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Chain classifications.
const (
	ChainValid            = "valid"
	ChainExpired          = "expired"
	ChainNotYetValid      = "not_yet_valid"
	ChainHostnameMismatch = "hostname_mismatch"
	ChainSelfSigned       = "self_signed"
	ChainIncomplete       = "incomplete_chain"
	ChainUntrustedRoot    = "untrusted_root"
	ChainInvalid          = "invalid"
	ChainHandshakeFailed  = "handshake_failed"
)

// tlsRoots is the trust store used for chain verification; nil means the
// system store. Tests inject their own CA here.
var tlsRoots *x509.CertPool

// aiaFetch retrieves a DER/PEM certificate from an Authority Information
// Access URL. Replaceable in tests.
var aiaFetch = fetchAIACached

// CertInfo describes the leaf certificate a server presented.
type CertInfo struct {
	Subject       string   `json:"subject"`
	Issuer        string   `json:"issuer"`
	NotBefore     string   `json:"not_before"`
	NotAfter      string   `json:"not_after"`
	DaysRemaining int      `json:"days_remaining"`
	SANs          []string `json:"sans,omitempty"` // moved to Report.Certificates when the report is finished
	CoversApex    bool     `json:"covers_apex"`
	CoversWWW     bool     `json:"covers_www"`
	Wildcard      bool     `json:"wildcard"`
	Key           string   `json:"key"`
	Fingerprint   string   `json:"fingerprint_sha256"`
}

// TLSResult is the outcome of one TLS handshake on port 443.
type TLSResult struct {
	Chain string `json:"chain"`
	// Problems lists every defect found, headline first. Chain names only
	// the most urgent one, so an operator who fixed it could still be left
	// with a broken site: badssl's fallback is both expired and served for
	// a name it does not cover.
	Problems []string `json:"chain_problems"`
	Version  string   `json:"version,omitempty"`
	Cipher   string   `json:"cipher,omitempty"`
	// TLS10 and TLS11 say whether the server completes a handshake capped
	// at that version: null when the question was never put (no
	// connection, or no answer before the deadline), which is not a
	// refusal.
	TLS10       *bool     `json:"tls10"`
	TLS11       *bool     `json:"tls11"`
	Cert        *CertInfo `json:"cert,omitempty"`
	ChainLength int       `json:"chain_length,omitempty"`
	Error       string    `json:"error,omitempty"`
	chain       []*x509.Certificate
	pkixValid   bool
	noALPN      bool // the handshake ended in alert 120: no HTTP/1.1 over TLS
}

// tlsConfig is the client configuration for a probe: SNI set, verification
// done by hand afterwards so that a bad chain still yields a full result.
func tlsConfig(host string, minVer, maxVer uint16) *tls.Config {
	return &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,                 //nolint:gosec // verified manually in classifyChain
		NextProtos:         []string{"http/1.1"}, // the GET that follows is HTTP/1.1
		MinVersion:         minVer,
		MaxVersion:         maxVer,
	}
}

// probeTLS performs the handshake on an already-connected socket and
// returns the TLS connection (for the HTTPS request that follows) together
// with the analysis. The caller owns conn.
func probeTLS(ctx context.Context, conn net.Conn, host, apex, www string, deadline time.Time) (*tls.Conn, TLSResult) {
	_ = conn.SetDeadline(deadline)
	tc := tls.Client(conn, tlsConfig(host, 0, 0))
	if err := tc.Handshake(); err != nil {
		return nil, TLSResult{Chain: ChainHandshakeFailed, Error: scrubProbeError(err.Error()), noALPN: noALPNAlert(err)}
	}
	state := tc.ConnectionState()
	res := TLSResult{
		Version:     formatTLSVersion(state.Version),
		Cipher:      tls.CipherSuiteName(state.CipherSuite),
		ChainLength: len(state.PeerCertificates),
		chain:       state.PeerCertificates,
	}
	if len(state.PeerCertificates) == 0 {
		res.Chain, res.Error = ChainInvalid, "server sent no certificate"
		res.Problems = []string{ChainInvalid}
		return tc, res
	}
	res.Chain, res.Error = classifyChain(ctx, state.PeerCertificates, host)
	res.Problems = chainProblems(res.Chain, state.PeerCertificates[0], host)
	res.pkixValid = res.Chain == ChainValid
	info := certInfo(state.PeerCertificates[0], apex, www)
	res.Cert = &info
	return tc, res
}

func formatTLSVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// classifyChain verifies the presented chain for host and names the
// problem. Expiry is checked explicitly first so that an expired cert on a
// wrong host is reported as expired, the more urgent fact.
func classifyChain(ctx context.Context, chain []*x509.Certificate, host string) (string, string) {
	leaf := chain[0]
	now := time.Now()
	switch {
	case now.After(leaf.NotAfter):
		return ChainExpired, "certificate expired " + leaf.NotAfter.UTC().Format(time.RFC3339)
	case now.Before(leaf.NotBefore):
		return ChainNotYetValid, "certificate not valid before " + leaf.NotBefore.UTC().Format(time.RFC3339)
	}
	err := verifyChain(leaf, chain[1:], host)
	if err == nil {
		return ChainValid, ""
	}
	return classifyVerifyError(ctx, err, chain, host)
}

// chainProblems collects every defect of the leaf, not just the one that
// classifyChain reports as the headline. The headline stays first so that
// anything keying on Chain and reading Problems[0] agrees.
func chainProblems(headline string, leaf *x509.Certificate, host string) []string {
	out := []string{}
	if headline != ChainValid {
		out = append(out, headline)
	}
	now := time.Now()
	add := func(p string) {
		if p != headline {
			out = append(out, p)
		}
	}
	if now.After(leaf.NotAfter) {
		add(ChainExpired)
	}
	if now.Before(leaf.NotBefore) {
		add(ChainNotYetValid)
	}
	if leaf.VerifyHostname(host) != nil {
		add(ChainHostnameMismatch)
	}
	if isSelfSigned(leaf) {
		add(ChainSelfSigned)
	}
	return out
}

// verifyTime is when chains are verified; zero means now. Tests that verify
// captured real certificates pin it to the capture time.
var verifyTime time.Time

func verifyChain(leaf *x509.Certificate, intermediates []*x509.Certificate, host string) error {
	pool := x509.NewCertPool()
	for _, c := range intermediates {
		pool.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: tlsRoots, Intermediates: pool, CurrentTime: verifyTime})
	return err
}

func classifyVerifyError(ctx context.Context, err error, chain []*x509.Certificate, host string) (string, string) {
	var hostErr x509.HostnameError
	var authErr x509.UnknownAuthorityError
	leaf := chain[0]
	switch {
	case errors.As(err, &hostErr):
		return ChainHostnameMismatch, scrubProbeError(err.Error())
	case errors.As(err, &authErr) && isSelfSigned(leaf):
		return ChainSelfSigned, "self-signed certificate"
	case errors.As(err, &authErr):
		if fetched, completed := completeViaAIA(ctx, leaf, chain[1:], host); completed {
			return ChainIncomplete, "server did not send the intermediate certificate (fetched via AIA: " + strings.Join(fetched, ", ") + ")"
		}
		return ChainUntrustedRoot, scrubProbeError(err.Error())
	default:
		return ChainInvalid, scrubProbeError(err.Error())
	}
}

// isSelfSigned reports whether the certificate signed itself. The raw
// signature is checked directly because CheckSignatureFrom would also
// demand CA constraints that self-signed leaves rarely carry.
func isSelfSigned(c *x509.Certificate) bool {
	if !bytes.Equal(c.RawIssuer, c.RawSubject) {
		return false
	}
	return c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// maxAIADepth bounds how far up the issuer links a repair follows. A leaf
// whose intermediate is signed by a root the store does not hold yet needs
// two fetches: incomplete-chain.badssl.com names Let's Encrypt YR1, which is
// signed by ISRG Root YR, and only YR1's own AIA leads to Root YR
// cross-signed by ISRG Root X1. One fetch reported that chain as an
// untrusted root (2026-10-06 tester report).
const maxAIADepth = 3

// completeViaAIA reports whether the chain becomes valid once the issuer
// certificates named in the AIA extensions are added, following each
// fetched certificate's own AIA link in turn: the classic "works in
// browsers, fails elsewhere" incomplete chain. It returns the URLs fetched.
func completeViaAIA(ctx context.Context, leaf *x509.Certificate, intermediates []*x509.Certificate, host string) ([]string, bool) {
	pool := append([]*x509.Certificate{}, intermediates...)
	var fetched []string
	for cert := leaf; len(fetched) < maxAIADepth; {
		if len(cert.IssuingCertificateURL) == 0 || isSelfSigned(cert) {
			return fetched, false
		}
		issuer, err := fetchIssuer(ctx, cert.IssuingCertificateURL[0])
		if err != nil {
			return fetched, false
		}
		fetched = append(fetched, cert.IssuingCertificateURL[0])
		pool = append(pool, issuer)
		if verifyChain(leaf, pool, host) == nil {
			return fetched, true
		}
		cert = issuer
	}
	return fetched, false
}

// fetchIssuer runs one AIA fetch under its own timeout.
func fetchIssuer(ctx context.Context, rawURL string) (*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, aiaTimeout)
	defer cancel()
	return aiaFetch(ctx, rawURL)
}

// parseCertificate accepts DER or PEM.
func parseCertificate(b []byte) (*x509.Certificate, error) {
	if c, err := x509.ParseCertificate(b); err == nil {
		return c, nil
	}
	certs, err := parsePEMCerts(b)
	if err != nil || len(certs) == 0 {
		return nil, fmt.Errorf("not a DER or PEM certificate")
	}
	return certs[0], nil
}

// certInfo summarises a leaf certificate against the two names under test.
func certInfo(leaf *x509.Certificate, apex, www string) CertInfo {
	sum := sha256.Sum256(leaf.Raw)
	info := CertInfo{
		Subject:       leaf.Subject.CommonName,
		Issuer:        issuerName(leaf),
		NotBefore:     leaf.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:      leaf.NotAfter.UTC().Format(time.RFC3339),
		DaysRemaining: int(time.Until(leaf.NotAfter).Hours() / 24),
		SANs:          nonNil(leaf.DNSNames),
		CoversApex:    leaf.VerifyHostname(apex) == nil,
		CoversWWW:     leaf.VerifyHostname(www) == nil,
		Key:           keyDescription(leaf),
		Fingerprint:   hex.EncodeToString(sum[:]),
	}
	for _, n := range leaf.DNSNames {
		if strings.HasPrefix(n, "*.") {
			info.Wildcard = true
		}
	}
	if info.Subject == "" && len(leaf.DNSNames) > 0 {
		info.Subject = leaf.DNSNames[0]
	}
	return info
}

func issuerName(c *x509.Certificate) string {
	if c.Issuer.CommonName != "" {
		return c.Issuer.CommonName
	}
	if len(c.Issuer.Organization) > 0 {
		return c.Issuer.Organization[0]
	}
	return c.Issuer.String()
}

// issuerOrg is the organisation used for CAA matching.
func issuerOrg(c *x509.Certificate) string {
	if len(c.Issuer.Organization) > 0 {
		return c.Issuer.Organization[0]
	}
	return c.Issuer.CommonName
}

func keyDescription(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return c.PublicKeyAlgorithm.String()
	}
}

// probeOldVersions opens two fresh connections and reports whether the
// server still accepts TLS 1.0 and TLS 1.1.
func probeOldVersions(ctx context.Context, d dialer, ip netip.Addr, host string, timeout time.Duration) (tls10, tls11 *bool) {
	parallel(
		func() { tls10 = acceptsVersion(ctx, d, ip, host, tls.VersionTLS10, timeout) },
		func() { tls11 = acceptsVersion(ctx, d, ip, host, tls.VersionTLS11, timeout) },
	)
	return tls10, tls11
}

// acceptsVersion is true when a handshake capped at ver completes, false
// when the server turns it down, and nil when the question was never put:
// a connection that could not be made, or a handshake still unanswered at
// the deadline, says nothing about which versions the server accepts.
func acceptsVersion(ctx context.Context, d dialer, ip netip.Addr, host string, ver uint16, timeout time.Duration) *bool {
	_, err, dialed := handshakeOnce(ctx, d, ip, tlsConfig(host, ver, ver), timeout)
	switch {
	case !dialed:
		return nil
	case err == nil:
		return boolPtr(true)
	case ctx.Err() != nil, isTimeoutErr(err):
		return nil
	}
	return boolPtr(false)
}

func tcpNetwork(ip netip.Addr) string {
	if ip.Is6() {
		return "tcp6"
	}
	return "tcp4"
}

// parsePEMCerts decodes every CERTIFICATE block in b.
func parsePEMCerts(b []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no CERTIFICATE blocks")
	}
	return certs, nil
}
