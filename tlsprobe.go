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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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
var aiaFetch = fetchAIA

// CertInfo describes the leaf certificate a server presented.
type CertInfo struct {
	Subject       string   `json:"subject"`
	Issuer        string   `json:"issuer"`
	NotBefore     string   `json:"not_before"`
	NotAfter      string   `json:"not_after"`
	DaysRemaining int      `json:"days_remaining"`
	SANs          []string `json:"sans,omitempty"`
	CoversApex    bool     `json:"covers_apex"`
	CoversWWW     bool     `json:"covers_www"`
	Wildcard      bool     `json:"wildcard,omitempty"`
	Key           string   `json:"key"`
	Fingerprint   string   `json:"fingerprint_sha256"`
}

// TLSResult is the outcome of one TLS handshake on port 443.
type TLSResult struct {
	Chain       string    `json:"chain"`
	Version     string    `json:"version,omitempty"`
	ALPN        string    `json:"alpn,omitempty"`
	Cipher      string    `json:"cipher,omitempty"`
	TLS10       bool      `json:"tls10"`
	TLS11       bool      `json:"tls11"`
	Cert        *CertInfo `json:"cert,omitempty"`
	ChainLength int       `json:"chain_length,omitempty"`
	Error       string    `json:"error,omitempty"`
	chain       []*x509.Certificate
	pkixValid   bool
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
func probeTLS(conn net.Conn, host, apex, www string, deadline time.Time) (*tls.Conn, TLSResult) {
	_ = conn.SetDeadline(deadline)
	tc := tls.Client(conn, tlsConfig(host, 0, 0))
	if err := tc.Handshake(); err != nil {
		return nil, TLSResult{Chain: ChainHandshakeFailed, Error: err.Error()}
	}
	state := tc.ConnectionState()
	res := TLSResult{
		Version:     formatTLSVersion(state.Version),
		ALPN:        state.NegotiatedProtocol,
		Cipher:      tls.CipherSuiteName(state.CipherSuite),
		ChainLength: len(state.PeerCertificates),
		chain:       state.PeerCertificates,
	}
	if len(state.PeerCertificates) == 0 {
		res.Chain, res.Error = ChainInvalid, "server sent no certificate"
		return tc, res
	}
	res.Chain, res.Error = classifyChain(state.PeerCertificates, host)
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
func classifyChain(chain []*x509.Certificate, host string) (string, string) {
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
	return classifyVerifyError(err, chain, host)
}

func verifyChain(leaf *x509.Certificate, intermediates []*x509.Certificate, host string) error {
	pool := x509.NewCertPool()
	for _, c := range intermediates {
		pool.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: tlsRoots, Intermediates: pool})
	return err
}

func classifyVerifyError(err error, chain []*x509.Certificate, host string) (string, string) {
	var hostErr x509.HostnameError
	var authErr x509.UnknownAuthorityError
	leaf := chain[0]
	switch {
	case errors.As(err, &hostErr):
		return ChainHostnameMismatch, err.Error()
	case errors.As(err, &authErr) && isSelfSigned(leaf):
		return ChainSelfSigned, "self-signed certificate"
	case errors.As(err, &authErr):
		if completed := completeViaAIA(leaf, chain[1:], host); completed {
			return ChainIncomplete, "server did not send the intermediate certificate (fetched via AIA: " + leaf.IssuingCertificateURL[0] + ")"
		}
		return ChainUntrustedRoot, err.Error()
	default:
		return ChainInvalid, err.Error()
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

// completeViaAIA reports whether the chain becomes valid once the issuer
// certificate named in the leaf's AIA extension is added: the classic
// "works in browsers, fails elsewhere" incomplete chain.
func completeViaAIA(leaf *x509.Certificate, intermediates []*x509.Certificate, host string) bool {
	if len(leaf.IssuingCertificateURL) == 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	issuer, err := aiaFetch(ctx, leaf.IssuingCertificateURL[0])
	if err != nil {
		return false
	}
	return verifyChain(leaf, append(append([]*x509.Certificate{}, intermediates...), issuer), host) == nil
}

// fetchAIA downloads a certificate (DER or PEM) from url.
func fetchAIA(ctx context.Context, url string) (*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	return parseCertificate(body)
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
		SANs:          leaf.DNSNames,
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
func probeOldVersions(ctx context.Context, d dialer, ip netip.Addr, host string, timeout time.Duration) (tls10, tls11 bool) {
	parallel(
		func() { tls10 = acceptsVersion(ctx, d, ip, host, tls.VersionTLS10, timeout) },
		func() { tls11 = acceptsVersion(ctx, d, ip, host, tls.VersionTLS11, timeout) },
	)
	return tls10, tls11
}

func acceptsVersion(ctx context.Context, d dialer, ip netip.Addr, host string, ver uint16, timeout time.Duration) bool {
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.DialContext(dctx, tcpNetwork(ip), netip.AddrPortFrom(ip, 443).String())
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	tc := tls.Client(conn, tlsConfig(host, ver, ver))
	return tc.Handshake() == nil
}

func tcpNetwork(ip netip.Addr) string {
	if ip.Is6() {
		return "tcp6"
	}
	return "tcp4"
}
