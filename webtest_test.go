package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// testCA is an in-memory certificate authority for TLS tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T, name string) *testCA {
	return newTestCAWithOrg(t, name, "domaintest test CA")
}

// newTestCAWithOrg creates a CA whose organisation becomes the issuer
// organisation of every leaf it signs (what CAA matching looks at).
func newTestCAWithOrg(t *testing.T, name, org string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name, Organization: []string{org}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// certSpec describes a leaf to mint.
type certSpec struct {
	sans      []string
	notBefore time.Time
	notAfter  time.Time
	issuer    *testCA // nil: self-signed
	org       string
	isCA      bool
}

// issue creates a certificate and returns it with its key.
func (ca *testCA) issue(t *testing.T, spec certSpec) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if spec.notBefore.IsZero() {
		spec.notBefore = time.Now().Add(-time.Hour)
	}
	if spec.notAfter.IsZero() {
		spec.notAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	cn := ""
	if len(spec.sans) > 0 {
		cn = spec.sans[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{spec.org}},
		DNSNames:              spec.sans,
		NotBefore:             spec.notBefore,
		NotAfter:              spec.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  spec.isCA,
	}
	parent, signer := tmpl, key
	if spec.issuer != nil {
		parent, signer = spec.issuer.cert, spec.issuer.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

// tlsServer starts a TLS listener serving handler with the given chain.
func tlsServer(t *testing.T, handler http.Handler, chain []*x509.Certificate, key *ecdsa.PrivateKey, minVer, maxVer uint16) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	raw := make([][]byte, len(chain))
	for i, c := range chain {
		raw[i] = c.Raw
	}
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: raw, PrivateKey: key, Leaf: chain[0]}},
		MinVersion:   minVer,
		MaxVersion:   maxVer,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// plainServer starts an HTTP listener.
func plainServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// mappedDialer redirects "ip:port" targets to local test servers while
// recording what was asked for. Unmapped targets are refused.
type mappedDialer struct {
	mu      sync.Mutex
	targets map[string]string // "ip:port" -> "127.0.0.1:port"
	seen    []string
}

func newMappedDialer() *mappedDialer { return &mappedDialer{targets: map[string]string{}} }

func (d *mappedDialer) mapTarget(ip string, port int, srv *httptest.Server) {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := net.JoinHostPort(ip, itoa(port))
	d.targets[key] = strings.TrimPrefix(strings.TrimPrefix(srv.URL, "https://"), "http://")
}

func (d *mappedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.seen = append(d.seen, network+" "+address)
	target, ok := d.targets[address]
	d.mu.Unlock()
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: network, Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", target)
}

func itoa(n int) string { return strconv.Itoa(n) }

// withRoots points chain verification at the test CA for the test.
func withRoots(t *testing.T, pool *x509.CertPool) {
	t.Helper()
	old := tlsRoots
	tlsRoots = pool
	t.Cleanup(func() { tlsRoots = old })
}

// okHandler answers 200 with optional headers.
func okHandler(headers map[string]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// redirectHandler answers with a Location.
func redirectHandler(status int, location string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", location)
		w.WriteHeader(status)
	})
}

func statusHandler(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })
}
