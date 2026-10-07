package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/netip"
	"testing"
	"time"
)

func quicFixture(t *testing.T, file string) *QUICResult {
	t.Helper()
	var q QUICResult
	if err := json.Unmarshal([]byte(fixture(t, "quicprobe/"+file)), &q); err != nil {
		t.Fatal(err)
	}
	return &q
}

// Alt-Svc headers as served on 2026-10-07: www.google.com (h3 and the h3-29
// draft), www.cloudflare.com and www.osu.edu (h3); osu.edu's apex sends
// none.
func TestH3Advertised(t *testing.T) {
	for _, c := range []struct {
		name, altSvc string
		want         *bool
	}{
		{"google", `h3=":443"; ma=2592000,h3-29=":443"; ma=2592000`, boolPtr(true)},
		{"cloudflare", `h3=":443"; ma=86400`, boolPtr(true)},
		{"draft only", `h3-29=":443"; ma=2592000`, boolPtr(true)},
		{"h2 only", `h2=":443"; ma=86400`, boolPtr(false)},
		{"clear", `clear`, boolPtr(false)},
		{"osu.edu apex: none", ``, boolPtr(false)},
	} {
		check(t, c.name, h3Advertised(&HTTPResult{Status: 200, AltSvc: c.altSvc}), c.want)
	}
	check(t, "no response", h3Advertised(&HTTPResult{Error: "read: EOF"}), (*bool)(nil))
	check(t, "not probed", h3Advertised(nil), (*bool)(nil))
}

// quicprobe captures: an endpoint that answered and refused is absent;
// silence is absent only when nothing advertises h3; a local failure says
// nothing.
func TestHTTP3Verdict(t *testing.T) {
	yes, no := boolPtr(true), boolPtr(false)
	for _, c := range []struct {
		file string
		adv  *bool
		want *bool
	}{
		{"google_supported.json", yes, yes},
		{"cloudfront_h3_enabled.json", nil, yes},
		{"cloudfront_h3_disabled.json", yes, no}, // tls_rejected: answered and refused
		{"blackhole_timeout.json", no, no},       // silent, not advertised
		{"blackhole_timeout.json", yes, nil},     // silent but advertised: filtered on our path?
		{"blackhole_timeout.json", nil, nil},     // silent, advertisement unknown
		{"nxdomain_error.json", no, nil},         // resolve_failed: a local failure
		{"usage_error.json", no, nil},
	} {
		check(t, c.file, http3Verdict(quicFixture(t, c.file), c.adv), c.want)
	}
	check(t, "not probed", http3Verdict(nil, yes), (*bool)(nil))
}

func TestHTTP11Verdict(t *testing.T) {
	ok := &TLSResult{Chain: ChainValid}
	for _, c := range []struct {
		name string
		st   PortState
		tls  *TLSResult
		res  *HTTPResult
		want *bool
	}{
		{"answered", PortOpen, ok, &HTTPResult{Status: 200}, boolPtr(true)},
		{"port refused", PortRefused, nil, nil, boolPtr(false)},
		{"port timeout", PortTimeout, nil, nil, nil},
		{"alert 120 on the http/1.1 offer", PortOpen, &TLSResult{Chain: ChainHandshakeFailed, noALPN: true}, nil, boolPtr(false)},
		{"handshake failed otherwise", PortOpen, &TLSResult{Chain: ChainHandshakeFailed}, nil, nil},
		{"not HTTP/1.1 on the session", PortOpen, ok, &HTTPResult{Error: `read: malformed HTTP response "\x00\x00"`}, boolPtr(false)},
		{"read timed out", PortOpen, ok, &HTTPResult{Error: "read: i/o timeout"}, nil},
	} {
		check(t, c.name, http11Verdict(c.st, c.tls, c.res), c.want)
	}
}

// alpnServer is a TLS listener that speaks only the given ALPN protocols.
// A Go server refuses a client offering none of them with alert 120.
func alpnServer(t *testing.T, protos ...string) (*mappedDialer, netip.Addr) {
	t.Helper()
	ca := newTestCA(t, "root")
	withRoots(t, ca.pool)
	leaf, key := ca.issue(t, certSpec{sans: []string{"example.test"}, issuer: ca})
	srv := tlsServer(t, okHandler(nil), []*x509.Certificate{leaf, ca.cert}, key, tls.VersionTLS12, tls.VersionTLS13)
	srv.TLS.NextProtos = protos
	d := newMappedDialer()
	ip := netip.MustParseAddr("192.0.2.10")
	d.mapTarget(ip.String(), 443, srv)
	return d, ip
}

func TestAcceptsALPN(t *testing.T) {
	for _, c := range []struct {
		name   string
		protos []string
		want   *bool
	}{
		{"h2 and http/1.1", []string{"h2", "http/1.1"}, boolPtr(true)},
		{"h2 only", []string{"h2"}, boolPtr(true)},
		{"http/1.1 only: alert 120", []string{"http/1.1"}, boolPtr(false)},
		{"no ALPN at all", nil, boolPtr(false)},
	} {
		t.Run(c.name, func(t *testing.T) {
			d, ip := alpnServer(t, c.protos...)
			check(t, "h2", acceptsALPN(context.Background(), d, ip, "example.test", "h2", 2*time.Second), c.want)
		})
	}
	// Nothing listening: the question was never put.
	d := newMappedDialer()
	check(t, "no listener", acceptsALPN(context.Background(), d, netip.MustParseAddr("192.0.2.11"), "example.test", "h2", time.Second), (*bool)(nil))
}

// probeAddress over servers speaking different ALPN sets. A Go server
// listing only h2 still lets an http/1.1-only client in, as if it offered
// no ALPN (go.dev/issue/46310), and then serves it HTTP/1.1, so both
// versions are served. A server speaking neither refuses both offers with
// alert 120.
func TestProbeAddress_HTTPVersions(t *testing.T) {
	yes, no := boolPtr(true), boolPtr(false)
	for _, c := range []struct {
		name   string
		protos []string
		h1, h2 *bool
	}{
		{"h2 and http/1.1", []string{"h2", "http/1.1"}, yes, yes},
		{"h2 listed, 1.1 let in", []string{"h2"}, yes, yes},
		{"http/1.1 only", []string{"http/1.1"}, yes, no},
		{"neither", []string{"acme-tls/1"}, no, no},
	} {
		t.Run(c.name, func(t *testing.T) {
			d, ip := alpnServer(t, c.protos...)
			p := probeAddress(context.Background(), d, ip, "example.test", "example.test", "www.example.test", 2*time.Second)
			v := httpVersionsFor(p, nil)
			check(t, "http1_1", v.HTTP1_1, c.h1)
			check(t, "http2", v.HTTP2, c.h2)
			check(t, "http3 not probed", v.HTTP3, (*bool)(nil))
		})
	}
}

func TestHTTPVersionFindings(t *testing.T) {
	yes, no := boolPtr(true), boolPtr(false)
	addr := func(h1, h2, h3, adv *bool) AddrWeb {
		return AddrWeb{IP: "192.0.2.1", HTTPS: PortOpen, HTTPVersions: &HTTPVersions{HTTP1_1: h1, HTTP2: h2, HTTP3: h3, H3Advertised: adv}}
	}
	codes := func(addrs ...AddrWeb) []string {
		var f findings
		f.httpVersionFindings("apex", addrs)
		var out []string
		for _, x := range f.list {
			out = append(out, x.Code+":"+string(x.Severity))
		}
		return out
	}
	check(t, "all served", codes(addr(yes, yes, yes, yes)), []string(nil))
	check(t, "no h2, no h3", codes(addr(yes, no, no, no)), []string{"http2_absent:info", "http3_absent:info"})
	check(t, "h2 partial", codes(addr(yes, yes, nil, nil), addr(yes, no, nil, nil)), []string{"http2_partial:info"})
	check(t, "h2-only", codes(addr(no, yes, nil, nil)), []string{"http1_1_absent:info"})
	check(t, "advertised, silent", codes(addr(yes, yes, nil, yes)), []string{"h3_advertised_unreachable:warn"})
	check(t, "unknowns say nothing", codes(addr(nil, nil, nil, nil)), []string(nil))
	// 443 refused (lescouleursdudedans.fr in the 2026-10-07 batch): no
	// version is served, but that is https_unreachable's finding.
	closed := addr(no, no, nil, nil)
	closed.HTTPS = PortRefused
	check(t, "no HTTPS is not a version fact", codes(closed), []string(nil))
}
