package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"
)

// HTTPVersions says which HTTP versions an address serves over TLS and QUIC
// on 443. Each value is true, false, or null when the question could not be
// put (no connection, a timeout, nothing probed): silence is never read as
// absence. Port 80 is plain HTTP/1.1 and is reported by the http result.
//
// Until 2026-10-07 the report carried tls.alpn instead. The probe's
// handshake offers only http/1.1 (the GET that follows on it is HTTP/1.1),
// so that field could never say anything else, and read as "no HTTP/2" on
// CDNs that serve h3.
type HTTPVersions struct {
	HTTP1_1 *bool `json:"http1_1"`
	HTTP2   *bool `json:"http2"`
	HTTP3   *bool `json:"http3"`
	// H3Advertised is whether the HTTPS response's Alt-Svc header offers
	// h3, which is how a browser learns to try it.
	H3Advertised *bool `json:"h3_advertised"`
}

// noALPNAlert reports a handshake the server ended with alert 120,
// no_application_protocol: it speaks none of the protocols offered. Go
// keeps the alert type unexported, so its fixed text is matched.
func noALPNAlert(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no application protocol")
}

// http11Verdict judges HTTP/1.1 from the main handshake, which offered
// only http/1.1, and the GET sent on it.
func http11Verdict(st PortState, tlsRes *TLSResult, res *HTTPResult) *bool {
	switch {
	case st == PortRefused:
		return boolPtr(false)
	case tlsRes == nil:
		return nil
	case tlsRes.noALPN:
		return boolPtr(false)
	case tlsRes.Chain == ChainHandshakeFailed || res == nil:
		return nil
	case res.Status > 0:
		return boolPtr(true)
	case strings.Contains(res.Error, "malformed HTTP"):
		return boolPtr(false) // the TLS session carried something that is not HTTP/1.1
	}
	return nil
}

// acceptsALPN offers only proto on a fresh connection and reports whether
// the server chose it: true when it did, false when it completed the
// handshake without it or refused the protocol (alert 120), and nil when
// the question was never put (no connection, a timeout, a handshake turned
// down for another reason, which says nothing about the protocol).
func acceptsALPN(ctx context.Context, d dialer, ip netip.Addr, host, proto string, timeout time.Duration) *bool {
	cfg := tlsConfig(host, 0, 0)
	cfg.NextProtos = []string{proto}
	state, err, dialed := handshakeOnce(ctx, d, ip, cfg, timeout)
	switch {
	case !dialed:
		return nil
	case err == nil:
		return boolPtr(state.NegotiatedProtocol == proto)
	case noALPNAlert(err):
		return boolPtr(false)
	}
	return nil
}

// handshakeOnce dials 443 at ip and runs one TLS handshake with cfg. dialed
// is false when no connection was made.
func handshakeOnce(ctx context.Context, d dialer, ip netip.Addr, cfg *tls.Config, timeout time.Duration) (tls.ConnectionState, error, bool) {
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.DialContext(dctx, tcpNetwork(ip), netip.AddrPortFrom(ip, 443).String())
	if err != nil {
		return tls.ConnectionState{}, err, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(ioDeadline(ctx, timeout))
	tc := tls.Client(conn, cfg)
	if err := tc.Handshake(); err != nil {
		return tls.ConnectionState{}, err, true
	}
	return tc.ConnectionState(), nil, true
}

// isTimeoutErr reports a network timeout.
func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// h3Advertised reads the Alt-Svc header of the HTTPS response: true when it
// lists h3 or an h3-NN draft, false when there was a response without one,
// nil when there was no response.
func h3Advertised(res *HTTPResult) *bool {
	if res == nil || res.Status == 0 {
		return nil
	}
	for _, entry := range strings.Split(res.AltSvc, ",") {
		id, _, _ := strings.Cut(strings.TrimSpace(entry), "=")
		if id == "h3" || strings.HasPrefix(id, "h3-") {
			return boolPtr(true)
		}
	}
	return boolPtr(false)
}

// http3Verdict judges HTTP/3 from quicprobe's QUIC handshake (ALPN h3).
// An endpoint that answered and refused is false. Silence (reason timeout)
// is false only when nothing advertises h3 either: an address that offers
// h3 in Alt-Svc but does not answer on UDP may be filtered on the probe's
// path, so that is unknown, not absent. A probe that failed locally says
// nothing.
func http3Verdict(q *QUICResult, advertised *bool) *bool {
	switch {
	case q == nil:
		return nil
	case q.Supported:
		return boolPtr(true)
	}
	switch q.Reason {
	case "tls_rejected", "version_negotiation", "stateless_reset", "transport_error", "application_error":
		return boolPtr(false)
	case "timeout":
		if advertised != nil && !*advertised {
			return boolPtr(false)
		}
	}
	return nil
}

// httpVersionsFor assembles one address's versions; nil when the address
// was not probed at all.
func httpVersionsFor(p addrProbe, q *QUICResult) *HTTPVersions {
	adv := h3Advertised(p.HTTPSRes)
	return &HTTPVersions{
		HTTP1_1:      http11Verdict(p.HTTPS, p.TLS, p.HTTPSRes),
		HTTP2:        p.http2,
		HTTP3:        http3Verdict(q, adv),
		H3Advertised: adv,
	}
}
