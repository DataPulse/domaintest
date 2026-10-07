package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"syscall"
	"time"
)

// PortState is the outcome of one TCP connect attempt.
type PortState string

const (
	PortOpen        PortState = "open"
	PortRefused     PortState = "refused"
	PortTimeout     PortState = "timeout"
	PortUnreachable PortState = "unreachable"
	PortError       PortState = "error"
	PortSkipped     PortState = "skipped" // reserved address, not probed
)

var webPorts = []int{80, 443}

// portKey identifies one (address, port) probe.
type portKey struct {
	IP   netip.Addr
	Port int
}

// dialer abstracts net.Dialer for tests.
type dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// probePorts dials every (addr, port) pair in parallel and returns the state
// of each. Duplicate addresses are collapsed. Connections are closed at once;
// it is the bare reachability check used by tests and by names whose
// application-layer probe is not wanted.
func probePorts(ctx context.Context, d dialer, addrs []netip.Addr, ports []int, timeout time.Duration) map[portKey]PortState {
	keys := uniquePortKeys(addrs, ports)
	results := make(map[portKey]PortState, len(keys))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, k := range keys {
		wg.Add(1)
		go func(k portKey) {
			defer wg.Done()
			conn, st := dialPort(ctx, d, k, timeout)
			if conn != nil {
				_ = conn.Close()
			}
			mu.Lock()
			results[k] = st
			mu.Unlock()
		}(k)
	}
	wg.Wait()
	return results
}

func uniquePortKeys(addrs []netip.Addr, ports []int) []portKey {
	seen := make(map[portKey]bool)
	var keys []portKey
	for _, a := range addrs {
		a = a.Unmap()
		for _, p := range ports {
			k := portKey{IP: a, Port: p}
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].IP != keys[j].IP {
			return keys[i].IP.Less(keys[j].IP)
		}
		return keys[i].Port < keys[j].Port
	})
	return keys
}

// dialPort connects to one (ip, port) and returns the open connection on
// success (caller closes it) with the classified state.
func dialPort(ctx context.Context, d dialer, k portKey, timeout time.Duration) (net.Conn, PortState) {
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.DialContext(dctx, tcpNetwork(k.IP), netip.AddrPortFrom(k.IP, uint16(k.Port)).String())
	if err != nil {
		return nil, classifyDialError(err)
	}
	return conn, PortOpen
}

// dialOnce is dialPort without keeping the connection.
func dialOnce(ctx context.Context, d dialer, k portKey, timeout time.Duration) PortState {
	conn, st := dialPort(ctx, d, k, timeout)
	if conn != nil {
		_ = conn.Close()
	}
	return st
}

// classifyDialError maps a dial error onto a PortState.
func classifyDialError(err error) PortState {
	switch {
	case errors.Is(err, context.DeadlineExceeded), os.IsTimeout(err):
		return PortTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return PortRefused
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.EADDRNOTAVAIL):
		return PortUnreachable
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return PortTimeout
	}
	return PortError
}

// addrProbe is everything learned about one address of one hostname.
type addrProbe struct {
	IP       netip.Addr
	HTTP     PortState
	HTTPS    PortState
	HTTPRes  *HTTPResult
	HTTPSRes *HTTPResult
	TLS      *TLSResult
	http2    *bool // h2 negotiated on a handshake that offered only h2
}

// probeAddress connects to 80 and 443 for host at ip. On 80 it issues one
// GET; on 443 it performs the TLS handshake and issues one HTTP/1.1 GET
// over it, while fresh connections test TLS 1.0/1.1 acceptance and HTTP/2.
// Each stage is bounded by timeout.
func probeAddress(ctx context.Context, d dialer, ip netip.Addr, host, apex, www string, timeout time.Duration) addrProbe {
	p := addrProbe{IP: ip}
	parallel(
		func() { p.HTTP, p.HTTPRes = probeHTTPPort(ctx, d, ip, host, timeout) },
		func() { probeHTTPSPort(ctx, d, &p, host, apex, www, timeout) },
	)
	return p
}

func probeHTTPPort(ctx context.Context, d dialer, ip netip.Addr, host string, timeout time.Duration) (PortState, *HTTPResult) {
	conn, st := dialPort(ctx, d, portKey{IP: ip, Port: 80}, timeout)
	if conn == nil {
		return st, nil
	}
	defer conn.Close()
	res := httpRequest(conn, host, "/", ioDeadline(ctx, timeout))
	return st, &res
}

// probeHTTPSPort fills p's 443 results. HTTP/2 is asked on a connection of
// its own even when the main handshake failed: an h2-only server refuses
// that handshake (it offered only http/1.1) and is found out this way.
func probeHTTPSPort(ctx context.Context, d dialer, p *addrProbe, host, apex, www string, timeout time.Duration) {
	conn, st := dialPort(ctx, d, portKey{IP: p.IP, Port: 443}, timeout)
	p.HTTPS = st
	if conn == nil {
		if st == PortRefused {
			p.http2 = boolPtr(false)
		}
		return
	}
	defer conn.Close()
	tc, tlsRes := probeTLS(ctx, conn, host, apex, www, ioDeadline(ctx, timeout))
	p.TLS = &tlsRes
	ok := tc != nil && tlsRes.Chain != ChainHandshakeFailed
	parallel(
		func() { p.http2 = acceptsALPN(ctx, d, p.IP, host, "h2", timeout) },
		func() {
			if ok {
				r := httpRequest(tc, host, "/", ioDeadline(ctx, timeout))
				p.HTTPSRes = &r
			}
		},
		func() {
			if ok {
				tlsRes.TLS10, tlsRes.TLS11 = probeOldVersions(ctx, d, p.IP, host, timeout)
			}
		},
	)
	p.TLS = &tlsRes
}

// ioDeadline is when a probe's reads and writes must stop: its own timeout
// from now, or the run's deadline when that comes first. A deadline set
// from the clock alone would let a handshake begun just before the run
// deadline outlive it.
func ioDeadline(ctx context.Context, timeout time.Duration) time.Time {
	d := time.Now().Add(timeout)
	if cd, ok := ctx.Deadline(); ok && cd.Before(d) {
		return cd
	}
	return d
}
