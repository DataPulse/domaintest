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
}

// probeAddress connects to 80 and 443 for host at ip. On 80 it issues one
// GET; on 443 it performs the TLS handshake, issues one GET over it and
// then tests TLS 1.0/1.1 acceptance on fresh connections. Each stage is
// bounded by timeout.
func probeAddress(ctx context.Context, d dialer, ip netip.Addr, host, apex, www string, timeout time.Duration) addrProbe {
	p := addrProbe{IP: ip}
	parallel(
		func() { p.HTTP, p.HTTPRes = probeHTTPPort(ctx, d, ip, host, timeout) },
		func() { p.HTTPS, p.TLS, p.HTTPSRes = probeHTTPSPort(ctx, d, ip, host, apex, www, timeout) },
	)
	return p
}

func probeHTTPPort(ctx context.Context, d dialer, ip netip.Addr, host string, timeout time.Duration) (PortState, *HTTPResult) {
	conn, st := dialPort(ctx, d, portKey{IP: ip, Port: 80}, timeout)
	if conn == nil {
		return st, nil
	}
	defer conn.Close()
	res := httpRequest(conn, host, "/", time.Now().Add(timeout))
	return st, &res
}

func probeHTTPSPort(ctx context.Context, d dialer, ip netip.Addr, host, apex, www string, timeout time.Duration) (PortState, *TLSResult, *HTTPResult) {
	conn, st := dialPort(ctx, d, portKey{IP: ip, Port: 443}, timeout)
	if conn == nil {
		return st, nil, nil
	}
	defer conn.Close()
	tc, tlsRes := probeTLS(conn, host, apex, www, time.Now().Add(timeout))
	var httpRes *HTTPResult
	if tc != nil && tlsRes.Chain != ChainHandshakeFailed {
		r := httpRequest(tc, host, "/", time.Now().Add(timeout))
		httpRes = &r
		tlsRes.TLS10, tlsRes.TLS11 = probeOldVersions(ctx, d, ip, host, timeout)
	}
	return st, &tlsRes, httpRes
}
