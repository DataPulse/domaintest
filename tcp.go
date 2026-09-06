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
)

var webPorts = []int{80, 443}

// portKey identifies one (address, port) probe; identical keys are only
// dialed once even when apex and www share addresses.
type portKey struct {
	IP   netip.Addr
	Port int
}

// dialer abstracts net.Dialer for tests.
type dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// probePorts dials every (addr, port) pair in parallel and returns the state
// of each. Duplicate addresses are collapsed.
func probePorts(ctx context.Context, d dialer, addrs []netip.Addr, ports []int, timeout time.Duration) map[portKey]PortState {
	keys := uniquePortKeys(addrs, ports)
	results := make(map[portKey]PortState, len(keys))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, k := range keys {
		wg.Add(1)
		go func(k portKey) {
			defer wg.Done()
			st := dialOnce(ctx, d, k, timeout)
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

func dialOnce(ctx context.Context, d dialer, k portKey, timeout time.Duration) PortState {
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	network := "tcp4"
	if k.IP.Is6() {
		network = "tcp6"
	}
	conn, err := d.DialContext(dctx, network, netip.AddrPortFrom(k.IP, uint16(k.Port)).String())
	if err == nil {
		_ = conn.Close()
		return PortOpen
	}
	return classifyDialError(err)
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
