package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"
)

func listen(t *testing.T, addr string) (netip.AddrPort, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String()), func() { _ = ln.Close() }
}

func TestProbePorts_OpenAndRefusedIPv4(t *testing.T) {
	open, closeOpen := listen(t, "127.0.0.1:0")
	defer closeOpen()
	closed, closeClosed := listen(t, "127.0.0.1:0")
	closeClosed()

	ports := []int{int(open.Port()), int(closed.Port())}
	res := probePorts(context.Background(), &netDialer{}, []netip.Addr{open.Addr()}, ports, time.Second)
	if got := res[portKey{IP: open.Addr(), Port: int(open.Port())}]; got != PortOpen {
		t.Errorf("open port reported %q", got)
	}
	if got := res[portKey{IP: open.Addr(), Port: int(closed.Port())}]; got != PortRefused {
		t.Errorf("closed port reported %q", got)
	}
}

func TestProbePorts_OpenIPv6(t *testing.T) {
	open, closeOpen := listen(t, "[::1]:0")
	defer closeOpen()
	res := probePorts(context.Background(), &netDialer{}, []netip.Addr{open.Addr()}, []int{int(open.Port())}, time.Second)
	if got := res[portKey{IP: open.Addr(), Port: int(open.Port())}]; got != PortOpen {
		t.Errorf("IPv6 open port reported %q", got)
	}
}

func TestProbePorts_TimeoutIsHonoured(t *testing.T) {
	// 192.0.2.1 is TEST-NET-1 (RFC 5737): black-holed on the public Internet.
	ip := netip.MustParseAddr("192.0.2.1")
	start := time.Now()
	res := probePorts(context.Background(), &netDialer{}, []netip.Addr{ip}, webPorts, 500*time.Millisecond)
	elapsed := time.Since(start)
	for _, p := range webPorts {
		st := res[portKey{IP: ip, Port: p}]
		if st != PortTimeout && st != PortUnreachable {
			t.Errorf("port %d: %q, want timeout or unreachable", p, st)
		}
	}
	if elapsed > 2*time.Second {
		t.Errorf("probes ran %v, timeout not honoured", elapsed)
	}
}

func TestProbePorts_DedupesAndFakeDialer(t *testing.T) {
	a := netip.MustParseAddr("192.0.2.10")
	b := netip.MustParseAddr("2001:db8::10")
	d := &fakeDialer{open: map[string]bool{"192.0.2.10:443": true, "[2001:db8::10]:80": true}}
	res := probePorts(context.Background(), d, []netip.Addr{a, b, a, netip.MustParseAddr("::ffff:192.0.2.10")}, webPorts, time.Second)
	if len(res) != 4 {
		t.Errorf("expected 4 unique probes, got %d: %v", len(res), res)
	}
	if len(d.seen) != 4 {
		t.Errorf("dialer should be called once per unique key, got %v", d.seen)
	}
	want := map[portKey]PortState{
		{a, 80}: PortRefused, {a, 443}: PortOpen, {b, 80}: PortOpen, {b, 443}: PortRefused,
	}
	for k, st := range want {
		if res[k] != st {
			t.Errorf("%v: %q, want %q", k, res[k], st)
		}
	}
	for _, s := range d.seen {
		if s[:4] != "tcp4" && s[:4] != "tcp6" {
			t.Errorf("dialer network should be tcp4/tcp6, got %q", s)
		}
	}
}

func TestProbePorts_HangingDialTimesOut(t *testing.T) {
	a := netip.MustParseAddr("192.0.2.20")
	d := &fakeDialer{hang: map[string]bool{"192.0.2.20:80": true, "192.0.2.20:443": true}}
	start := time.Now()
	res := probePorts(context.Background(), d, []netip.Addr{a}, webPorts, 100*time.Millisecond)
	if time.Since(start) > time.Second {
		t.Error("hanging dials should be cut off by the timeout")
	}
	if res[portKey{a, 80}] != PortTimeout || res[portKey{a, 443}] != PortTimeout {
		t.Errorf("expected timeouts, got %v", res)
	}
}

func TestUniquePortKeys_Sorted(t *testing.T) {
	keys := uniquePortKeys([]netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1")}, []int{443, 80})
	want := []portKey{
		{netip.MustParseAddr("10.0.0.1"), 80}, {netip.MustParseAddr("10.0.0.1"), 443},
		{netip.MustParseAddr("10.0.0.2"), 80}, {netip.MustParseAddr("10.0.0.2"), 443},
	}
	if len(keys) != len(want) {
		t.Fatalf("got %v", keys)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Errorf("index %d: %v, want %v", i, keys[i], want[i])
		}
	}
	if got := uniquePortKeys(nil, webPorts); len(got) != 0 {
		t.Errorf("no addrs should give no keys, got %v", got)
	}
}

func TestClassifyDialError(t *testing.T) {
	opErr := func(err error) error { return &net.OpError{Op: "dial", Err: err} }
	cases := []struct {
		err  error
		want PortState
	}{
		{context.DeadlineExceeded, PortTimeout},
		{opErr(os.NewSyscallError("connect", syscall.ECONNREFUSED)), PortRefused},
		{opErr(syscall.ENETUNREACH), PortUnreachable},
		{opErr(syscall.EHOSTUNREACH), PortUnreachable},
		{opErr(syscall.EADDRNOTAVAIL), PortUnreachable},
		{opErr(&timeoutErr{}), PortTimeout},
		{errors.New("something else"), PortError},
	}
	for _, c := range cases {
		if got := classifyDialError(c.err); got != c.want {
			t.Errorf("%v: %q, want %q", c.err, got, c.want)
		}
	}
}

type timeoutErr struct{}

func (*timeoutErr) Error() string   { return "i/o timeout" }
func (*timeoutErr) Timeout() bool   { return true }
func (*timeoutErr) Temporary() bool { return true }
