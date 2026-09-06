package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// fixture reads a captured tool output from testdata.
func fixture(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", rel))
	if err != nil {
		t.Fatalf("fixture %s: %v", rel, err)
	}
	return string(b)
}

// fakeCall is one canned tool response.
type fakeCall struct {
	stdout string
	stderr string
	err    error
	delay  time.Duration
}

// fakeRunner serves canned responses keyed by "<tool> <args...>". A
// fallback function handles calls with no exact key.
type fakeRunner struct {
	mu        sync.Mutex
	responses map[string]fakeCall
	seq       map[string][]fakeCall // consumed in order, before responses
	fallback  func(tool string, args []string) (fakeCall, bool)
	calls     []string
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{responses: map[string]fakeCall{}, seq: map[string][]fakeCall{}}
}

// onSeq registers responses served one per call, in order.
func (f *fakeRunner) onSeq(tool string, args []string, calls ...fakeCall) {
	f.seq[callKey(tool, args)] = calls
}

func callKey(tool string, args []string) string {
	return filepath.Base(tool) + " " + strings.Join(args, " ")
}

func (f *fakeRunner) on(tool string, args []string, resp fakeCall) {
	f.responses[callKey(tool, args)] = resp
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	key := callKey(name, args)
	f.mu.Lock()
	f.calls = append(f.calls, key)
	resp, ok := f.responses[key]
	if q := f.seq[key]; len(q) > 0 {
		resp, ok = q[0], true
		f.seq[key] = q[1:]
	}
	f.mu.Unlock()
	if !ok && f.fallback != nil {
		resp, ok = f.fallback(filepath.Base(name), args)
	}
	if !ok {
		return nil, nil, fmt.Errorf("fakeRunner: unexpected call %q", key)
	}
	if resp.delay > 0 {
		select {
		case <-time.After(resp.delay):
		case <-ctx.Done():
			return nil, nil, fmt.Errorf("%s: %w", name, ctx.Err())
		}
	}
	return []byte(resp.stdout), []byte(resp.stderr), resp.err
}

func (f *fakeRunner) called(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// fakeDialer answers DialContext from a table of open "ip:port" addresses.
// Everything else is refused, or black-holed when hang is set.
type fakeDialer struct {
	open map[string]bool
	hang map[string]bool
	mu   sync.Mutex
	seen []string
}

func (d *fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.seen = append(d.seen, network+" "+address)
	d.mu.Unlock()
	if d.hang[address] {
		<-ctx.Done()
		return nil, &net.OpError{Op: "dial", Net: network, Err: ctx.Err()}
	}
	if d.open[address] {
		c1, c2 := net.Pipe()
		go func() { _ = c2.Close() }()
		return c1, nil
	}
	return nil, &net.OpError{Op: "dial", Net: network, Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
}

var errFake = errors.New("fake failure")

// withResolvConf points the reachability check at a temporary resolv.conf.
func withResolvConf(t *testing.T, content string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	old := resolvConfPath
	resolvConfPath = p
	t.Cleanup(func() { resolvConfPath = old })
}

// baseConfig is a config with fake tool names for use with fakeRunner.
func baseConfig(domain, server string) config {
	return config{
		Domain:         domain,
		Server:         server,
		Families:       []string{familyIPv4, familyIPv6},
		TimeoutSec:     5,
		QuicTimeoutSec: defaultQuicTimeoutSec,
		DelvPath:       "delv",
		DigPath:        "dig",
		QuicPath:       "quicprobe",
		dnsFamily:      serverFamily(server),
	}
}

func contains(list []string, substr string) bool {
	for _, s := range list {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// writeFile creates or replaces a small text file.
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

// check reports a mismatch between got and want under a label.
func check(t *testing.T, what string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s = %#v, want %#v", what, got, want)
	}
}
