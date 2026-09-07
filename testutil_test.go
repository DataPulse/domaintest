package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
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
	res := resolver{}
	if server != "" {
		var err error
		if res, err = parseResolver(server); err != nil {
			panic("baseConfig: " + err.Error())
		}
	}
	return config{
		Domain:         domain,
		Resolver:       res,
		Families:       []string{familyIPv4, familyIPv6},
		TimeoutSec:     5,
		TCPTimeoutSec:  defaultTCPTimeoutSec,
		QuicTimeoutSec: defaultQuicTimeoutSec,
		DNSConcurrency: 0, // unlimited unless a test caps it
		HSTSCache:      noCachePath,
		DelvPath:       "delv",
		DigPath:        "dig",
		QuicPath:       "quicprobe",
		dnsFamily:      serverFamily(res.Host),
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

// hostWeb assembles a HostWeb from bare port states, for findings tests.
func hostWeb(addrs []netip.Addr, ports map[portKey]PortState, quic map[string]*QUICResult) *HostWeb {
	if len(addrs) == 0 {
		return nil
	}
	h := &HostWeb{}
	seen := map[netip.Addr]bool{}
	for _, ip := range addrs {
		if seen[ip] {
			continue
		}
		seen[ip] = true
		h.add(AddrWeb{IP: ip.String(), HTTP: ports[portKey{IP: ip, Port: 80}], HTTPS: ports[portKey{IP: ip, Port: 443}], QUIC: quic[ip.String()]})
	}
	return h
}

// fixtureIndex maps "query_name/TYPE" to captured delv output by scanning
// every fixture under testdata/delv once. Positive answers are indexed by
// the types they contain; negative answers serve any type not positively
// covered for that name.
type fixtureIndex struct {
	positive map[string]string // name/TYPE -> content
	negative map[string]string // name -> content
}

var (
	fixtureIndexOnce sync.Once
	fixtureIndexData *fixtureIndex
)

func loadFixtureIndex(t *testing.T) *fixtureIndex {
	t.Helper()
	fixtureIndexOnce.Do(func() {
		idx := &fixtureIndex{positive: map[string]string{}, negative: map[string]string{}}
		_ = filepath.WalkDir("testdata/delv", func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			indexFixture(idx, string(b))
			return nil
		})
		fixtureIndexData = idx
	})
	return fixtureIndexData
}

func indexFixture(idx *fixtureIndex, content string) {
	name := ""
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "query_name:") {
			name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(line, "query_name:")), "."))
		}
	}
	if name == "" {
		return
	}
	l := parseDelvYAML(content, "")
	if l.Status != StatusOK {
		if _, ok := idx.negative[name]; !ok {
			idx.negative[name] = content
		}
		return
	}
	for _, rr := range l.rrs {
		switch rr.Type {
		case "RRSIG", "NSEC", "NSEC3", "SOA":
			continue
		}
		idx.positive[name+"/"+rr.Type] = content
	}
}

// answer returns fixture content for name/qtype: a positive fixture for
// that exact type, else a captured negative answer for the name, else a
// generic validated NXRRSET.
func (idx *fixtureIndex) answer(t *testing.T, name, qtype string) string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if c, ok := idx.positive[name+"/"+qtype]; ok {
		return c
	}
	if c, ok := idx.negative[name]; ok {
		return c
	}
	return fixture(t, "delv/jschmidt_aaaa_nxrrset.yaml")
}

// fixtureFallback makes a fakeRunner answer every delv call from the index
// and every nameserver-audit / glue dig from a healthy authoritative
// capture, so scenario tests only register what they want to vary.
func fixtureFallback(t *testing.T) func(tool string, args []string) (fakeCall, bool) {
	idx := loadFixtureIndex(t)
	return func(tool string, args []string) (fakeCall, bool) {
		switch tool {
		case "delv":
			name, qtype := args[len(args)-2], args[len(args)-1]
			return fakeCall{stdout: idx.answer(t, name, qtype)}, true
		case "dig":
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "+norecurse") && strings.HasSuffix(joined, " NS") {
				return fakeCall{stdout: fixture(t, "dig/jschmidt_at_org_referral.yaml")}, true
			}
			if strings.Contains(joined, "+norecurse") {
				return fakeCall{stdout: fixture(t, "dig/ns/jschmidt_at_ns-507.yaml")}, true
			}
		case "quicprobe":
			return fakeCall{stdout: fixture(t, "quicprobe/example_unsupported.json")}, true
		}
		return fakeCall{}, false
	}
}

// indexLookup is a lookupFn over every captured delv fixture.
func indexLookup(t *testing.T) lookupFn {
	t.Helper()
	idx := loadFixtureIndex(t)
	return func(name, qtype string) Lookup {
		l := parseDelvYAML(idx.answer(t, name, qtype), qtype)
		l.Name = strings.ToLower(strings.TrimSuffix(name, "."))
		return l
	}
}

// googleAddrs returns the apex IPv4 and IPv6 address from the fixtures.
func googleAddrs(t *testing.T) (netip.Addr, netip.Addr) {
	t.Helper()
	v4 := parseDelvYAML(fixture(t, "delv/google_a_unsigned.yaml"), "A").Addrs()[0]
	v6 := parseDelvYAML(fixture(t, "delv/google_aaaa_unsigned.yaml"), "AAAA").Addrs()[0]
	return v4, v6
}
