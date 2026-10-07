package main

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// timedDialer records when the first connection was attempted.
type timedDialer struct {
	inner dialer
	mu    sync.Mutex
	first time.Time
}

func (d *timedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	if d.first.IsZero() {
		d.first = time.Now()
	}
	d.mu.Unlock()
	return d.inner.DialContext(ctx, network, address)
}

// The web probes need only the first wave's addresses. A second-wave lookup
// that is slow (here a DKIM selector, held for 1.5 s) must not hold them
// back: the first dial happens while that lookup is still running.
func TestRun_WebProbesStartAfterFirstWave(t *testing.T) {
	g := googleScenario(t)
	s := g.s
	const hold = 1500 * time.Millisecond
	slow := dogCall(t, "dog/google_ds_nxrrset.json")
	slow.delay = hold
	s.r.on("dog", s.dogArgs("default._domainkey.google.com", "TXT"), slow)
	d := &timedDialer{inner: s.dialer}
	start := time.Now()
	rep := run(context.Background(), s.cfg, s.r, d)
	if d.first.IsZero() {
		t.Fatal("no address was probed")
	}
	if waited := d.first.Sub(start); waited >= hold {
		t.Errorf("first dial %v after start: the probes waited for the second DNS wave", waited)
	}
	check(t, "apex probed", rep.Web.Apex != nil && len(rep.Web.Apex.IPv4) > 0, true)
	check(t, "www probed", rep.Web.WWW != nil, true)
}

// stop and wait are safe on probes that never started and after each other.
func TestEarlyWeb_Lifecycle(t *testing.T) {
	var idle earlyWeb
	idle.stop()
	check(t, "never started", idle.wait(), WebSection{})

	g := googleScenario(t)
	var w earlyWeb
	dns := dnsResults{apex: map[string]Lookup{}, www: map[string]Lookup{}}
	w.start(context.Background(), g.s.cfg, g.s.r, g.s.dialer, dns, &Report{})
	check(t, "no addresses, empty section", w.wait(), WebSection{})
	w.stop()
}

// A reserved name's addresses are the resolver's local answers: the early
// start must not probe them either.
func TestRun_EarlyWebSkipsReservedName(t *testing.T) {
	s := newScenario(t, "localhost", "")
	for _, tt := range []string{"A", "AAAA", "MX", "NS", "TXT"} {
		s.dns("localhost", tt, "dog/reserved/localhost_"+strings.ToLower(tt)+".json", t)
	}
	s.reach(familyIPv4, "dog/root_ns_v4.json", t)
	rep := s.run()
	check(t, "not probed", rep.Web, WebSection{})
	check(t, "nothing dialed", len(s.dialer.seen), 0)
}

// Against a resolver that does not validate, the classification clears
// every trust in the apex and www maps after the early probes started; the
// probes work on their own copy of those maps, and still probe the site.
func TestRun_EarlyWebAndDropTrust(t *testing.T) {
	g := googleScenario(t)
	g.s.reach(familyIPv4, "dog/root_ns_no_ad_authoritative.json", t)
	rep := g.s.run()
	no := false
	check(t, "resolver_validates", rep.DNS.ResolverValidates, &no)
	check(t, "apex probed", rep.Web.Apex != nil && len(rep.Web.Apex.IPv4) > 0, true)
}
