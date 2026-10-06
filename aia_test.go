package main

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

// stubAIANetwork resolves every issuer host to addr and maps addr:80 to
// srv, for the test's duration.
func stubAIANetwork(t *testing.T, addr string, srv http.Handler) *atomic.Int32 {
	t.Helper()
	var hits atomic.Int32
	server := plainServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		srv.ServeHTTP(w, r)
	}))
	d := newMappedDialer()
	d.mapTarget(addr, 80, server)
	oldD, oldR := aiaDialer, aiaResolve
	aiaDialer = d
	aiaResolve = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr(addr)}, nil
	}
	t.Cleanup(func() { aiaDialer, aiaResolve = oldD, oldR })
	return &hits
}

func TestFetchAIA_FetchesOncePerURL(t *testing.T) {
	ca := newTestCA(t, "AIA Test CA")
	hits := stubAIANetwork(t, "1.1.1.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(ca.cert.Raw)
	}))
	for range 3 {
		c, err := fetchAIACached(context.Background(), "http://aia.once.example/ca.der")
		check(t, "fetched", err == nil && c != nil && c.Subject.CommonName == "AIA Test CA", true)
	}
	check(t, "one request", hits.Load(), int32(1))
}

// The issuer URL is chosen by whoever made the leaf. It must not be able
// to send the probe to an internal address, to another host by redirect,
// or anywhere but plain HTTP.
func TestFetchAIA_RefusesWhatOtherProbesRefuse(t *testing.T) {
	hits := stubAIANetwork(t, "1.1.1.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	_, err := fetchAIA(context.Background(), "http://aia.redirect.example/ca.der")
	check(t, "redirect not followed", err != nil && strings.Contains(err.Error(), "HTTP 302"), true)
	check(t, "one request only", hits.Load(), int32(1))

	_, err = fetchAIA(context.Background(), "https://aia.tls.example/ca.der")
	check(t, "https refused", err != nil && strings.Contains(err.Error(), "not plain http"), true)
	_, err = fetchAIA(context.Background(), "http://aia.port.example:70000/ca.der")
	check(t, "bad port refused", err != nil && strings.Contains(err.Error(), "invalid port"), true)

	aiaResolve = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("10.0.0.1")}, nil
	}
	_, err = fetchAIA(context.Background(), "http://aia.internal.example/ca.der")
	check(t, "reserved refused", err != nil && strings.Contains(err.Error(), "only reserved addresses"), true)
	check(t, "never contacted", hits.Load(), int32(1))
}

func TestParsePort(t *testing.T) {
	for p, ok := range map[string]bool{"80": true, "65535": true, "0": false, "65536": false, "70000": false, "x": false} {
		_, err := parsePort(p)
		check(t, p, err == nil, ok)
	}
}
