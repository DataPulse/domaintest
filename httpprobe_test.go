package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestHTTPRequest(t *testing.T) {
	srv := plainServer(t, okHandler(map[string]string{"Server": "unit/1", "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"}))
	res := httpRequest(dialServer(t, srv), "example.test", "/", time.Now().Add(2*time.Second))
	check(t, "status", res.Status, 200)
	check(t, "server", res.Server, "unit/1")
	check(t, "hsts", res.HSTS, &HSTS{MaxAge: 31536000, IncludeSubdomains: true, Preload: true})
	check(t, "no error", res.Error, "")

	redir := plainServer(t, redirectHandler(301, "https://www.example.test/"))
	res = httpRequest(dialServer(t, redir), "example.test", "/", time.Now().Add(2*time.Second))
	check(t, "redirect status", res.Status, 301)
	check(t, "location", res.Location, "https://www.example.test/")
	check(t, "no hsts", res.HSTS, (*HSTS)(nil))
}

func TestHTTPRequest_ErrorsAndDeadline(t *testing.T) {
	slow := plainServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	start := time.Now()
	res := httpRequest(dialServer(t, slow), "example.test", "/", time.Now().Add(300*time.Millisecond))
	check(t, "deadline error", strings.HasPrefix(res.Error, "read:"), true)
	check(t, "returned quickly", time.Since(start) < 1500*time.Millisecond, true)

	// Server that hangs up without a response.
	closer := plainServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		c, _, _ := hj.Hijack()
		_ = c.Close()
	}))
	res = httpRequest(dialServer(t, closer), "example.test", "/", time.Now().Add(2*time.Second))
	check(t, "EOF surfaces", res.Error != "", true)
}

func TestParseHSTS(t *testing.T) {
	check(t, "full", parseHSTS("max-age=63072000; includeSubDomains; preload"), &HSTS{63072000, true, true})
	check(t, "case and quotes", parseHSTS(`Max-Age="300"; IncludeSubdomains`), &HSTS{300, true, false})
	check(t, "bare", parseHSTS("max-age=0"), &HSTS{0, false, false})
	check(t, "garbage", parseHSTS("nonsense"), &HSTS{})
}

func TestFollowRedirects(t *testing.T) {
	ca := newTestCA(t, "root")
	withRoots(t, ca.pool)
	leaf, key := ca.issue(t, certSpec{sans: []string{"example.test", "www.example.test"}, issuer: ca})
	apexIP, wwwIP := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	hosts := hostAddrs{"example.test": apexIP, "www.example.test": wwwIP}

	// http://example.test -> https://example.test -> https://www.example.test (200)
	http80 := plainServer(t, redirectHandler(301, "https://example.test/"))
	https443 := tlsServer(t, redirectHandler(301, "https://www.example.test/"), []*x509.Certificate{leaf, ca.cert}, key, tls.VersionTLS12, tls.VersionTLS13)
	wwwHTTPS := tlsServer(t, okHandler(nil), []*x509.Certificate{leaf, ca.cert}, key, tls.VersionTLS12, tls.VersionTLS13)
	d := newMappedDialer()
	d.mapTarget(apexIP.String(), 80, http80)
	d.mapTarget(apexIP.String(), 443, https443)
	d.mapTarget(wwwIP.String(), 443, wwwHTTPS)

	chain := followRedirects(context.Background(), d, "http", "example.test", hosts, 2*time.Second)
	check(t, "hops", chain.Hops, []RedirectHop{{"http://example.test/", 301}, {"https://example.test/", 301}, {"https://www.example.test/", 200}})
	check(t, "final", chain.FinalURL, "https://www.example.test/")
	check(t, "no loop", chain.Loop, false)
	check(t, "no error", chain.Error, "")

	// Loop: apex -> www -> apex.
	loopA := tlsServer(t, redirectHandler(302, "https://www.example.test/"), []*x509.Certificate{leaf, ca.cert}, key, tls.VersionTLS12, tls.VersionTLS13)
	loopW := tlsServer(t, redirectHandler(302, "https://example.test/"), []*x509.Certificate{leaf, ca.cert}, key, tls.VersionTLS12, tls.VersionTLS13)
	d.mapTarget(apexIP.String(), 443, loopA)
	d.mapTarget(wwwIP.String(), 443, loopW)
	chain = followRedirects(context.Background(), d, "https", "example.test", hosts, 2*time.Second)
	check(t, "loop detected", chain.Loop, true)
	check(t, "loop hops", len(chain.Hops), 2)

	// External target is recorded, not followed.
	ext := plainServer(t, redirectHandler(301, "https://cdn.example.net/x"))
	d.mapTarget(apexIP.String(), 80, ext)
	chain = followRedirects(context.Background(), d, "http", "example.test", hosts, 2*time.Second)
	check(t, "external", chain.External, "https://cdn.example.net/x")
	check(t, "one hop", len(chain.Hops), 1)

	// Relative Location and a chain that is too long.
	long := plainServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/next"+r.URL.Path)
		w.WriteHeader(302)
	}))
	d.mapTarget(apexIP.String(), 80, long)
	chain = followRedirects(context.Background(), d, "http", "example.test", hosts, 2*time.Second)
	check(t, "too many", strings.HasPrefix(chain.Error, "more than"), true)
	check(t, "max hops recorded", len(chain.Hops), maxRedirectHops+1)

	// Broken hop (connection refused) is an error, not a loop.
	chain = followRedirects(context.Background(), d, "https", "www.example.test", hostAddrs{"www.example.test": netip.MustParseAddr("192.0.2.99")}, time.Second)
	check(t, "connect error names the URL", strings.HasPrefix(chain.Error, "https://www.example.test/: connect:"), true)
	check(t, "no hop recorded for a failed connect", len(chain.Hops), 0)
}

func TestIsRedirect(t *testing.T) {
	for _, s := range []int{301, 302, 303, 307, 308} {
		check(t, "redirect", isRedirect(s), true)
	}
	for _, s := range []int{200, 304, 400, 500} {
		check(t, "not redirect", isRedirect(s), false)
	}
}

// A chain that leaves the zone is finished, not truncated. Both cases end
// with no final_url, so without a reason a caller cannot tell a domain that
// correctly hands off to an external host from one whose chain broke.
func TestRedirectChain_EndedReason(t *testing.T) {
	hosts := hostAddrs{}
	// No known host at all: the very first URL is external.
	c := followRedirects(context.Background(), newMappedDialer(), "http", "example.com", hosts, time.Second)
	check(t, "external is a finished chain", c.Ended, RedirectExternal)
	check(t, "and names where it went", c.External, "http://example.com/")
	check(t, "with no final url", c.FinalURL, "")
	check(t, "and is not an error", c.Error, "")
}
