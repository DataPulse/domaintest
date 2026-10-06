package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
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
	check(t, "hops", chain.Hops, []RedirectHop{
		{URL: "http://example.test/", Status: 301, Location: "https://example.test/"},
		{URL: "https://example.test/", Status: 301, Location: "https://www.example.test/"},
		{URL: "https://www.example.test/", Status: 200},
	})
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
	check(t, "where the loop closed", chain.Hops[1].Location, "https://example.test/")

	// The ip-house.com shape (2026-10-05, CloudFront): port 80 upgrades to
	// https, and https redirects to itself. Only the Location shows that
	// the second hop pointed at its own URL rather than back a step.
	self := tlsServer(t, redirectHandler(301, "https://example.test/"), []*x509.Certificate{leaf, ca.cert}, key, tls.VersionTLS12, tls.VersionTLS13)
	d.mapTarget(apexIP.String(), 80, http80)
	d.mapTarget(apexIP.String(), 443, self)
	chain = followRedirects(context.Background(), d, "http", "example.test", hosts, 2*time.Second)
	check(t, "self loop", chain.Loop, true)
	f := &findings{}
	f.redirectFindings("apex", map[string]*RedirectChain{familyIPv4: &chain})
	check(t, "loop message names the target", f.errors, []string{"apex (ipv4): redirect loop http://example.test/ (301) -> https://example.test/ (301) -> https://example.test/"})

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
	check(t, "relative Location kept as sent", chain.Hops[0].Location, "/next/")

	// A hostile Location does not bloat the report or get followed: the
	// chain ends broken, and the recorded value is clipped and says so.
	huge := "https://example.test/" + strings.Repeat("a", maxLocationBytes)
	hostile := plainServer(t, redirectHandler(301, huge))
	d.mapTarget(apexIP.String(), 80, hostile)
	chain = followRedirects(context.Background(), d, "http", "example.test", hosts, 2*time.Second)
	check(t, "not followed", len(chain.Hops), 1)
	check(t, "ended broken", chain.Ended, RedirectFailed)
	check(t, "says why", chain.Error, fmt.Sprintf("Location header is %d bytes, over the %d-byte limit", len(huge), maxLocationBytes))
	check(t, "recorded clipped", strings.HasSuffix(chain.Hops[0].Location, fmt.Sprintf("... (clipped, %d bytes)", len(huge))), true)
	check(t, "bounded", len(chain.Hops[0].Location) < maxLocationBytes+64, true)
	check(t, "at the limit is kept whole", clipLocation(huge[:maxLocationBytes]), huge[:maxLocationBytes])

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

// A 103 Early Hints (or 100 Continue) is not the answer: the response
// after it is.
func TestHTTPRequest_SkipsInterimResponses(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	go func() {
		defer c2.Close()
		buf := make([]byte, 4096)
		_, _ = c2.Read(buf)
		_, _ = io.WriteString(c2, "HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\nStrict-Transport-Security: max-age=1\r\n\r\n"+
			"HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com/\r\nContent-Length: 0\r\n\r\n")
	}()
	res := httpRequest(c1, "example.com", "/", time.Now().Add(2*time.Second))
	check(t, "final status", res.Status, 301)
	check(t, "final location", res.Location, "https://example.com/")
	check(t, "hints' headers are not the response's", res.HSTS == nil, true)
}

func TestParseHSTS_WhitespaceAroundEquals(t *testing.T) {
	check(t, "spaced", parseHSTS(`max-age = 31536000 ; includeSubDomains`), &HSTS{MaxAge: 31536000, IncludeSubdomains: true})
	check(t, "quoted and spaced", parseHSTS(`max-age= "600"`), &HSTS{MaxAge: 600})
}
