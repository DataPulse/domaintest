package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// maxHeaderBytes caps what is read from a server before giving up on the
// response head.
const maxHeaderBytes = 64 << 10

// HSTS is a parsed Strict-Transport-Security header.
type HSTS struct {
	MaxAge            int64 `json:"max_age"`
	IncludeSubdomains bool  `json:"include_subdomains"`
	Preload           bool  `json:"preload"`
}

// HTTPResult is the head of one HTTP response.
type HTTPResult struct {
	Status   int    `json:"status,omitempty"`
	Location string `json:"location,omitempty"`
	Server   string `json:"server,omitempty"`
	HSTS     *HSTS  `json:"hsts,omitempty"`
	// AltSvc is the Alt-Svc header as received, which is how a browser
	// learns an origin offers HTTP/3 (http_versions.h3_advertised).
	AltSvc string `json:"alt_svc,omitempty"`
	Error  string `json:"error,omitempty"`
}

// httpRequest sends GET path with Host host over an open connection (plain
// or TLS) and parses the response head. The body is not read.
func httpRequest(conn net.Conn, host, path string, deadline time.Time) HTTPResult {
	_ = conn.SetDeadline(deadline)
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: domaintest/1 (+https://github.com/DataPulse/domaintest)\r\nAccept: */*\r\nConnection: close\r\n\r\n", path, host)
	if _, err := io.WriteString(conn, req); err != nil {
		return HTTPResult{Error: "write: " + scrubProbeError(err.Error())}
	}
	br := bufio.NewReaderSize(io.LimitReader(conn, maxHeaderBytes), 4096)
	resp, err := readFinalResponse(br)
	if err != nil {
		return HTTPResult{Error: "read: " + scrubProbeError(err.Error())}
	}
	defer resp.Body.Close()
	res := HTTPResult{Status: resp.StatusCode, Location: resp.Header.Get("Location"), Server: resp.Header.Get("Server"), AltSvc: resp.Header.Get("Alt-Svc")}
	if h := resp.Header.Get("Strict-Transport-Security"); h != "" {
		res.HSTS = parseHSTS(h)
	}
	return res
}

// maxInterimResponses bounds how many 1xx responses are skipped before
// the final one; the header cap bounds their size.
const maxInterimResponses = 8

// readFinalResponse reads past interim 1xx responses (100 Continue, 103
// Early Hints) to the response the request actually got. Taking a 103 as
// the answer read a redirecting site as serving content, and took its
// HSTS from hints that are not the response's headers.
func readFinalResponse(br *bufio.Reader) (*http.Response, error) {
	for range maxInterimResponses {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= 200 || resp.StatusCode < 100 || resp.StatusCode == http.StatusSwitchingProtocols {
			return resp, nil
		}
		_ = resp.Body.Close()
	}
	return nil, fmt.Errorf("more than %d interim responses", maxInterimResponses)
}

// parseHSTS parses "max-age=N; includeSubDomains; preload" case-insensitively.
func parseHSTS(header string) *HSTS {
	h := &HSTS{}
	for _, part := range strings.Split(header, ";") {
		// RFC 6797 §6.1 allows whitespace around "=": "max-age = 31536000".
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		switch strings.ToLower(strings.TrimSpace(kv[0])) {
		case "max-age":
			if len(kv) == 2 {
				h.MaxAge, _ = strconv.ParseInt(strings.Trim(strings.TrimSpace(kv[1]), `"`), 10, 64)
			}
		case "includesubdomains":
			h.IncludeSubdomains = true
		case "preload":
			h.Preload = true
		}
	}
	return h
}

// RedirectHop is one step of a redirect chain.
type RedirectHop struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	// Location is the Location header as the server sent it, when it sent
	// one. A loop is diagnosed from it: without it, a hop that redirected
	// to itself and one that sent the chain back a step look the same.
	Location string `json:"location,omitempty"`
}

// Why a redirect chain stopped. A chain that leaves the zone is finished,
// not truncated: without saying so, a caller cannot tell a domain that
// correctly hands off to an external host from one whose chain broke,
// since both end with no final_url.
const (
	RedirectFinal    = "final"     // a terminal, non-redirect response
	RedirectExternal = "external"  // the next hop left the zone; deliberately not followed
	RedirectLoop     = "loop"      // the chain returned to a URL it had already visited
	RedirectHopLimit = "hop_limit" // more hops than the follower allows
	RedirectFailed   = "error"     // a hop could not be fetched
)

// RedirectChain records where a name's HTTP entry point leads.
type RedirectChain struct {
	Hops     []RedirectHop `json:"hops"`
	Ended    string        `json:"ended"` // why the chain stopped
	FinalURL string        `json:"final_url,omitempty"`
	External string        `json:"external,omitempty"` // first target outside apex/www, not followed
	Loop     bool          `json:"loop"`
	Error    string        `json:"error,omitempty"`
}

// maxRedirectHops bounds the chain follower. Ordinary sites chain four to
// six hops (scheme upgrade, apex to www, path normalisation, locale,
// session), so a limit of three failed mail.google.com and much of any
// real portfolio. Browsers allow 20 and curl defaults to 50; ten is
// generous for a health check while still bounding the work. The probe
// phase has its own budget, so a pathological chain runs out of time
// rather than requests.
const maxRedirectHops = 10

// maxLocationBytes bounds a Location the follower will act on or record.
// Every hop's URL and Location go into the report, so without a bound a
// hostile server could put 64 KB (the header cap) into each of up to 44
// hops across apex, www and both families. Real redirects, including SSO
// hand-offs with long query strings, fit in a few kilobytes. A longer one
// ends the chain as broken, recorded clipped.
const maxLocationBytes = 4096

// hostAddrs maps a hostname (apex or www) to the address to connect to for
// one family; the follower only connects to hosts present here.
type hostAddrs map[string]netip.Addr

// followRedirects starts at scheme://host/ on the given address and follows
// Location headers while they stay within the known hosts.
func followRedirects(ctx context.Context, d dialer, scheme, host string, hosts hostAddrs, timeout time.Duration) RedirectChain {
	chain := RedirectChain{Hops: []RedirectHop{}}
	current := scheme + "://" + host + "/"
	seen := map[string]bool{}
	for hop := 0; hop <= maxRedirectHops; hop++ {
		u, ip, ok := chain.admit(current, seen, hosts)
		if !ok {
			return chain
		}
		res := fetchHead(ctx, d, u, ip, timeout)
		if res.Error != "" {
			chain.Error, chain.Ended = current+": "+res.Error, RedirectFailed
			return chain
		}
		chain.Hops = append(chain.Hops, RedirectHop{URL: current, Status: res.Status, Location: clipLocation(res.Location)})
		if current, ok = chain.next(u, res); !ok {
			return chain
		}
	}
	chain.Error, chain.Ended = fmt.Sprintf("more than %d redirects", maxRedirectHops), RedirectHopLimit
	return chain
}

// admit decides whether the chain goes on to current, and where it
// connects if so. A URL already visited closes a loop: URLs are compared
// as requests, so http://Example.com:80/ and http://example.com/ are one
// visit. A target outside the known hosts ends the chain as external.
func (c *RedirectChain) admit(current string, seen map[string]bool, hosts hostAddrs) (*url.URL, netip.Addr, bool) {
	key, ok := urlKey(current)
	if !ok {
		key = current
	}
	if seen[key] {
		c.Loop, c.Ended = true, RedirectLoop
		return nil, netip.Addr{}, false
	}
	seen[key] = true
	u, err := url.Parse(current)
	switch {
	case err != nil:
		c.Error, c.Ended = "bad URL "+current, RedirectFailed
		return nil, netip.Addr{}, false
	case u.Scheme != "http" && u.Scheme != "https":
		c.Error, c.Ended = "redirect to a non-HTTP URL "+current, RedirectFailed
		return nil, netip.Addr{}, false
	}
	ip, ok := hosts[bareName(u.Hostname())]
	if !ok {
		c.External, c.Ended = current, RedirectExternal
		return nil, netip.Addr{}, false
	}
	return u, ip, true
}

// next is the URL a response sends the chain to, or false when the chain
// ends at it: a final answer, or a Location that cannot be followed.
func (c *RedirectChain) next(u *url.URL, res HTTPResult) (string, bool) {
	current := u.String()
	switch {
	case !isRedirect(res.Status) || res.Location == "":
		c.FinalURL, c.Ended = c.Hops[len(c.Hops)-1].URL, RedirectFinal
		return current, false
	case len(res.Location) > maxLocationBytes:
		c.Error, c.Ended = fmt.Sprintf("Location header is %d bytes, over the %d-byte limit", len(res.Location), maxLocationBytes), RedirectFailed
		return current, false
	}
	n, err := u.Parse(res.Location)
	if err != nil {
		c.Error, c.Ended = "bad Location "+res.Location, RedirectFailed
		return current, false
	}
	return n.String(), true
}

// clipLocation bounds a Location for the report, saying how long the
// original was so a clipped value is never mistaken for the real one.
func clipLocation(loc string) string {
	if len(loc) <= maxLocationBytes {
		return loc
	}
	return fmt.Sprintf("%s... (clipped, %d bytes)", strings.ToValidUTF8(loc[:maxLocationBytes], ""), len(loc))
}

func isRedirect(status int) bool {
	return status == 301 || status == 302 || status == 303 || status == 307 || status == 308
}

// fetchHead connects to ip for u (TLS when https) and returns the response
// head for u's path.
func fetchHead(ctx context.Context, d dialer, u *url.URL, ip netip.Addr, timeout time.Duration) HTTPResult {
	port := uint16(80)
	if u.Scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		n, err := parsePort(p)
		if err != nil {
			return HTTPResult{Error: err.Error()}
		}
		port = n
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.DialContext(dctx, tcpNetwork(ip), netip.AddrPortFrom(ip, port).String())
	if err != nil {
		return HTTPResult{Error: "connect: " + classifyDialErrorText(err)}
	}
	defer conn.Close()
	deadline := ioDeadline(ctx, timeout)
	if u.Scheme == "https" {
		_ = conn.SetDeadline(deadline)
		tc := tls.Client(conn, tlsConfig(u.Hostname(), 0, 0))
		if err := tc.Handshake(); err != nil {
			return HTTPResult{Error: "tls: " + scrubProbeError(err.Error())}
		}
		conn = tc
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	return httpRequest(conn, u.Host, path, deadline)
}

func classifyDialErrorText(err error) string {
	return string(classifyDialError(err)) + ": " + scrubProbeError(err.Error())
}

// parsePort reads a URL port: a decimal from 1 to 65535. A larger number
// would otherwise wrap silently in a uint16 and connect somewhere else.
func parsePort(p string) (uint16, error) {
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port %q", p)
	}
	return uint16(n), nil
}
