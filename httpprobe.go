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
	Error    string `json:"error,omitempty"`
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
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return HTTPResult{Error: "read: " + scrubProbeError(err.Error())}
	}
	defer resp.Body.Close()
	res := HTTPResult{Status: resp.StatusCode, Location: resp.Header.Get("Location"), Server: resp.Header.Get("Server")}
	if h := resp.Header.Get("Strict-Transport-Security"); h != "" {
		res.HSTS = parseHSTS(h)
	}
	return res
}

// parseHSTS parses "max-age=N; includeSubDomains; preload" case-insensitively.
func parseHSTS(header string) *HSTS {
	h := &HSTS{}
	for _, part := range strings.Split(header, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		switch strings.ToLower(kv[0]) {
		case "max-age":
			if len(kv) == 2 {
				h.MaxAge, _ = strconv.ParseInt(strings.Trim(kv[1], `"`), 10, 64)
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
		if seen[current] {
			chain.Loop, chain.Ended = true, RedirectLoop
			return chain
		}
		seen[current] = true
		u, err := url.Parse(current)
		if err != nil {
			chain.Error, chain.Ended = "bad URL "+current, RedirectFailed
			return chain
		}
		ip, ok := hosts[strings.ToLower(u.Hostname())]
		if !ok {
			chain.External, chain.Ended = current, RedirectExternal
			return chain
		}
		res := fetchHead(ctx, d, u, ip, timeout)
		if res.Error != "" {
			chain.Error, chain.Ended = current+": "+res.Error, RedirectFailed
			return chain
		}
		chain.Hops = append(chain.Hops, RedirectHop{URL: current, Status: res.Status})
		if !isRedirect(res.Status) || res.Location == "" {
			chain.FinalURL, chain.Ended = current, RedirectFinal
			return chain
		}
		next, err := u.Parse(res.Location)
		if err != nil {
			chain.Error, chain.Ended = "bad Location "+res.Location, RedirectFailed
			return chain
		}
		current = next.String()
	}
	chain.Error, chain.Ended = fmt.Sprintf("more than %d redirects", maxRedirectHops), RedirectHopLimit
	return chain
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
		if n, err := strconv.Atoi(p); err == nil {
			port = uint16(n)
		}
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.DialContext(dctx, tcpNetwork(ip), netip.AddrPortFrom(ip, port).String())
	if err != nil {
		return HTTPResult{Error: "connect: " + classifyDialErrorText(err)}
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
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
