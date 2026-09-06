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
		return HTTPResult{Error: "write: " + err.Error()}
	}
	br := bufio.NewReaderSize(io.LimitReader(conn, maxHeaderBytes), 4096)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return HTTPResult{Error: "read: " + err.Error()}
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

// RedirectChain records where a name's HTTP entry point leads.
type RedirectChain struct {
	Hops     []RedirectHop `json:"hops"`
	FinalURL string        `json:"final_url,omitempty"`
	External string        `json:"external,omitempty"` // first target outside apex/www, not followed
	Loop     bool          `json:"loop,omitempty"`
	Error    string        `json:"error,omitempty"`
}

// maxRedirectHops bounds the chain follower.
const maxRedirectHops = 3

// hostAddrs maps a hostname (apex or www) to the address to connect to for
// one family; the follower only connects to hosts present here.
type hostAddrs map[string]netip.Addr

// followRedirects starts at scheme://host/ on the given address and follows
// Location headers while they stay within the known hosts.
func followRedirects(ctx context.Context, d dialer, scheme, host string, hosts hostAddrs, timeout time.Duration) RedirectChain {
	chain := RedirectChain{}
	current := scheme + "://" + host + "/"
	seen := map[string]bool{}
	for hop := 0; hop <= maxRedirectHops; hop++ {
		if seen[current] {
			chain.Loop = true
			return chain
		}
		seen[current] = true
		u, err := url.Parse(current)
		if err != nil {
			chain.Error = "bad URL " + current
			return chain
		}
		ip, ok := hosts[strings.ToLower(u.Hostname())]
		if !ok {
			chain.External = current
			return chain
		}
		res := fetchHead(ctx, d, u, ip, timeout)
		if res.Error != "" {
			chain.Error = current + ": " + res.Error
			return chain
		}
		chain.Hops = append(chain.Hops, RedirectHop{URL: current, Status: res.Status})
		if !isRedirect(res.Status) || res.Location == "" {
			chain.FinalURL = current
			return chain
		}
		next, err := u.Parse(res.Location)
		if err != nil {
			chain.Error = "bad Location " + res.Location
			return chain
		}
		current = next.String()
	}
	chain.Error = fmt.Sprintf("more than %d redirects", maxRedirectHops)
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
			return HTTPResult{Error: "tls: " + err.Error()}
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
	return string(classifyDialError(err)) + ": " + err.Error()
}
