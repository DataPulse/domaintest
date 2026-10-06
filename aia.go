package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// aiaTimeout bounds one issuer fetch; the run's context bounds it too.
const aiaTimeout = 3 * time.Second

// maxAIABytes caps an issuer certificate download. Real ones are 1-2 KB.
const maxAIABytes = 64 << 10

// aiaDialer connects issuer fetches; tests point it at local servers.
var aiaDialer dialer = &netDialer{}

// aiaResolve resolves an issuer URL's host; tests replace it.
var aiaResolve = net.DefaultResolver.LookupNetIP

// The URL an AIA fetch goes to is written by whoever issued the leaf, and
// any server can present a leaf it made itself. So the fetch is held to
// the rules of every other probe: plain HTTP to a public address only,
// no redirects (a redirect could point anywhere), a size cap, and the
// run's deadline. An issuer URL is fetched once per run however many
// addresses served a leaf naming it.
var aiaCache = struct {
	mu   sync.Mutex
	done map[string]*aiaEntry
}{done: map[string]*aiaEntry{}}

type aiaEntry struct {
	once sync.Once
	cert *x509.Certificate
	err  error
}

// fetchAIACached fetches each issuer URL once, sharing the result.
func fetchAIACached(ctx context.Context, rawURL string) (*x509.Certificate, error) {
	aiaCache.mu.Lock()
	e := aiaCache.done[rawURL]
	if e == nil {
		e = &aiaEntry{}
		aiaCache.done[rawURL] = e
	}
	aiaCache.mu.Unlock()
	e.once.Do(func() { e.cert, e.err = fetchAIA(ctx, rawURL) })
	return e.cert, e.err
}

// fetchAIA downloads a certificate (DER or PEM) from an issuer URL.
func fetchAIA(ctx context.Context, rawURL string) (*x509.Certificate, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" || u.Hostname() == "" {
		return nil, fmt.Errorf("issuer URL %q is not plain http", rawURL)
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialPublic(ctx, u)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issuer URL answered HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAIABytes))
	if err != nil {
		return nil, err
	}
	return parseCertificate(body)
}

// dialPublic resolves the URL's host and connects to its first public
// address that answers. A reserved address is never contacted.
func dialPublic(ctx context.Context, u *url.URL) (net.Conn, error) {
	port := uint16(80)
	if p := u.Port(); p != "" {
		n, err := parsePort(p)
		if err != nil {
			return nil, err
		}
		port = n
	}
	addrs, err := aiaResolve(ctx, "ip", u.Hostname())
	if err != nil {
		return nil, err
	}
	public, reserved := splitReserved(addrs)
	if len(public) == 0 {
		if len(reserved) > 0 {
			return nil, errors.New("issuer host has only reserved addresses (" + strings.Join(reserved, ", ") + ")")
		}
		return nil, errors.New("issuer host has no address")
	}
	return dialFirst(ctx, aiaDialer, public, port)
}
