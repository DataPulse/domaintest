package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Preload-list statuses as reported by the tool. The Chromium list records
// enforcement, not submission, so hstspreload.org's "pending" and
// "rejected" have no equivalent: such domains read absent, which is what
// browsers do.
const (
	PreloadPreloaded = "preloaded"
	PreloadAbsent    = "absent"  // the list was consulted and nothing covers the name
	PreloadUnknown   = "unknown" // the list could not be obtained; see hsts_preload_error
)

// preloadListURL is Chromium's HSTS preload list. ?format=TEXT returns the
// file base64-encoded; Go's transport asks for gzip and decodes it, so the
// transfer is about 1.1 MB for a 14 MB file.
var preloadListURL = "https://chromium.googlesource.com/chromium/src/+/main/net/http/transport_security_state_static.json?format=TEXT"

// cacheHeaderPrefix identifies the derived cache and its format. A file
// that does not start with this exact prefix is refetched rather than
// guessed at.
const cacheHeaderPrefix = "#domaintest-hsts-preload v1"

// warmTimeout bounds `-warm-hsts-cache`, which runs at container start and
// has no probe budget to share.
const warmTimeout = 60 * time.Second

// noCachePath disables the cache: fetch on every run.
const noCachePath = "-"

// preloadList maps a preloaded name to its include_subdomains flag.
type preloadList struct {
	entries map[string]bool
}

// status reports whether the name is HSTS-preloaded and, when it is
// covered by an ancestor rather than itself, which ancestor. Whole TLDs
// (app, bank, dev, page) are entries with include_subdomains, so names
// under them are preloaded.
func (l *preloadList) status(domain string) (status, coveredBy string) {
	if l == nil || len(l.entries) == 0 {
		return PreloadUnknown, ""
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if _, ok := l.entries[name]; ok {
		return PreloadPreloaded, ""
	}
	for rest := name; ; {
		i := strings.IndexByte(rest, '.')
		if i < 0 {
			return PreloadAbsent, ""
		}
		rest = rest[i+1:]
		if includeSubdomains, ok := l.entries[rest]; ok && includeSubdomains {
			return PreloadPreloaded, rest
		}
	}
}

// preloadListFetcher retrieves the list from the network; replaceable in
// tests so no unit test touches chromium.googlesource.com.
var preloadListFetcher = fetchPreloadList

// fetchPreloadList downloads and derives the list. A zero timeout means the
// caller's context is the only bound, which is what the probe phase wants:
// the download is far larger than one TCP connect and must not be held to
// the connect budget.
func fetchPreloadList(ctx context.Context, timeout time.Duration) (*preloadList, error) {
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	var err error
	for attempt := 0; attempt < fetchAttempts; attempt++ {
		if attempt > 0 && !sleepCtx(ctx, fetchBackoff*time.Duration(attempt)) {
			break
		}
		var l *preloadList
		l, err = fetchOnce(ctx, client)
		if err == nil {
			return l, nil
		}
		if !retryableFetch(err) {
			return nil, err
		}
	}
	return nil, err
}

// fetchAttempts and fetchBackoff bound the retry: googlesource answers 503
// under bursts, and one quick retry turns that into a populated cache
// rather than a run without a preload answer.
const fetchAttempts = 3

var fetchBackoff = 500 * time.Millisecond

// errRetryableFetch marks a server-side failure worth retrying.
var errRetryableFetch = errors.New("retryable")

func retryableFetch(err error) bool {
	return errors.Is(err, errRetryableFetch) || errors.Is(err, syscall.ECONNRESET)
}

// sleepCtx waits for d, reporting false when the context ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func fetchOnce(ctx context.Context, client *http.Client) (*preloadList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, preloadListURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("HTTP %d from chromium.googlesource.com: %w", resp.StatusCode, errRetryableFetch)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from chromium.googlesource.com", resp.StatusCode)
	}
	body, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, resp.Body))
	if err != nil {
		return nil, fmt.Errorf("decoding the preload list: %w", err)
	}
	return parsePreloadJSON(body)
}

// preloadEntry is one record of transport_security_state_static.json.
type preloadEntry struct {
	Name              string `json:"name"`
	Mode              string `json:"mode"`
	IncludeSubdomains bool   `json:"include_subdomains"`
}

// parsePreloadJSON derives the lookup table from Chromium's JSON, which
// carries // line comments that encoding/json will not accept. Only
// force-https entries impose HSTS.
func parsePreloadJSON(body []byte) (*preloadList, error) {
	var doc struct {
		Entries []preloadEntry `json:"entries"`
	}
	if err := json.Unmarshal(stripLineComments(body), &doc); err != nil {
		return nil, fmt.Errorf("parsing the preload list: %w", err)
	}
	l := &preloadList{entries: make(map[string]bool, len(doc.Entries))}
	for _, e := range doc.Entries {
		if e.Mode != "force-https" || e.Name == "" {
			continue
		}
		l.entries[strings.ToLower(e.Name)] = e.IncludeSubdomains
	}
	if len(l.entries) == 0 {
		return nil, errors.New("the preload list contained no force-https entries")
	}
	return l, nil
}

// stripLineComments removes whole-line // comments, the only comment form
// Chromium's file uses.
func stripLineComments(body []byte) []byte {
	lines := strings.Split(string(body), "\n")
	kept := lines[:0]
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		kept = append(kept, line)
	}
	return []byte(strings.Join(kept, "\n"))
}

// ------------------------------------------------------------------ cache

// defaultPreloadCachePath is <user cache dir>/domaintest/hsts-preload.tsv,
// i.e. $XDG_CACHE_HOME or $HOME/.cache. An empty result disables caching.
func defaultPreloadCachePath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "domaintest", "hsts-preload.tsv")
}

// marshalCache renders the list: a version header then "name\t0|1" lines,
// sorted so the file is reproducible.
func marshalCache(l *preloadList, now time.Time) []byte {
	names := make([]string, 0, len(l.entries))
	for name := range l.entries {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	b.Grow(len(names) * 24)
	fmt.Fprintf(&b, "%s %s\n", cacheHeaderPrefix, now.UTC().Format(time.RFC3339))
	for _, name := range names {
		b.WriteString(name)
		if l.entries[name] {
			b.WriteString("\t1\n")
		} else {
			b.WriteString("\t0\n")
		}
	}
	return []byte(b.String())
}

// unmarshalCache parses a cache file. Any damage (wrong header, truncation,
// no entries) is reported as an error so the caller refetches; a corrupt
// cache never fails a run.
func unmarshalCache(body []byte) (*preloadList, error) {
	text := string(body)
	nl := strings.IndexByte(text, '\n')
	if nl < 0 || !strings.HasPrefix(text, cacheHeaderPrefix) {
		return nil, errors.New("not a domaintest preload cache of this version")
	}
	l := &preloadList{entries: map[string]bool{}}
	for _, line := range strings.Split(text[nl+1:], "\n") {
		if line == "" {
			continue
		}
		name, flag, ok := strings.Cut(line, "\t")
		if !ok || name == "" {
			return nil, fmt.Errorf("malformed cache line %q", line)
		}
		includeSubdomains, err := strconv.ParseBool(flag)
		if err != nil {
			return nil, fmt.Errorf("malformed cache line %q", line)
		}
		l.entries[name] = includeSubdomains
	}
	if len(l.entries) == 0 {
		return nil, errors.New("the preload cache holds no entries")
	}
	return l, nil
}

// readPreloadCache loads a usable cache, or an error saying why not.
func readPreloadCache(path string) (*preloadList, error) {
	if path == "" || path == noCachePath {
		return nil, errors.New("caching disabled")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return unmarshalCache(body)
}

// writePreloadCache writes the cache atomically: a temporary file in the
// same directory, fsynced, then renamed, so a reader never sees a partial
// file.
func writePreloadCache(path string, l *preloadList) error {
	if path == "" || path == noCachePath {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(marshalCache(l, time.Now())); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// ------------------------------------------------------------------- lock

// systemLockDir is the house location for lock files. It is never created:
// on a host it always exists, and where it does not (a container) the lock
// goes beside the cache instead.
var systemLockDir = "/run/lock"

// lockPath is /run/lock/domaintest-hsts.lock when that directory is usable,
// else <cache>.lock.
func lockPath(cachePath string) string {
	if info, err := os.Stat(systemLockDir); err == nil && info.IsDir() {
		p := filepath.Join(systemLockDir, "domaintest-hsts.lock")
		if f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o666); err == nil {
			f.Close()
			return p
		}
	}
	return cachePath + ".lock"
}

// lockPoll is how often a contended lock is retried.
var lockPoll = 50 * time.Millisecond

// acquireLock takes an exclusive flock, retrying without blocking so that
// the wait honours ctx: a stuck holder can never outlast the caller's
// budget. The returned function releases it.
func acquireLock(ctx context.Context, path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o666)
	if err != nil {
		return nil, err
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(lockPoll):
		}
	}
}

// ------------------------------------------------------------- population

// loadPreloadList returns the list for this run: the cache when it holds
// one, otherwise a single fetch serialised across processes by an flock.
// The second cache read matters: while this process waited for the lock,
// another may have populated it.
func loadPreloadList(ctx context.Context, cachePath string, timeout time.Duration) (*preloadList, error) {
	if l, err := readPreloadCache(cachePath); err == nil {
		return l, nil
	}
	if cachePath == "" || cachePath == noCachePath {
		return preloadListFetcher(ctx, timeout)
	}
	release, err := acquireLock(ctx, lockPath(cachePath))
	if err != nil {
		return nil, fmt.Errorf("waiting for the preload cache lock: %w", err)
	}
	defer release()
	if l, err := readPreloadCache(cachePath); err == nil {
		return l, nil
	}
	l, err := preloadListFetcher(ctx, timeout)
	if err != nil {
		return nil, err
	}
	// A cache that cannot be written is not fatal: this run still answers
	// from the list it just fetched and the next run retries.
	_ = writePreloadCache(cachePath, l)
	return l, nil
}

// warmPreloadCache populates the cache and reports where it put things, for
// `-warm-hsts-cache` at container start.
func warmPreloadCache(ctx context.Context, cachePath string) (string, error) {
	if cachePath == "" || cachePath == noCachePath {
		return "", errors.New("no cache path: nothing to warm")
	}
	wctx, cancel := context.WithTimeout(ctx, warmTimeout)
	defer cancel()
	lock := lockPath(cachePath)
	release, err := acquireLock(wctx, lock)
	if err != nil {
		return "", fmt.Errorf("waiting for the preload cache lock %s: %w", lock, err)
	}
	defer release()
	if _, err := readPreloadCache(cachePath); err == nil {
		return fmt.Sprintf("preload cache already present at %s (lock %s)", cachePath, lock), nil
	}
	l, err := preloadListFetcher(wctx, warmTimeout)
	if err != nil {
		return "", err
	}
	if err := writePreloadCache(cachePath, l); err != nil {
		return "", fmt.Errorf("writing %s: %w", cachePath, err)
	}
	return fmt.Sprintf("preload cache written to %s (%d entries, lock %s)", cachePath, len(l.entries), lock), nil
}
