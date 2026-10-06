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
const cacheHeaderPrefix = "#domaintest-hsts-preload v2"

// warmTimeout bounds `-warm-hsts-cache`, which runs at container start and
// has no probe budget to share.
const warmTimeout = 60 * time.Second

// noCachePath disables the cache: fetch on every run.
const noCachePath = "-"

// preloadRecord is what the list says about one preloaded name.
type preloadRecord struct {
	includeSubdomains bool
	// policy is Chromium's reason the entry exists: "bulk-*" entries came
	// through hstspreload.org and must keep serving a compliant header;
	// "google", "custom", "public-suffix" and the rest are maintained by
	// hand and carry no such obligation.
	policy string
}

// preloadList maps a preloaded name to its record.
type preloadList struct {
	entries map[string]preloadRecord
	// fetched is when the list was downloaded: the cache header's time, or
	// now for a fresh fetch. Zero means unknown, which counts as stale.
	fetched time.Time
	// note says what went wrong around a list that was still obtained: a
	// cache that could not be written, or a refresh that failed so an
	// older cache answered.
	note string
}

// preloadCacheMaxAge is how long a cached list is used before it is
// fetched again. Chromium changes the list every few days; a name takes
// months to reach browsers once added, so a week's lag changes nothing
// that matters while bounding how stale a long-lived host's cache gets.
const preloadCacheMaxAge = 7 * 24 * time.Hour

// fresh reports whether the list is recent enough to use without
// refetching.
func (l *preloadList) fresh(now time.Time) bool {
	return !l.fetched.IsZero() && now.Sub(l.fetched) < preloadCacheMaxAge
}

// bulkPolicyPrefix marks the policies of entries submitted through
// hstspreload.org (bulk-legacy, bulk-18-weeks, bulk-1-year).
const bulkPolicyPrefix = "bulk-"

// headerRequired reports whether an entry under this policy is expected to
// keep serving a preload-grade header. An empty policy is an entry the list
// did not explain, which is held to the requirement rather than excused.
func headerRequired(policy string) bool {
	return policy == "" || strings.HasPrefix(policy, bulkPolicyPrefix)
}

// status reports whether the name is HSTS-preloaded, when it is covered by
// an ancestor rather than itself which ancestor, and the policy of the
// entry that covers it. Whole TLDs (app, bank, dev, page) are entries with
// include_subdomains, so names under them are preloaded.
func (l *preloadList) status(domain string) (status, coveredBy, policy string) {
	if l == nil || len(l.entries) == 0 {
		return PreloadUnknown, "", ""
	}
	name := bareName(domain)
	if name == "" {
		return PreloadUnknown, "", ""
	}
	if rec, ok := l.entries[name]; ok {
		return PreloadPreloaded, "", rec.policy
	}
	for rest := name; ; {
		i := strings.IndexByte(rest, '.')
		if i < 0 {
			return PreloadAbsent, "", ""
		}
		rest = rest[i+1:]
		if rec, ok := l.entries[rest]; ok && rec.includeSubdomains {
			return PreloadPreloaded, rest, rec.policy
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
	Policy            string `json:"policy"`
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
	l := &preloadList{entries: make(map[string]preloadRecord, len(doc.Entries)), fetched: time.Now()}
	for _, e := range doc.Entries {
		if e.Mode != "force-https" || e.Name == "" {
			continue
		}
		l.entries[strings.ToLower(e.Name)] = preloadRecord{includeSubdomains: e.IncludeSubdomains, policy: cachePolicy(e.Policy)}
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

// cachePolicy keeps a policy safe to store as one cache field. Chromium's
// policies are plain tokens; anything carrying the cache's own separators
// is dropped rather than allowed to corrupt the file.
func cachePolicy(policy string) string {
	if strings.ContainsAny(policy, "\t\r\n") {
		return ""
	}
	return policy
}

// marshalCache renders the list: a version header then "name\t0|1\tpolicy"
// lines, sorted so the file is reproducible.
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
		rec := l.entries[name]
		b.WriteString(name)
		if rec.includeSubdomains {
			b.WriteString("\t1\t")
		} else {
			b.WriteString("\t0\t")
		}
		b.WriteString(rec.policy)
		b.WriteByte('\n')
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
	l := &preloadList{entries: map[string]preloadRecord{}, fetched: cacheTime(text[:nl])}
	for _, line := range strings.Split(text[nl+1:], "\n") {
		if line == "" {
			continue
		}
		name, rec, err := parseCacheLine(line)
		if err != nil {
			return nil, err
		}
		l.entries[name] = rec
	}
	if len(l.entries) == 0 {
		return nil, errors.New("the preload cache holds no entries")
	}
	return l, nil
}

// cacheTime reads the fetch time from a cache header line, zero when it
// has none it can read.
func cacheTime(header string) time.Time {
	ts, err := time.Parse(time.RFC3339, strings.TrimSpace(strings.TrimPrefix(header, cacheHeaderPrefix)))
	if err != nil {
		return time.Time{}
	}
	return ts
}

// parseCacheLine reads one "name\t0|1\tpolicy" line. The policy field may
// be empty but must be present: a two-field line is a v1 leftover or
// damage, never something to guess at.
func parseCacheLine(line string) (string, preloadRecord, error) {
	fields := strings.Split(line, "\t")
	if len(fields) != 3 || fields[0] == "" {
		return "", preloadRecord{}, fmt.Errorf("malformed cache line %q", line)
	}
	includeSubdomains, err := strconv.ParseBool(fields[1])
	if err != nil {
		return "", preloadRecord{}, fmt.Errorf("malformed cache line %q", line)
	}
	return fields[0], preloadRecord{includeSubdomains: includeSubdomains, policy: fields[2]}, nil
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
		// Read-only is all flock needs, and it is what lets a run share a
		// lock file a root warm-up created 0644: opening it read-write
		// failed, and the run silently took a different lock.
		if f, err := os.OpenFile(p, os.O_CREATE|os.O_RDONLY, 0o666); err == nil {
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
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0o666)
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
// a fresh one, otherwise a single fetch serialised across processes by an
// flock. The second cache read matters: while this process waited for the
// lock, another may have refreshed it. When a refresh fails, a stale cache
// still answers, and says so in its note.
func loadPreloadList(ctx context.Context, cachePath string, timeout time.Duration) (*preloadList, error) {
	if cachePath == "" || cachePath == noCachePath {
		return preloadListFetcher(ctx, timeout)
	}
	if l := cachedList(cachePath); l != nil && l.fresh(time.Now()) {
		return l, nil
	}
	release, err := acquireLock(ctx, lockPath(cachePath))
	if err != nil {
		return nil, fmt.Errorf("waiting for the preload cache lock: %w", err)
	}
	defer release()
	return refreshPreloadList(ctx, cachePath, timeout)
}

// refreshPreloadList fetches and caches the list, under the lock.
func refreshPreloadList(ctx context.Context, cachePath string, timeout time.Duration) (*preloadList, error) {
	stale := cachedList(cachePath)
	if stale != nil && stale.fresh(time.Now()) {
		return stale, nil
	}
	l, err := preloadListFetcher(ctx, timeout)
	switch {
	case err != nil && stale != nil:
		stale.note = fmt.Sprintf("the preload list could not be refreshed, so a copy from %s answered: %v", stale.fetched.UTC().Format(time.RFC3339), err)
		return stale, nil
	case err != nil:
		return nil, err
	}
	if err := writePreloadCache(cachePath, l); err != nil {
		// This run still answers from the list it fetched; the next run
		// retries the write. The path is left out: it names the host.
		l.note = "the preload cache could not be written: " + fsCause(err)
	}
	return l, nil
}

// cachedList is the cache's list, or nil when there is no usable cache;
// the caller then fetches, which is the handling for every reason a cache
// can be unusable (absent, damaged, an older format).
func cachedList(path string) *preloadList {
	l, err := readPreloadCache(path)
	if err != nil {
		return nil
	}
	return l
}

// fsCause is a filesystem error without the path it names.
func fsCause(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Op + ": " + pe.Err.Error()
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		return le.Op + ": " + le.Err.Error()
	}
	return err.Error()
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
	if l := cachedList(cachePath); l != nil && l.fresh(time.Now()) {
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
