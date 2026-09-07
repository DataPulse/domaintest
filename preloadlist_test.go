package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fixtureList parses the captured slice of Chromium's list.
func fixtureList(t *testing.T) *preloadList {
	t.Helper()
	l, err := parsePreloadJSON([]byte(fixture(t, "preload/entries_slice.json")))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// stubList replaces the network fetcher for the test and counts calls.
func stubList(t *testing.T, l *preloadList, err error) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	old := preloadListFetcher
	preloadListFetcher = func(context.Context, time.Duration) (*preloadList, error) {
		calls.Add(1)
		return l, err
	}
	t.Cleanup(func() { preloadListFetcher = old })
	return &calls
}

func TestParsePreloadJSON(t *testing.T) {
	l := fixtureList(t)
	check(t, "entries parsed", len(l.entries) > 200, true)
	check(t, "TLD entry with include_subdomains", l.entries["app"], true)
	check(t, "bulk entry", l.entries["github.com"], true)
	inc, ok := l.entries["gmail.com"]
	check(t, "gmail.com present", ok, true)
	check(t, "gmail.com does not include subdomains", inc, false)

	// Comments are stripped, force-https is required, an empty list is an error.
	_, err := parsePreloadJSON([]byte(`{"entries":[{"name":"x.test","mode":"disabled"}]}`))
	check(t, "no force-https entries", err != nil, true)
	_, err = parsePreloadJSON([]byte("// only a comment\n{invalid"))
	check(t, "malformed json", err != nil, true)
	one, err := parsePreloadJSON([]byte("// lead comment\n{\"entries\":[\n // inner\n {\"name\":\"X.Test\",\"mode\":\"force-https\",\"include_subdomains\":true}]}"))
	check(t, "comments tolerated", err, nil)
	check(t, "name lower-cased", one.entries["x.test"], true)
}

func TestPreloadListStatus(t *testing.T) {
	l := fixtureList(t)
	cases := []struct{ domain, status, coveredBy string }{
		{"github.com", PreloadPreloaded, ""},
		{"GitHub.com.", PreloadPreloaded, ""},
		{"api.github.com", PreloadPreloaded, "github.com"},
		{"deep.api.github.com", PreloadPreloaded, "github.com"},
		{"app", PreloadPreloaded, ""},
		{"anything.app", PreloadPreloaded, "app"},
		{"a.b.c.bank", PreloadPreloaded, "bank"},
		{"gmail.com", PreloadPreloaded, ""},
		// gmail.com is listed without include_subdomains, so children are not covered.
		{"mail.gmail.com", PreloadAbsent, ""},
		{"jschmidt.org", PreloadAbsent, ""},
		{"org", PreloadAbsent, ""},
		{"xn--mnchen-3ya.de", PreloadAbsent, ""},
	}
	for _, c := range cases {
		status, coveredBy := l.status(c.domain)
		check(t, c.domain+" status", status, c.status)
		check(t, c.domain+" covered by", coveredBy, c.coveredBy)
	}
	var empty *preloadList
	s, _ := empty.status("x.test")
	check(t, "nil list is unknown", s, PreloadUnknown)
	s, _ = (&preloadList{entries: map[string]bool{}}).status("x.test")
	check(t, "empty list is unknown", s, PreloadUnknown)
}

func TestPreloadCacheRoundTrip(t *testing.T) {
	l := fixtureList(t)
	path := filepath.Join(t.TempDir(), "sub", "hsts-preload.tsv")
	if err := writePreloadCache(path, l); err != nil {
		t.Fatal(err)
	}
	back, err := readPreloadCache(path)
	if err != nil {
		t.Fatal(err)
	}
	check(t, "entry count survives", len(back.entries), len(l.entries))
	check(t, "flags survive", []bool{back.entries["app"], back.entries["gmail.com"]}, []bool{true, false})

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	check(t, "header", strings.HasPrefix(string(body), cacheHeaderPrefix+" "), true)
	check(t, "sorted and tab separated", strings.Contains(string(body), "\napp\t1\n"), true)
	check(t, "no temporary files left", len(dirEntries(t, filepath.Dir(path))), 1)

	// Writing twice is idempotent apart from the timestamp.
	if err := writePreloadCache(path, l); err != nil {
		t.Fatal(err)
	}
	check(t, "still one file", len(dirEntries(t, filepath.Dir(path))), 1)
}

func dirEntries(t *testing.T, dir string) []os.DirEntry {
	t.Helper()
	e, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestPreloadCacheDamageForcesRefetch(t *testing.T) {
	good := string(marshalCache(fixtureList(t), time.Now()))
	cases := map[string]string{
		"empty file":      "",
		"header only":     cacheHeaderPrefix + " 2026-01-01T00:00:00Z\n",
		"wrong version":   "#domaintest-hsts-preload v2 2026-01-01T00:00:00Z\napp\t1\n",
		"foreign file":    "{\"json\": true}\n",
		"no header":       "app\t1\n",
		"bad flag":        cacheHeaderPrefix + " x\napp\tyes\n",
		"missing tab":     cacheHeaderPrefix + " x\napp1\n",
		"truncated write": good[:len(good)/2],
	}
	dir := t.TempDir()
	for name, body := range cases {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".tsv")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readPreloadCache(path); err == nil && name != "truncated write" {
			t.Errorf("%s: expected the cache to be rejected", name)
		}
	}
	// A truncated file usually ends mid-line, which is caught; whatever the
	// cut, loadPreloadList must still produce a list rather than fail.
	calls := stubList(t, fixtureList(t), nil)
	path := filepath.Join(dir, "truncated_write.tsv")
	l, err := loadPreloadList(context.Background(), path, time.Second)
	check(t, "list produced", err, nil)
	check(t, "usable", len(l.entries) > 0, true)
	_ = calls
}

func TestLoadPreloadList_UsesCacheThenFetchesOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hsts-preload.tsv")
	calls := stubList(t, fixtureList(t), nil)

	l, err := loadPreloadList(context.Background(), path, time.Second)
	check(t, "first load fetches", err, nil)
	check(t, "one fetch", calls.Load(), int32(1))
	check(t, "cache written", fileExists(path), true)
	check(t, "list usable", l.entries["app"], true)

	l2, err := loadPreloadList(context.Background(), path, time.Second)
	check(t, "second load", err, nil)
	check(t, "no second fetch", calls.Load(), int32(1))
	check(t, "same content", len(l2.entries), len(l.entries))
}

func TestLoadPreloadList_FetchErrorAndDisabledCache(t *testing.T) {
	stubList(t, nil, errors.New("dial tcp: lookup chromium.googlesource.com on 10.0.0.2:53: no such host"))
	_, err := loadPreloadList(context.Background(), filepath.Join(t.TempDir(), "c.tsv"), time.Second)
	check(t, "fetch error surfaces", err != nil, true)
	check(t, "message kept", strings.Contains(err.Error(), "no such host"), true)

	// "-" disables the cache: every call fetches, nothing is written.
	calls := stubList(t, fixtureList(t), nil)
	for i := 0; i < 2; i++ {
		if _, err := loadPreloadList(context.Background(), noCachePath, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	check(t, "fetched every time", calls.Load(), int32(2))
	check(t, "no file named -", fileExists(noCachePath), false)
}

func TestLoadPreloadList_UnwritableCacheStillAnswers(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	stubList(t, fixtureList(t), nil)
	l, err := loadPreloadList(context.Background(), filepath.Join(dir, "sub", "c.tsv"), time.Second)
	check(t, "still answers", err, nil)
	check(t, "list usable", l.entries["app"], true)
}

func TestLoadPreloadList_ConcurrentCallersFetchOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hsts-preload.tsv")
	var calls atomic.Int32
	old := preloadListFetcher
	preloadListFetcher = func(context.Context, time.Duration) (*preloadList, error) {
		calls.Add(1)
		time.Sleep(150 * time.Millisecond) // hold the lock long enough to contend
		return fixtureList(t), nil
	}
	t.Cleanup(func() { preloadListFetcher = old })

	const n = 5
	results := make([]*preloadList, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = loadPreloadList(context.Background(), path, 5*time.Second)
		}(i)
	}
	wg.Wait()
	check(t, "exactly one fetch", calls.Load(), int32(1))
	for i := range results {
		check(t, "no error", errs[i], nil)
		check(t, "answered", results[i].entries["app"], true)
	}
}

func TestAcquireLock_HonoursContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")
	release, err := acquireLock(context.Background(), path)
	check(t, "acquired", err, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = acquireLock(ctx, path)
	check(t, "second caller gives up", errors.Is(err, context.DeadlineExceeded), true)
	check(t, "gave up promptly", time.Since(start) < time.Second, true)

	release()
	release2, err := acquireLock(context.Background(), path)
	check(t, "available after release", err, nil)
	release2()
}

func TestLockPath(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "hsts-preload.tsv")
	old := systemLockDir
	t.Cleanup(func() { systemLockDir = old })

	// A usable system lock directory is preferred.
	systemLockDir = t.TempDir()
	check(t, "system lock dir used", lockPath(cache), filepath.Join(systemLockDir, "domaintest-hsts.lock"))

	// A missing one falls back beside the cache, as in a container.
	systemLockDir = filepath.Join(t.TempDir(), "absent")
	check(t, "fallback beside the cache", lockPath(cache), cache+".lock")

	// So does an unwritable one.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	systemLockDir = dir
	if os.Geteuid() != 0 {
		check(t, "unwritable falls back", lockPath(cache), cache+".lock")
	}
}

func TestWarmPreloadCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hsts-preload.tsv")
	calls := stubList(t, fixtureList(t), nil)

	note, err := warmPreloadCache(context.Background(), path)
	check(t, "warmed", err, nil)
	check(t, "cache exists", fileExists(path), true)
	check(t, "note names the cache", strings.Contains(note, path), true)
	check(t, "note names the lock", strings.Contains(note, "lock"), true)
	check(t, "note counts entries", strings.Contains(note, "entries"), true)

	note, err = warmPreloadCache(context.Background(), path)
	check(t, "second warm is a no-op", err, nil)
	check(t, "no refetch", calls.Load(), int32(1))
	check(t, "note says already present", strings.Contains(note, "already present"), true)

	stubList(t, nil, errors.New("boom"))
	_, err = warmPreloadCache(context.Background(), filepath.Join(dir, "other.tsv"))
	check(t, "fetch failure reported", err != nil && strings.Contains(err.Error(), "boom"), true)

	_, err = warmPreloadCache(context.Background(), noCachePath)
	check(t, "nothing to warm", err != nil, true)
}

func TestDefaultPreloadCachePath(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", "/tmp/example-cache")
	check(t, "under XDG_CACHE_HOME", defaultPreloadCachePath(), "/tmp/example-cache/domaintest/hsts-preload.tsv")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("HOME", "/home/pwuser")
	check(t, "falls back to HOME/.cache", defaultPreloadCachePath(), "/home/pwuser/.cache/domaintest/hsts-preload.tsv")
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// A 503 from googlesource is retried; a 404 is not.
func TestFetchPreloadList_Retries(t *testing.T) {
	var hits atomic.Int32
	body := marshalJSONList(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString(body)))
	}))
	t.Cleanup(srv.Close)
	withURL(t, srv.URL)
	withBackoff(t, time.Millisecond)

	l, err := fetchPreloadList(context.Background(), 5*time.Second)
	check(t, "succeeds after retries", err, nil)
	check(t, "attempts", hits.Load(), int32(3))
	check(t, "list parsed", l.entries["app"], true)

	// A client error is final.
	hits.Store(0)
	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(notFound.Close)
	withURL(t, notFound.URL)
	_, err = fetchPreloadList(context.Background(), 5*time.Second)
	check(t, "404 fails", err != nil && strings.Contains(err.Error(), "HTTP 404"), true)
	check(t, "not retried", hits.Load(), int32(1))

	// Persistent 5xx exhausts the attempts and reports the last error.
	hits.Store(0)
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(down.Close)
	withURL(t, down.URL)
	_, err = fetchPreloadList(context.Background(), 5*time.Second)
	check(t, "gives up", err != nil && strings.Contains(err.Error(), "HTTP 502"), true)
	check(t, "tried three times", hits.Load(), int32(fetchAttempts))

	// A context that ends during the backoff stops the retry loop.
	hits.Store(0)
	withURL(t, down.URL)
	withBackoff(t, 200*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = fetchPreloadList(ctx, time.Second)
	check(t, "stops early", err != nil, true)
	check(t, "one attempt", hits.Load(), int32(1))
}

// marshalJSONList renders the fixture back to Chromium's JSON shape.
func marshalJSONList(t *testing.T) []byte {
	t.Helper()
	var doc struct {
		Entries []preloadEntry `json:"entries"`
	}
	for name, inc := range fixtureList(t).entries {
		doc.Entries = append(doc.Entries, preloadEntry{Name: name, Mode: "force-https", IncludeSubdomains: inc})
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func withURL(t *testing.T, url string) {
	t.Helper()
	old := preloadListURL
	preloadListURL = url
	t.Cleanup(func() { preloadListURL = old })
}

func withBackoff(t *testing.T, d time.Duration) {
	t.Helper()
	old := fetchBackoff
	fetchBackoff = d
	t.Cleanup(func() { fetchBackoff = old })
}
