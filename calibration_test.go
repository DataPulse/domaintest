//go:build calibration

package main

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
)

// calibrationLimit is the share of the reference set a single warn code may
// fire on. The reference names are run by operators who would fix a real
// defect; a warning most of them carry is describing a choice, and belongs
// at info.
const calibrationLimit = 0.20

// TestCalibration runs the built binary live over testdata/calibration/
// reference.txt (flagship apexes and as many of their subdomains) and fails
// when any warn code exceeds calibrationLimit. It needs the network and
// takes a minute or two, so it sits behind a build tag:
//
//	go test -tags calibration -run Calibration -v
func TestCalibration(t *testing.T) {
	names := referenceNames(t)
	bin := buildDomaintest(t)

	var mu sync.Mutex
	hits := map[string][]string{} // warn code -> names
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, name := range names {
		wg.Add(1)
		sem <- struct{}{}
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()
			_, out := runBinary(t, bin, "-t", "3", name)
			var rep Report
			if err := json.Unmarshal([]byte(out), &rep); err != nil {
				t.Errorf("%s: stdout is not a report: %v", name, err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, code := range warnCodes(&rep) {
				hits[code] = append(hits[code], name)
			}
		}(name)
	}
	wg.Wait()

	codes := make([]string, 0, len(hits))
	for c := range hits {
		codes = append(codes, c)
	}
	sort.Slice(codes, func(i, j int) bool { return len(hits[codes[i]]) > len(hits[codes[j]]) })
	for _, c := range codes {
		share := float64(len(hits[c])) / float64(len(names))
		t.Logf("%-32s %3d/%d  %s", c, len(hits[c]), len(names), strings.Join(hits[c], " "))
		if share > calibrationLimit {
			t.Errorf("warn code %s fires on %.0f%% of the reference set", c, share*100)
		}
	}
}

func referenceNames(t *testing.T) []string {
	t.Helper()
	f, err := os.Open("testdata/calibration/reference.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var names []string
	sub := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		n := strings.TrimSpace(sc.Text())
		if n == "" || strings.HasPrefix(n, "#") {
			continue
		}
		names = append(names, n)
		if !registrableDomain(n) {
			sub++
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	// An apex-only set never walks into a subdomain's redirects, wildcard
	// or certificate coverage, which is where the blind spots were.
	if sub*2 < len(names) {
		t.Fatalf("reference set must be at least half subdomains: %d of %d", sub, len(names))
	}
	return names
}
