package main

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

func TestVCSVersion(t *testing.T) {
	rev := "ec2c130f00dc0ffee0000000000000000000000a"
	check(t, "clean tree", vcsVersion([]debug.BuildSetting{{Key: "vcs.revision", Value: rev}, {Key: "vcs.modified", Value: "false"}}), rev)
	check(t, "modified tree", vcsVersion([]debug.BuildSetting{{Key: "vcs.revision", Value: rev}, {Key: "vcs.modified", Value: "true"}}), rev+"-dirty")
	check(t, "no VCS (-buildvcs=false)", vcsVersion([]debug.BuildSetting{{Key: "-buildmode", Value: "exe"}}), "devel")
}

func TestBuildVersion_StampWins(t *testing.T) {
	saved := version
	defer func() { version = saved }()
	version = "0123456789abcdef0123456789abcdef01234567"
	check(t, "stamped", buildVersion(), version)
}

func TestParseArgs_Version(t *testing.T) {
	cfg, err := parseArgs([]string{"-version"})
	if err != nil {
		t.Fatal(err)
	}
	check(t, "version flag", cfg.ShowVersion, true)
	if _, err := parseArgs([]string{"-version", "example.com"}); err == nil {
		t.Error("-version with a domain must be a usage error")
	}
	var out, errBuf bytes.Buffer
	check(t, "exit 0", realMain([]string{"-version"}, &out, &errBuf), 0)
	check(t, "prints the version", out.String(), buildVersion()+"\n")
	check(t, "nothing on stderr", errBuf.String(), "")
}

func TestReport_CarriesVersion(t *testing.T) {
	rep := newReport(config{Domain: "example.com"})
	out, _ := json.Marshal(rep)
	check(t, "version key", strings.Contains(string(out), `"version":"`+buildVersion()+`"`), true)
}

// The stamp is a contract with scrape's worker build, and -X ignores a
// variable that does not exist without any error. Building exactly the
// way the worker does proves the name still binds.
func TestBinary_LdflagsStamp(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	const stamp = "0123456789abcdef0123456789abcdef01234567"
	bin := filepath.Join(t.TempDir(), "domaintest_stamped")
	build := exec.Command("go", "build", "-buildvcs=false", "-ldflags", "-X main.version="+stamp, "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	rc, out := runBinary(t, bin, "-version")
	check(t, "exit 0", rc, 0)
	check(t, "stamped version", out, stamp+"\n")
}

// The header is the first thing on the line: version, then timestamp, then
// the domain. Consumers parse the object, so order is for a human reading
// the raw output, but it is pinned so it does not drift.
func TestReport_HeaderLeads(t *testing.T) {
	rep := newReport(config{Domain: "example.com"})
	rep.Timestamp = reportTimestamp(time.Date(2026, 10, 5, 14, 42, 7, 900, time.FixedZone("CDT", -5*3600)))
	out, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":"` + buildVersion() + `","timestamp":"2026-10-05T19:42:07Z","domain":"example.com",`
	check(t, "header leads", strings.HasPrefix(string(out), want), true)
}
