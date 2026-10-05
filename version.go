package main

import "runtime/debug"

// version is the build's identity, stamped by whoever builds the binary:
//
//	go build -ldflags "-X main.version=<commit>"
//
// scrape's worker image stamps the full commit it vendored and builds with
// -buildvcs=false. The name and type are a contract with that build: -X
// silently ignores a variable that does not exist, so renaming this would
// unstamp every worker without an error anywhere.
var version = "devel"

// buildVersion is the version a report and -version give. An unstamped
// build falls back to the commit Go recorded from the source tree, marked
// -dirty when the tree had uncommitted changes, so a local binary still
// says what it is; with neither, it is "devel".
func buildVersion() string {
	if version != "devel" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return version
	}
	return vcsVersion(info.Settings)
}

// vcsVersion reads the revision and modified flag from build settings.
func vcsVersion(settings []debug.BuildSetting) string {
	rev, dirty := "", false
	for _, s := range settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	switch {
	case rev == "":
		return version
	case dirty:
		return rev + "-dirty"
	}
	return rev
}
