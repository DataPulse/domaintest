package main

import (
	"slices"
	"sync"
	"testing"
)

// A published MTA-STS record puts the policy host's lookups in the second
// wave, so the policy fetch in the probe phase finds them answered.
func TestDependentLookups_PrefetchMTASTSHost(t *testing.T) {
	for _, c := range []struct {
		file string
		want bool
	}{
		{"dog/mail/mta_sts_gmail.json", true},
		{"dog/mail/mta_sts_jschmidt_missing.json", false},
	} {
		res := dnsResults{apex: map[string]Lookup{}, www: map[string]Lookup{}, mtaSTS: dogFixture(t, c.file, "TXT")}
		var mu sync.Mutex
		var asked []string
		get := func(name, qtype string) Lookup {
			mu.Lock()
			asked = append(asked, name+"/"+qtype)
			mu.Unlock()
			return Lookup{Name: name, Type: qtype, Status: StatusNXRRSet}
		}
		parallel(dependentLookups(&res, baseConfig("gmail.com", ""), get)...)
		check(t, c.file+" A", slices.Contains(asked, "mta-sts.gmail.com/A"), c.want)
		check(t, c.file+" AAAA", slices.Contains(asked, "mta-sts.gmail.com/AAAA"), c.want)
	}
}
