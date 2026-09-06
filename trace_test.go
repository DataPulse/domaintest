package main

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseTrace_Blocks(t *testing.T) {
	blocks, diags := parseTrace(fixture(t, "trace/jschmidt.txt"))
	if len(diags) != 0 {
		t.Errorf("unexpected diagnostics %v", diags)
	}
	if len(blocks) != 4 {
		t.Fatalf("expected 4 blocks (root, org, referral, answer), got %d", len(blocks))
	}
	if blocks[0].Server != "a.root-servers.net" || blocks[0].IP == "" {
		t.Errorf("first block server %q ip %q", blocks[0].Server, blocks[0].IP)
	}
	if ns := blocks[0].nsFor("."); len(ns) != 13 {
		t.Errorf("root block should list 13 NS, got %d", len(ns))
	}
	if ns := blocks[2].nsFor("jschmidt.org."); len(ns) != 4 {
		t.Errorf("referral block should list 4 NS, got %v", ns)
	}
}

func TestParseTrace_DiagnosticsAndTrailingBlock(t *testing.T) {
	out := ";; communications error to 192.0.2.1#53: timed out\n" +
		"example.org.\t3600\tIN\tNS\tns1.example.org.\n"
	blocks, diags := parseTrace(out)
	if len(diags) != 1 || !strings.Contains(diags[0], "communications error") {
		t.Errorf("diags %v", diags)
	}
	if len(blocks) != 1 || len(blocks[0].nsFor("example.org.")) != 1 {
		t.Errorf("trailing block without Received line should be kept: %+v", blocks)
	}
	if b, d := parseTrace(""); len(b) != 0 || len(d) != 0 {
		t.Errorf("empty output: %v %v", b, d)
	}
}

func TestCompareDelegation_Fixtures(t *testing.T) {
	cases := []struct {
		file, domain, status string
		parent, child        int
		parentOnly           []string
		childOnly            []string
	}{
		{"trace/jschmidt.txt", "jschmidt.org", DelegationMatch, 4, 4, nil, nil},
		{"trace/google.txt", "google.com", DelegationMatch, 4, 4, nil, nil},
		{"trace/osu_edu.txt", "osu.edu", DelegationMatch, 6, 6, nil, nil},
		{"trace/bbc_co_uk.txt", "bbc.co.uk", DelegationMatch, 8, 8, nil, nil},
		{"trace/dnssec_failed_consistent.txt", "dnssec-failed.org", DelegationMatch, 5, 5, nil, nil},
		{"trace/dnssec_failed_mismatch.txt", "dnssec-failed.org", DelegationMismatch, 3, 5, nil,
			[]string{"dns102.comcast.net.", "dns103.comcast.net."}},
		{"trace/nxdomain.txt", "nonexistent-zzz-qq.org", DelegationNotDelegated, 0, 0, nil, nil},
		{"trace/nic_cz_same_servers.txt", "nic.cz", DelegationSameServers, 3, 3, nil, nil},
		{"trace/gov_uk_same_servers.txt", "gov.uk", DelegationSameServers, 8, 8, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			blocks, diags := parseTrace(fixture(t, c.file))
			d := compareDelegation(blocks, diags, c.domain)
			if d.Status != c.status {
				t.Errorf("status %q, want %q (%+v)", d.Status, c.status, d)
			}
			if len(d.ParentNS) != c.parent || len(d.ChildNS) != c.child {
				t.Errorf("parent %d child %d, want %d/%d", len(d.ParentNS), len(d.ChildNS), c.parent, c.child)
			}
			if !reflect.DeepEqual(d.ParentOnly, c.parentOnly) || !reflect.DeepEqual(d.ChildOnly, c.childOnly) {
				t.Errorf("parentOnly %v childOnly %v, want %v / %v", d.ParentOnly, d.ChildOnly, c.parentOnly, c.childOnly)
			}
			if c.status != DelegationNotDelegated && (d.ParentServer == "" || d.ChildServer == "") {
				t.Errorf("servers missing: %+v", d)
			}
		})
	}
}

func TestCompareDelegation_CaseAndDomainForms(t *testing.T) {
	blocks, _ := parseTrace(fixture(t, "trace/jschmidt.txt"))
	for _, dom := range []string{"JSCHMIDT.ORG", "jschmidt.org.", "Jschmidt.Org."} {
		if d := compareDelegation(blocks, nil, dom); d.Status != DelegationMatch {
			t.Errorf("%q: %+v", dom, d)
		}
	}
	if d := compareDelegation(blocks, nil, "other.org"); d.Status != DelegationError {
		t.Errorf("unrelated domain should be an error, got %+v", d)
	}
}

func TestCompareDelegation_NoChildAnswerAndNoBlocks(t *testing.T) {
	// Keep only the blocks up to and including the parent referral.
	full := fixture(t, "trace/jschmidt.txt")
	idx := strings.LastIndex(full, ";; Received")
	cut := full[:strings.LastIndex(full[:idx], ";; Received")+1]
	cut = cut[:strings.LastIndex(cut, "\n")+1]
	blocks, _ := parseTrace(cut)
	d := compareDelegation(blocks, []string{"communications error to 1.2.3.4#53: timed out"}, "jschmidt.org")
	if d.Status != DelegationNoChildAnswer || len(d.ParentNS) != 4 || !strings.Contains(d.Error, "timed out") {
		t.Errorf("unexpected %+v", d)
	}
	d = compareDelegation(nil, nil, "jschmidt.org")
	if d.Status != DelegationError || d.Error == "" {
		t.Errorf("no blocks should be an error: %+v", d)
	}
}

func TestSetDiff(t *testing.T) {
	got := setDiff([]string{"b", "a", "c"}, []string{"a"})
	if !reflect.DeepEqual(got, []string{"b", "c"}) {
		t.Errorf("got %v", got)
	}
	if got := setDiff(nil, []string{"a"}); got != nil {
		t.Errorf("nil diff got %v", got)
	}
}

func TestTraceArgs(t *testing.T) {
	got := strings.Join(traceArgs(familyIPv4, 5, "jschmidt.org"), " ")
	if got != "+trace +nodnssec +tries=1 +time=2 -4 @a.root-servers.net jschmidt.org NS" {
		t.Errorf("got %q", got)
	}
	if !strings.Contains(strings.Join(traceArgs(familyIPv6, 5, "x.org"), " "), " -6 ") {
		t.Error("ipv6 family should pass -6")
	}
}

func TestTraceDelegation_FakeRunner(t *testing.T) {
	r := newFakeRunner()
	args := traceArgs(familyIPv4, 5, "dnssec-failed.org")
	r.on("dig", args, fakeCall{stdout: fixture(t, "trace/dnssec_failed_mismatch.txt"), err: errFake})
	d := traceDelegation(context.Background(), r, "dig", familyIPv4, 5, "dnssec-failed.org")
	if d.Status != DelegationMismatch {
		t.Errorf("non-zero dig exit with output should still parse: %+v", d)
	}

	r.on("dig", traceArgs(familyIPv4, 5, "dead.org"), fakeCall{stderr: "no servers", err: errFake})
	d = traceDelegation(context.Background(), r, "dig", familyIPv4, 5, "dead.org")
	if d.Status != DelegationError || !strings.Contains(d.Error, "no servers") {
		t.Errorf("unexpected %+v", d)
	}

	r.on("dig", traceArgs(familyIPv4, 5, "slow.org"), fakeCall{delay: 2 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	d = traceDelegation(ctx, r, "dig", familyIPv4, 5, "slow.org")
	if d.Status != DelegationError || !strings.Contains(d.Error, "timed out") {
		t.Errorf("unexpected %+v", d)
	}
}

func TestClassifySingleBlock(t *testing.T) {
	blocks, _ := parseTrace(fixture(t, "trace/nic_cz_same_servers.txt"))
	last := blocks[len(blocks)-1]
	d := classifySingleBlock(Delegation{}, last, "nic.cz.")
	check(t, "status", d.Status, DelegationSameServers)
	check(t, "server", d.ParentServer, "a.ns.nic.cz")
	check(t, "child == parent", d.ChildNS, d.ParentNS)
	// Same block but answered by a server outside the NS set: no child answer.
	last.Server = "c0.org.afilias-nst.info"
	d = classifySingleBlock(Delegation{}, last, "nic.cz.")
	check(t, "status", d.Status, DelegationNoChildAnswer)
	check(t, "child NS empty", len(d.ChildNS), 0)
}

func TestDigAuthoritative(t *testing.T) {
	check(t, "aa answer", digAuthoritative(fixture(t, "dig/nic_cz_at_c_ns_aa.yaml")), true)
	check(t, "referral", digAuthoritative(fixture(t, "dig/jschmidt_at_org_referral.yaml")), false)
	check(t, "empty", digAuthoritative(""), false)
	check(t, "EDNS flags line only", digAuthoritative("          flags: do\n"), false)
}

func TestAuthArgs(t *testing.T) {
	got := strings.Join(authArgs("c.ns.nic.cz", familyIPv4, 5, "nic.cz"), " ")
	check(t, "args", got, "+norecurse +yaml +tries=1 +time=2 -4 @c.ns.nic.cz nic.cz NS")
	check(t, "ipv6", strings.Contains(strings.Join(authArgs("x", familyIPv6, 5, "d"), " "), " -6 "), true)
}

// TestTraceDelegation_AuthoritativeParentServer covers the case seen live
// for nic.cz: dig +trace lands on c.ns.nic.cz, which serves .cz and answers
// for nic.cz authoritatively although it is not in nic.cz's NS set.
func TestTraceDelegation_AuthoritativeParentServer(t *testing.T) {
	trace := strings.ReplaceAll(fixture(t, "trace/nic_cz_same_servers.txt"), "(a.ns.nic.cz)", "(c.ns.nic.cz)")
	r := newFakeRunner()
	r.on("dig", traceArgs(familyIPv4, 5, "nic.cz"), fakeCall{stdout: trace})
	r.on("dig", authArgs("c.ns.nic.cz", familyIPv4, 5, "nic.cz"), fakeCall{stdout: fixture(t, "dig/nic_cz_at_c_ns_aa.yaml")})
	d := traceDelegation(context.Background(), r, "dig", familyIPv4, 5, "nic.cz")
	check(t, "status", d.Status, DelegationSameServers)
	check(t, "child server", d.ChildServer, "c.ns.nic.cz")
	check(t, "child NS", d.ChildNS, d.ParentNS)
	check(t, "dig calls", len(r.called("dig")), 2)

	// A referral-only server (no aa) leaves the verdict at no_child_answer.
	r = newFakeRunner()
	r.on("dig", traceArgs(familyIPv4, 5, "nic.cz"), fakeCall{stdout: trace})
	r.on("dig", authArgs("c.ns.nic.cz", familyIPv4, 5, "nic.cz"), fakeCall{stdout: fixture(t, "dig/jschmidt_at_org_referral.yaml")})
	d = traceDelegation(context.Background(), r, "dig", familyIPv4, 5, "nic.cz")
	check(t, "status", d.Status, DelegationNoChildAnswer)

	// When the answering server is in the NS set no extra query is needed.
	r = newFakeRunner()
	r.on("dig", traceArgs(familyIPv4, 5, "nic.cz"), fakeCall{stdout: fixture(t, "trace/nic_cz_same_servers.txt")})
	d = traceDelegation(context.Background(), r, "dig", familyIPv4, 5, "nic.cz")
	check(t, "status", d.Status, DelegationSameServers)
	check(t, "dig calls", len(r.called("dig")), 1)
}
