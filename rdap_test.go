package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The rdap fixtures are real `rdap` CLI captures (openrdap 64c8c7d, the
// commit the scrape workers build); see testdata/rdap/README.md.

// rdapCall serves one captured lookup: its stdout and stderr, and the exit
// status the CLI returned.
func rdapCall(t *testing.T, name string, failed bool) fakeCall {
	t.Helper()
	c := fakeCall{stdout: fixture(t, "rdap/"+name+".stdout"), stderr: fixture(t, "rdap/"+name+".stderr")}
	if failed {
		c.err = errFake // the CLI exits 1 on every failure
	}
	return c
}

// rdapConfig is a config whose rdap binary is the fake runner's.
func rdapConfig(domain string) config {
	cfg := baseConfig(domain, "")
	cfg.RDAP, cfg.RDAPPath = true, "rdap"
	return cfg
}

// onRDAP registers a lookup of query.
func onRDAP(r *fakeRunner, cfg config, query, server string, c fakeCall) {
	r.on("rdap", rdapArgs(query, server, cfg.TimeoutSec), c)
}

func TestRDAPTarget(t *testing.T) {
	for _, c := range []struct {
		in, query, server string
		ok                bool
	}{
		{"google.com", "google.com", "", true},
		{"www.google.com", "google.com", "", true},
		{"mail.google.co.uk", "google.co.uk", "", true},
		// A private suffix with its own RDAP service is asked there, for
		// the name registered under it.
		{"microsoft.jp.net", "microsoft.jp.net", "https://rdap.centralnic.com/jp.net/", true},
		{"www.microsoft.jp.net", "microsoft.jp.net", "https://rdap.centralnic.com/jp.net/", true},
		// A private suffix without one is registered at the ICANN level.
		{"someone.github.io", "github.io", "", true},
		{"com", "", "", false},
		{"co.uk", "", "", false},
		{"localhost", "", "", false},
		{"www.example.test", "", "", false},
	} {
		q, s, ok := rdapTarget(c.in)
		check(t, c.in, []any{q, s, ok}, []any{c.query, c.server, c.ok})
	}
}

func TestRDAPArgs(t *testing.T) {
	check(t, "bootstrap", rdapArgs("google.com", "", 3), []string{"--json", "--timeout", "3", "--", "google.com"})
	check(t, "routed", rdapArgs("microsoft.jp.net", "https://rdap.centralnic.com/jp.net/", 3),
		[]string{"--json", "--timeout", "3", "-s", "https://rdap.centralnic.com/jp.net/", "--", "microsoft.jp.net"})
	check(t, "timeout at least 1", rdapArgs("x.com", "", 0)[2], "1")
}

// One lookup, at the registry. The registrar is named from its answer and
// not asked: Verisign links to MarkMonitor's record, which is not fetched.
func TestCheckRDAP_RegistryOnly(t *testing.T) {
	cfg := rdapConfig("www.google.com")
	r := newFakeRunner()
	onRDAP(r, cfg, "google.com", "", rdapCall(t, "google.com", false))
	rep := checkRDAP(context.Background(), cfg, r)

	check(t, "domain", rep.Domain, "google.com")
	check(t, "no server route", rep.Server, "")
	check(t, "registered", rep.Registered, boolPtr(true))
	check(t, "registry url", rep.Registry.URL, "https://rdap.verisign.com/com/v1/domain/google.com")
	check(t, "registry status", rep.Registry.Status, []string{"client delete prohibited", "client transfer prohibited",
		"client update prohibited", "server delete prohibited", "server transfer prohibited", "server update prohibited"})
	check(t, "registrar", *rep.Registrar, RDAPRegistrar{Name: "MarkMonitor Inc.", IANAID: "292"})
	check(t, "one lookup", len(r.called("rdap")), 1)

	var f findings
	f.rdapFindings(rep)
	check(t, "locks are facts, not findings", findingCodes(&f), []string{})
}

func TestCheckRDAP_Holds(t *testing.T) {
	for _, c := range []struct {
		domain  string
		want    []string
		message string
	}{
		// A registrar's clientHold is set at the registry (Tucows, Verisign).
		{"finalthreadss.com", []string{"fail:domain_on_hold"},
			"RDAP reports finalthreadss.com on hold: client hold"},
		// serverHold at the registry, which GoDaddy's own record omitted.
		{"3pattifacebook.site", []string{"fail:domain_on_hold"},
			"RDAP reports 3pattifacebook.site on hold: server hold"},
		{"datapulse.vip", []string{"warn:domain_pending_deletion"},
			"RDAP reports datapulse.vip being deleted: pending delete, redemption period"},
	} {
		cfg := rdapConfig(c.domain)
		r := newFakeRunner()
		onRDAP(r, cfg, c.domain, "", rdapCall(t, c.domain, false))
		rep := checkRDAP(context.Background(), cfg, r)
		var f findings
		f.rdapFindings(rep)
		check(t, c.domain+" codes", findingCodes(&f), c.want)
		check(t, c.domain+" message", f.list[0].Message, c.message)
		check(t, c.domain+" domain-wide", f.list[0].Host, "")
	}
}

// inactive says only that the domain has no delegation, so beside a hold it
// adds nothing, and alone it is a fact without a finding.
func TestCheckRDAP_InactiveAndHeld(t *testing.T) {
	cfg := rdapConfig("loginmicrosoftonline.cloud")
	r := newFakeRunner()
	onRDAP(r, cfg, "loginmicrosoftonline.cloud", "", rdapCall(t, "loginmicrosoftonline.cloud", false))
	rep := checkRDAP(context.Background(), cfg, r)
	var f findings
	f.rdapFindings(rep)
	check(t, "codes", findingCodes(&f), []string{"fail:domain_on_hold"})
	check(t, "registered", rep.Registered, boolPtr(true))
}

// CZ.NIC names the registrar with no IANA ID (ccTLD registrars have none).
func TestCheckRDAP_RegistrarWithoutIANAID(t *testing.T) {
	cfg := rdapConfig("example.cz")
	r := newFakeRunner()
	onRDAP(r, cfg, "example.cz", "", rdapCall(t, "example.cz", false))
	rep := checkRDAP(context.Background(), cfg, r)
	check(t, "registry status", rep.Registry.Status, []string{"active"})
	check(t, "registrar named", *rep.Registrar, RDAPRegistrar{Name: "INTERNET CZ, a.s."})
	var f findings
	f.rdapFindings(rep)
	check(t, "no finding", findingCodes(&f), []string{})
}

func TestCheckRDAP_PrivateSuffixRoute(t *testing.T) {
	cfg := rdapConfig("www.microsoft.jp.net")
	r := newFakeRunner()
	onRDAP(r, cfg, "microsoft.jp.net", "https://rdap.centralnic.com/jp.net/", rdapCall(t, "microsoft.jp.net", false))
	rep := checkRDAP(context.Background(), cfg, r)
	check(t, "server", rep.Server, "https://rdap.centralnic.com/jp.net/")
	check(t, "registered at the registry", rep.Registered, boolPtr(true))
	check(t, "registrar", rep.Registrar.Name, "GMO Internet Group, Inc. d/b/a Onamae.com")
}

func TestCheckRDAP_Failures(t *testing.T) {
	for _, c := range []struct {
		name       string
		call       fakeCall
		registered *bool
		err        string
		codes      []string
	}{
		// A 404 is the registry's answer: the domain is not registered.
		{"not registered", rdapCall(t, "nonexist", true), boolPtr(false),
			"rdap: RDAP server returned 404, object does not exist.", []string{}},
		{"deleted since portdb saw it in redemption", rdapCall(t, "microsoftskype.net", true), boolPtr(false),
			"rdap: RDAP server returned 404, object does not exist.", []string{}},
		{"no RDAP for the TLD", rdapCall(t, "de", true), nil,
			"rdap: No RDAP servers found for 'denic.de'", []string{"info:rdap_lookup_failed"}},
		{"CLI timeout", rdapCall(t, "timeout", true), nil,
			`rdap: Get "https://10.255.255.1/domain/example.com": context deadline exceeded`, []string{"info:rdap_lookup_failed"}},
		{"no output", fakeCall{}, nil, "rdap produced no output", []string{"info:rdap_lookup_failed"}},
		{"not an object", fakeCall{stdout: "[1,2]"}, nil, "rdap output not a JSON object: [1,2]", []string{"info:rdap_lookup_failed"}},
		{"truncated", fakeCall{stdout: `{"status": ["active"`}, nil, "rdap output not an RDAP object: unexpected end of JSON input", []string{"info:rdap_lookup_failed"}},
		{"wrong type", fakeCall{stdout: `{"status": "active"}`}, nil, "rdap output not an RDAP object: json: cannot unmarshal string into Go struct field rdapDomain.status of type []string", []string{"info:rdap_lookup_failed"}},
		{"failed silently", fakeCall{err: errFake}, nil, "rdap: fake failure", []string{"info:rdap_lookup_failed"}},
	} {
		cfg := rdapConfig("example.com")
		r := newFakeRunner()
		onRDAP(r, cfg, "example.com", "", c.call)
		rep := checkRDAP(context.Background(), cfg, r)
		check(t, c.name+" registered", rep.Registered, c.registered)
		check(t, c.name+" error", rep.Registry.Error, c.err)
		check(t, c.name+" status unknown", rep.Registry.Status, []string(nil))
		check(t, c.name+" no registrar", rep.Registrar, (*RDAPRegistrar)(nil))
		var f findings
		f.rdapFindings(rep)
		check(t, c.name+" codes", findingCodes(&f), c.codes)
	}
}

// The context is the kill switch for a CLI that never returns.
func TestCheckRDAP_KilledAtDeadline(t *testing.T) {
	cfg := rdapConfig("example.com")
	cfg.TimeoutSec = 1
	r := newFakeRunner()
	onRDAP(r, cfg, "example.com", "", fakeCall{delay: time.Minute})
	start := time.Now()
	rep := checkRDAP(context.Background(), cfg, r)
	if el := time.Since(start); el > 3*time.Second {
		t.Errorf("took %v, want about 2 s", el)
	}
	check(t, "error", rep.Registry.Error, "rdap timed out")
	check(t, "unknown", rep.Registered, (*bool)(nil))
}

func TestCheckRDAP_BinaryMissing(t *testing.T) {
	cfg := rdapConfig("example.com")
	cfg.RDAPPath = ""
	r := newFakeRunner()
	rep := checkRDAP(context.Background(), cfg, r)
	check(t, "error", rep.Registry.Error, "rdap not found on PATH")
	check(t, "unknown", rep.Registered, (*bool)(nil))
	check(t, "nothing run", len(r.called("rdap")), 0)
	var f findings
	f.rdapFindings(rep)
	check(t, "info only", findingCodes(&f), []string{"info:rdap_lookup_failed"})
}

func TestCheckRDAP_NothingToLookUp(t *testing.T) {
	r := newFakeRunner()
	check(t, "public suffix", checkRDAP(context.Background(), rdapConfig("co.uk"), r), (*RDAPReport)(nil))
	check(t, "reserved", checkRDAP(context.Background(), rdapConfig("localhost"), r), (*RDAPReport)(nil))
	check(t, "nothing run", len(r.called("rdap")), 0)
}

// Registries serve RFC 8056 names ("client hold"); EPP's camelCase form
// ("clientHold", as portdb stores them) must match the same rules.
func TestStatusKey(t *testing.T) {
	for _, s := range []string{"client hold", "clientHold", "CLIENT HOLD", " client_hold ", "client-hold"} {
		check(t, s, statusKey(s), "clienthold")
	}
	rep := &RDAPReport{Domain: "auth-messenger.info", Registry: RDAPRegistry{Status: []string{
		"clientDeleteProhibited", "serverDeleteProhibited", "clientHold", "serverHold", "clientRenewProhibited"}}}
	check(t, "camelCase holds", matchedStatuses(rep, rdapHoldStatus), []string{"clientHold", "serverHold"})
	rep.Registry.Status = []string{"redemptionPeriod", "pendingDelete", "pendingRestore", "inactive", "autoRenewPeriod"}
	check(t, "camelCase deletion", matchedStatuses(rep, rdapDeletionStatus),
		[]string{"redemptionPeriod", "pendingDelete", "pendingRestore"})
}

// status is null when the lookup did not complete and [] when the registry
// served none; registered is null when undetermined.
func TestRDAPReport_JSONShape(t *testing.T) {
	out, err := json.Marshal(&RDAPReport{Domain: "example.com", Registry: RDAPRegistry{Error: "rdap timed out"}})
	if err != nil {
		t.Fatal(err)
	}
	check(t, "unknown", string(out), `{"domain":"example.com","registered":null,"registry":{"status":null,"error":"rdap timed out"}}`)
	out, _ = json.Marshal(&RDAPReport{Domain: "example.com", Registered: boolPtr(true), Registry: RDAPRegistry{Status: []string{}},
		Registrar: &RDAPRegistrar{Name: "MarkMonitor Inc.", IANAID: "292"}})
	check(t, "none served", string(out), `{"domain":"example.com","registered":true,"registry":{"status":[]},"registrar":{"name":"MarkMonitor Inc.","iana_id":"292"}}`)
}

func TestVCardName(t *testing.T) {
	raw := func(s string) []json.RawMessage {
		var v []json.RawMessage
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	check(t, "fn", vcardName(raw(`["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "MarkMonitor Inc."]]]`)), "MarkMonitor Inc.")
	check(t, "empty", vcardName(nil), "")
	check(t, "no fn", vcardName(raw(`["vcard", [["version", {}, "text", "4.0"]]]`)), "")
	check(t, "fn not text", vcardName(raw(`["vcard", [["fn", {}, "text", 7]]]`)), "")
	check(t, "props not a list", vcardName(raw(`["vcard", "x"]`)), "")
	check(t, "short prop", vcardName(raw(`["vcard", [["fn"]]]`)), "")
}

func TestFindRDAP(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	p, err := findRDAP("")
	check(t, "missing on PATH is not an error", []any{p, err}, []any{"", error(nil)})
	_, err = findRDAP(filepath.Join(dir, "nope"))
	check(t, "explicit missing is an error", err != nil, true)
	bin := filepath.Join(dir, "rdap")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p, err = findRDAP("")
	check(t, "found on PATH", []any{p, err}, []any{bin, error(nil)})
}

// A held domain's zone is usually what the run stops early for, so the
// registration lookup is joined on that path too, and its findings stand
// beside zone_unreachable.
func TestRun_RDAPOnDeadZone(t *testing.T) {
	g := googleScenario(t)
	s := g.s
	s.cfg.TimeoutSec, s.cfg.TCPTimeoutSec, s.cfg.QuicTimeoutSec = 2, 1, 2
	s.cfg.RDAP, s.cfg.RDAPPath = true, "rdap"
	onRDAP(s.r, s.cfg, "google.com", "", rdapCall(t, "google.com", false))
	full := fixture(t, "trace/google.txt")
	cut := full[:strings.Index(full, ";; Received 287 bytes from 192.41.162.30")]
	cut += ";; Received 287 bytes from 192.41.162.30#53(l.gtld-servers.net) in 36 ms\n\n;; communications error to 216.239.32.10#53: timed out\n"
	s.r.on("dig", traceArgs(familyIPv4, s.cfg.TimeoutSec, s.cfg.Domain), fakeCall{stdout: cut})
	s.r.on("dig", authArgs("l.gtld-servers.net", familyIPv4, s.cfg.TimeoutSec, s.cfg.Domain), fakeCall{stdout: fixture(t, "dig/jschmidt_at_org_referral.yaml")})
	s.glue("l.gtld-servers.net", "dig/ns/glue_google_at_gtld.yaml", t)
	b := &budgetRunner{inner: s.r, left: map[string]time.Duration{}, delay: func(key string) time.Duration {
		if strings.Contains(key, "+norecurse") && strings.Contains(key, "SOA") {
			return time.Minute // every delegated server is silent
		}
		return 0
	}}
	rep := run(context.Background(), s.cfg, b, s.dialer)
	check(t, "dead zone", zoneUnreachable(rep), true)
	if rep.RDAP == nil {
		t.Fatal("no rdap section on the early return")
	}
	check(t, "registered", rep.RDAP.Registered, boolPtr(true))
	check(t, "registry status read", rep.RDAP.Registry.Status != nil, true)
	check(t, "findings", reportCodes(rep), []string{"fail:zone_unreachable"})
}

func TestRun_RDAPSection(t *testing.T) {
	s := newScenario(t, "nonexistent-zzz-qq.org", "")
	s.r.fallback = func(tool string, args []string) (fakeCall, bool) {
		if tool == "dog" {
			return fakeCall{stdout: fixture(t, "dog/nxdomain_signed.json")}, true
		}
		return fakeCall{}, false
	}
	s.cfg.RDAP, s.cfg.RDAPPath = true, "rdap"
	onRDAP(s.r, s.cfg, "nonexistent-zzz-qq.org", "", fakeCall{err: errFake, stderr: fixture(t, "rdap/nonexist.stderr")})
	s.reach(familyIPv4, "dog/root_ns_v4.json", t)
	s.trace("trace/nxdomain.txt", t)
	rep := s.run()
	check(t, "not registered", rep.RDAP.Registered, boolPtr(false))
	check(t, "one fact, the NXDOMAIN", reportCodes(rep), []string{"fail:apex_nxdomain"})

	s.cfg.RDAP = false
	s.r.calls = nil
	rep = s.run()
	check(t, "-no-rdap: no section", rep.RDAP, (*RDAPReport)(nil))
	check(t, "-no-rdap: nothing run", len(s.r.called("rdap")), 0)
}

// A held name whose zone is gone reports both facts: the DNS symptom and
// the registry's reason for it.
func TestRDAPFindings_BesideCollapsedReports(t *testing.T) {
	cfg := rdapConfig("finalthreadss.com")
	r := newFakeRunner()
	onRDAP(r, cfg, "finalthreadss.com", "", rdapCall(t, "finalthreadss.com", false))
	held := checkRDAP(context.Background(), cfg, r)
	for _, c := range []struct{ fixture, first string }{
		{"skvr.site.json", "fail:zone_unreachable"},
		{"datapulse-nonexistent-7f3a9c.com.json", "fail:apex_nxdomain"},
	} {
		rep, _, _ := replayFixture(t, "testdata/reports/"+c.fixture)
		rep.RDAP = held
		buildFindings(rep)
		check(t, c.fixture, reportCodes(rep), []string{c.first, "fail:domain_on_hold"})
		check(t, c.fixture+" two errors", len(rep.Errors), 2)
	}
}

// gov.uk is a public suffix, so www.gov.uk is itself the registration, and
// Nominet serves it as inactive: registered, never delegated. That is a
// fact, not a domain being deleted (calibration, 2026-10-29).
func TestCheckRDAP_InactiveAloneIsAFact(t *testing.T) {
	cfg := rdapConfig("www.gov.uk")
	r := newFakeRunner()
	onRDAP(r, cfg, "www.gov.uk", "", rdapCall(t, "www.gov.uk", false))
	rep := checkRDAP(context.Background(), cfg, r)
	check(t, "asked as itself", rep.Domain, "www.gov.uk")
	check(t, "inactive reported", rep.Registry.Status[0], "inactive")
	check(t, "registrar as Nominet names it", *rep.Registrar, RDAPRegistrar{Name: ".gov.uk Registry"})
	var f findings
	f.rdapFindings(rep)
	check(t, "no finding", findingCodes(&f), []string{})
}
