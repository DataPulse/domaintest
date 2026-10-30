package main

import (
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/DataPulse/dpdomain/psl"
)

// RDAP registration status, read with openrdap's `rdap` CLI: the binary the
// scrape workers already build, with the IANA bootstrap cache their
// entrypoint warms (~/.cache/openrdap). One lookup, at the registry, in a
// single attempt: a refusal or a timeout is reported, not retried.
//
// The registry holds a domain's EPP status (RFC 5731): a registrar sets its
// client statuses there, and the deletion states are the registry's own. The
// registrar's RDAP record adds nothing the findings read, and captures show it
// lagging or lossy: GoDaddy's record for 3pattifacebook.site lacked the
// registry's server hold and spelled locks without client/server. So the
// registrar is named from the registry's answer and not asked itself.

const rdapName = "rdap"

// RDAPReport is the registration status of the registered domain the
// probed name belongs to.
type RDAPReport struct {
	// Domain is the name asked about: the registered domain, which is the
	// probed name itself or the domain enclosing it (google.com for
	// www.google.com).
	Domain string `json:"domain"`
	// Server is the RDAP base used for a name under a private suffix whose
	// operator runs its own service; absent when the IANA bootstrap chose.
	Server string `json:"server,omitempty"`
	// Registered is true when the registry returned the domain, false when
	// it answered that the domain does not exist, and null when the lookup
	// did not complete.
	Registered *bool          `json:"registered"`
	Registry   RDAPRegistry   `json:"registry"`
	Registrar  *RDAPRegistrar `json:"registrar,omitempty"`
}

// RDAPRegistry is the registry's answer.
type RDAPRegistry struct {
	// URL is the domain's RDAP URL at the registry (its self link).
	URL string `json:"url,omitempty"`
	// Status is the registry's status values as served ("client hold");
	// [] when it served none, null when the lookup did not complete.
	Status []string `json:"status"`
	Error  string   `json:"error,omitempty"`
}

// RDAPRegistrar is the sponsoring registrar as the registry names it.
type RDAPRegistrar struct {
	Name   string `json:"name,omitempty"`
	IANAID string `json:"iana_id,omitempty"`
}

// rdapDomain is the part of an RFC 9083 domain object the check reads.
type rdapDomain struct {
	Status   []string     `json:"status"`
	Links    []rdapLink   `json:"links"`
	Entities []rdapEntity `json:"entities"`
}

type rdapLink struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

type rdapEntity struct {
	Roles     []string          `json:"roles"`
	PublicIDs []rdapPublicID    `json:"publicIds"`
	VCard     []json.RawMessage `json:"vcardArray"`
}

type rdapPublicID struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

// rdapNotFound is the CLI's message when the registry answers 404.
const rdapNotFound = "object does not exist"

// findRDAP locates the rdap binary. An explicit path that is not an
// executable is a usage error; with none given, a missing binary leaves the
// path empty and the report says the lookup could not run.
func findRDAP(explicit string) (string, error) {
	if explicit != "" {
		return requireTool(explicit, rdapName)
	}
	if p, err := exec.LookPath(rdapName); err == nil {
		return p, nil
	}
	return "", nil
}

// rdapTarget picks the name to ask about and, for a private suffix with its
// own RDAP service, the server. It returns false for a name with no
// registration to look up: a reserved name, a public suffix.
func rdapTarget(domain string) (query, server string, ok bool) {
	if reservedName(domain) != "" {
		return "", "", false
	}
	if base, routed := psl.RDAPServer(domain); routed {
		if r := psl.Lookup(domain, true); r.Registrable != "" {
			return r.Registrable, base, true
		}
	}
	r := psl.Lookup(domain, false)
	if r.Registrable == "" {
		return "", "", false
	}
	return r.Registrable, "", true
}

// rdapArgs builds argv for the lookup of query.
func rdapArgs(query, server string, timeoutSec int) []string {
	args := []string{"--json", "--timeout", strconv.Itoa(maxInt(1, timeoutSec))}
	if server != "" {
		args = append(args, "-s", server)
	}
	return append(args, "--", query)
}

// checkRDAP looks the domain up at its registry. It returns nil when there
// is nothing to look up.
func checkRDAP(ctx context.Context, cfg config, r Runner) *RDAPReport {
	query, server, ok := rdapTarget(cfg.Domain)
	if !ok {
		return nil
	}
	rep := &RDAPReport{Domain: query, Server: server}
	if cfg.RDAPPath == "" {
		rep.Registry.Error = "rdap not found on PATH"
		return rep
	}
	obj, errText := runRDAP(ctx, cfg, r, query, server)
	if errText != "" {
		rep.Registry.Error = errText
		if strings.Contains(errText, rdapNotFound) {
			rep.Registered = boolPtr(false)
		}
		return rep
	}
	rep.Registered = boolPtr(true)
	rep.Registry = RDAPRegistry{URL: linkHref(obj.Links, "self"), Status: nonNil(obj.Status)}
	rep.Registrar = registrarNamed(obj.Entities)
	return rep
}

// registrarNamed is the registrar entity of the registry's answer, nil when
// it names none.
func registrarNamed(es []rdapEntity) *RDAPRegistrar {
	e := registrarEntity(es)
	if e == nil {
		return nil
	}
	reg := &RDAPRegistrar{Name: vcardName(e.VCard), IANAID: ianaID(e.PublicIDs)}
	if reg.Name == "" && reg.IANAID == "" {
		return nil
	}
	return reg
}

// runRDAP runs one lookup and decodes the domain object it prints. On
// failure it returns the CLI's own message.
func runRDAP(ctx context.Context, cfg config, r Runner, query, server string) (rdapDomain, string) {
	// The CLI enforces --timeout itself; the context is the kill switch for
	// a CLI that does not return.
	cctx, cancel := context.WithTimeout(ctx, cfg.timeout()+time.Second)
	defer cancel()
	stdout, stderr, err := r.Run(cctx, cfg.RDAPPath, rdapArgs(query, server, cfg.TimeoutSec)...)
	if isTimeout(cctx, err) {
		return rdapDomain{}, "rdap timed out"
	}
	if err != nil {
		return rdapDomain{}, "rdap: " + rdapMessage(stderr, err)
	}
	return parseRDAP(stdout)
}

// rdapMessage is the CLI's error line without its "# Error: " prefix, or
// the process error when it printed nothing.
func rdapMessage(stderr []byte, err error) string {
	for _, line := range strings.Split(string(stderr), "\n") {
		if msg := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "# Error:")); msg != "" {
			return msg
		}
	}
	return err.Error()
}

// parseRDAP decodes the CLI's --json output: one RDAP object.
func parseRDAP(out []byte) (rdapDomain, string) {
	text := strings.TrimSpace(string(out))
	if text == "" {
		return rdapDomain{}, "rdap produced no output"
	}
	var d rdapDomain
	if !strings.HasPrefix(text, "{") {
		return rdapDomain{}, "rdap output not a JSON object: " + firstLine(text)
	}
	if err := json.Unmarshal([]byte(text), &d); err != nil {
		return rdapDomain{}, "rdap output not an RDAP object: " + err.Error()
	}
	return d, ""
}

// linkHref returns the href of the first RDAP link with rel.
func linkHref(links []rdapLink, rel string) string {
	for _, l := range links {
		if strings.EqualFold(l.Rel, rel) && l.Href != "" {
			return l.Href
		}
	}
	return ""
}

func registrarEntity(es []rdapEntity) *rdapEntity {
	for i := range es {
		for _, role := range es[i].Roles {
			if strings.EqualFold(role, "registrar") {
				return &es[i]
			}
		}
	}
	return nil
}

func ianaID(ids []rdapPublicID) string {
	for _, id := range ids {
		if strings.EqualFold(id.Type, "IANA Registrar ID") {
			return strings.TrimSpace(id.Identifier)
		}
	}
	return ""
}

// vcardName returns the fn property of a jCard (RFC 7095):
// ["vcard", [["fn", {}, "text", "Name"], ...]].
func vcardName(card []json.RawMessage) string {
	if len(card) < 2 {
		return ""
	}
	var props [][]json.RawMessage
	if err := json.Unmarshal(card[1], &props); err != nil {
		return ""
	}
	for _, p := range props {
		var name, value string
		if len(p) < 4 || json.Unmarshal(p[0], &name) != nil || name != "fn" {
			continue
		}
		if json.Unmarshal(p[3], &value) == nil {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// statusKey folds an RDAP status ("client hold", RFC 8056) and its EPP
// form ("clientHold") to one key, so a registrar serving either matches.
func statusKey(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '_' || r == '-' {
			return -1
		}
		return r
	}, strings.ToLower(strings.TrimSpace(s)))
}

// Status values the findings act on, by statusKey.
var (
	rdapHoldStatus = map[string]bool{"clienthold": true, "serverhold": true}
	// A domain in these states is leaving the registry: deleted and in its
	// grace period, scheduled for purge, or being restored from deletion.
	// inactive is not among them: it says only that the domain has no
	// delegation, which Nominet serves for www.gov.uk, a name inside the
	// gov.uk zone that is registered but never delegated.
	rdapDeletionStatus = map[string]bool{"redemptionperiod": true, "pendingdelete": true, "pendingrestore": true}
)

// matchedStatuses lists the registry's statuses in set, as served and in
// the order served.
func matchedStatuses(rep *RDAPReport, set map[string]bool) []string {
	var out []string
	for _, s := range rep.Registry.Status {
		if set[statusKey(s)] {
			out = append(out, s)
		}
	}
	return out
}
