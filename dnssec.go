package main

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// DNSSECState summarises the zone's DNSSEC posture.
type DNSSECState string

const (
	DNSSECSecure   DNSSECState = "secure"   // DS at parent, DNSKEY in zone, answers validate
	DNSSECInsecure DNSSECState = "insecure" // unsigned zone, no DS
	DNSSECIsland   DNSSECState = "island"   // DNSKEY present but no DS at parent
	DNSSECBogus    DNSSECState = "bogus"    // validation fails although data exists
	DNSSECServfail DNSSECState = "servfail" // resolver failed and no data even with CD
	DNSSECUnknown  DNSSECState = "unknown"  // lookups timed out
	// DNSSECNonexistent: the name is NXDOMAIN, so there is no zone to be
	// signed or unsigned. Detail says whether the denial itself validated.
	DNSSECNonexistent DNSSECState = "nonexistent"
)

// DNSSECReport is the dnssec section of the JSON report.
type DNSSECReport struct {
	State  DNSSECState `json:"state"`
	DS     bool        `json:"ds"`
	DNSKEY bool        `json:"dnskey"`
	EDE    string      `json:"ede,omitempty"`
	Detail string      `json:"detail,omitempty"`
}

// bogusProbe is the callback used when a lookup failed. It returns
// whether the data exists when checking is disabled (dig +cd) and any
// Extended DNS Error text from a validating query.
type bogusProbe func(name, qtype string) (hasData bool, ede string)

// classifyDNSSEC derives the DNSSEC state from the DS and DNSKEY lookups and
// the apex record lookups. failed is the first apex lookup that ended in
// StatusFailure (or nil).
func classifyDNSSEC(ds, dnskey Lookup, apex map[string]Lookup, probe bogusProbe) DNSSECReport {
	rep := DNSSECReport{DS: ds.HasRecords(), DNSKEY: dnskey.HasRecords()}
	if failed := firstFailed(ds, dnskey, apex); failed != nil {
		if failed.unqueryable {
			rep.State, rep.Detail = DNSSECUnknown, failed.Error
			return rep
		}
		return classifyFailure(rep, *failed, probe, unsignedDelegation(ds))
	}
	if !ds.Answered() || !dnskey.Answered() {
		rep.State = DNSSECUnknown
		rep.Detail = "DS or DNSKEY lookup did not complete"
		return rep
	}
	if nameDoesNotExist(apex) {
		nonexistentState(&rep, ds)
		return rep
	}
	switch {
	case rep.DS && rep.DNSKEY:
		signedState(&rep, dnskey.Trust)
	case rep.DNSKEY:
		rep.State = DNSSECIsland
		rep.Detail = "zone publishes DNSKEY but parent has no DS"
	case rep.DS:
		rep.State = DNSSECBogus
		rep.Detail = "parent has DS but zone publishes no DNSKEY"
	default:
		rep.State = DNSSECInsecure
	}
	return rep
}

// nonexistentState reports a name that does not exist. "insecure" read as a
// verdict on a zone that is not there, beside a TLSA section whose validated
// denial said signed: true (tester, 2026-10-06). The DS lookup carries the
// parent's denial; its trust, the resolver's AD bit (confirmNegativeTrust),
// says whether that denial validated. An NSEC3 opt-out denial (every missing
// .com, .net or .org name) proves nothing and does not.
func nonexistentState(rep *DNSSECReport, ds Lookup) {
	rep.State = DNSSECNonexistent
	if ds.Trust == TrustSecure {
		rep.Detail = "the name does not exist (NXDOMAIN); the parent's denial of existence was DNSSEC-validated"
		return
	}
	rep.Detail = "the name does not exist (NXDOMAIN); the parent's denial of existence was not validated"
}

// nameDoesNotExist reports an apex the resolver answered NXDOMAIN for.
func nameDoesNotExist(apex map[string]Lookup) bool {
	return apex["NS"].Status == StatusNXDomain || apex["A"].Status == StatusNXDomain
}

// signedState judges a zone that publishes DS and DNSKEY by whether the
// validator actually validated its keys. Both can be present and the zone
// still not be secure: a DS whose algorithm or digest the validator does
// not support makes it treat the zone as unsigned (RFC 4035 §5.2).
func signedState(rep *DNSSECReport, trust Trust) {
	switch trust {
	case TrustSecure:
		rep.State = DNSSECSecure
	case TrustInsecure:
		rep.State = DNSSECInsecure
		rep.Detail = "DS and DNSKEY are published, but the validator treated the zone as unsigned"
	default:
		rep.State = DNSSECUnknown
		rep.Detail = "DS and DNSKEY are published, but the validator reported no validation status for the DNSKEY answer"
	}
}

// classifyByTrust derives a state from the validation status of the
// answers alone, for names that are not zone apexes and so have no DS or
// DNSKEY of their own.
func classifyByTrust(apex map[string]Lookup) DNSSECReport {
	rep := DNSSECReport{Detail: "not a zone apex; state taken from answer validation"}
	secure, insecure := 0, 0
	for _, l := range apex {
		switch {
		case !l.Answered():
		case l.Trust == TrustSecure:
			secure++
		case l.Trust == TrustInsecure:
			insecure++
		}
	}
	switch {
	case insecure > 0:
		rep.State = DNSSECInsecure
	case secure > 0:
		rep.State = DNSSECSecure
	default:
		rep.State = DNSSECUnknown
	}
	return rep
}

func firstFailed(ds, dnskey Lookup, apex map[string]Lookup) *Lookup {
	for _, qtype := range apexTypes {
		if l, ok := apex[qtype]; ok && l.Status == StatusFailure {
			return &l
		}
	}
	for _, l := range []Lookup{ds, dnskey} {
		if l.Status == StatusFailure {
			return &l
		}
	}
	return nil
}

// unsignedDelegation reports a DS lookup the parent answered with no DS:
// nothing in the zone is ever validated, so no failure in it can be a
// validation failure.
func unsignedDelegation(ds Lookup) bool {
	return ds.Status == StatusNXRRSet
}

// classifyFailure judges a failed lookup. "Fails, but answers with checking
// disabled" means bogus only in a signed zone: in an unsigned one it is a
// server that failed once and answered the retry. jd.com (2026-10-07) had
// its MX lookup SERVFAIL on a slow nameserver, the +cd re-query answered,
// and the unsigned zone was reported bogus.
func classifyFailure(rep DNSSECReport, failed Lookup, probe bogusProbe, unsigned bool) DNSSECReport {
	if probe == nil {
		rep.State = DNSSECServfail
		rep.Detail = failed.Error
		return rep
	}
	hasData, ede := probe(failed.Name, failed.Type)
	rep.EDE = ede
	if hasData && unsigned {
		rep.State = DNSSECServfail
		rep.Detail = "resolver failed, then answered with checking disabled; the zone is unsigned, so this is not a validation failure"
		return rep
	}
	if hasData {
		rep.State = DNSSECBogus
		rep.Detail = "resolver fails validation but data exists with checking disabled"
	} else {
		rep.State = DNSSECServfail
		rep.Detail = "resolver failed and returned no data even with checking disabled"
	}
	return rep
}

var (
	digStatusRe = regexp.MustCompile(`(?m)^\s*status:\s*(\S+)`)
	digAnswerRe = regexp.MustCompile(`(?m)^\s*ANSWER:\s*(\d+)`)
	digEDECode  = regexp.MustCompile(`(?m)^\s*INFO-CODE:\s*(.+?)\s*$`)
	digEDEText  = regexp.MustCompile(`(?m)^\s*EXTRA-TEXT:\s*"(.*)"\s*$`)
)

// digHasData parses `dig +yaml` output and reports whether the response was
// NOERROR with at least one answer record.
func digHasData(out string) bool {
	st := digStatusRe.FindStringSubmatch(out)
	an := digAnswerRe.FindStringSubmatch(out)
	if st == nil || an == nil || st[1] != "NOERROR" {
		return false
	}
	n, err := strconv.Atoi(an[1])
	return err == nil && n > 0
}

// digEDE extracts "code (name): text" from the EDE option in `dig +yaml`
// output, or "" when absent.
func digEDE(out string) string {
	code := digEDECode.FindStringSubmatch(out)
	if code == nil {
		return ""
	}
	if text := digEDEText.FindStringSubmatch(out); text != nil && text[1] != "" {
		return code[1] + ": " + text[1]
	}
	return code[1]
}

// digArgs builds argv for a dig +yaml query with optional +cd.
func digArgs(res resolver, cd bool, timeoutSec int, name, qtype string) []string {
	args := []string{"+yaml", "+tries=1", "+time=" + strconv.Itoa(maxInt(1, timeoutSec))}
	if cd {
		args = append(args, "+cd")
	}
	args = append(args, res.args()...)
	return append(args, name, qtype)
}

// newBogusProbe returns a bogusProbe that runs dig twice: with +cd to see
// whether data exists, and without to harvest the EDE explanation.
func newBogusProbe(ctx context.Context, r Runner, digPath string, res resolver, timeoutSec int) bogusProbe {
	return func(name, qtype string) (bool, string) {
		cdOut, _, _ := r.Run(ctx, digPath, digArgs(res, true, timeoutSec, name, qtype)...)
		plainOut, _, _ := r.Run(ctx, digPath, digArgs(res, false, timeoutSec, name, qtype)...)
		return digHasData(string(cdOut)), strings.TrimSpace(digEDE(string(plainOut)))
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
