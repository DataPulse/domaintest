package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"os"
	"testing"
)

func loadChain(t *testing.T, name string) []*x509.Certificate {
	t.Helper()
	b, err := os.ReadFile("testdata/certs/" + name + ".pem")
	if err != nil {
		t.Fatal(err)
	}
	certs, err := parsePEMCerts(b)
	if err != nil {
		t.Fatal(err)
	}
	return certs
}

func TestParseTLSA(t *testing.T) {
	l := parseDelvYAML(fixture(t, "tlsa/www_huque_com.yaml"), "TLSA")
	recs := parseTLSARecords(l.Records)
	check(t, "four records", len(recs), 4)
	for _, r := range recs {
		check(t, "usage 3", r.Usage, 3)
		check(t, "selector 1", r.Selector, 1)
		check(t, "matching 1", r.Matching, 1)
		check(t, "sha256 length", len(r.Data), 32)
	}
	for _, bad := range []string{"", "3 1", "4 1 1 aa", "3 2 1 aa", "3 1 3 aa", "3 1 1 zz", "3 1 1"} {
		if _, ok := parseTLSA(bad); ok {
			t.Errorf("parseTLSA(%q) should fail", bad)
		}
	}
	// Hex with embedded spaces, as delv prints it.
	rec, ok := parseTLSA("3 1 1 0D2280AA14C34B9FD76607135B16FB165A0059F6E47F455814DD8617 6BBC3FDF")
	check(t, "spaced hex ok", ok, true)
	check(t, "spaced hex bytes", len(rec.Data), 32)
}

func TestMatchTLSA_LiveChains(t *testing.T) {
	cases := []struct{ host, fixture, pem string }{
		{"www.huque.com", "tlsa/www_huque_com.yaml", "www_huque_com"},
		{"torproject.org", "tlsa/torproject_org.yaml", "torproject_org"},
		{"fedoraproject.org", "tlsa/fedoraproject_org.yaml", "fedoraproject_org"},
	}
	for _, c := range cases {
		t.Run(c.host, func(t *testing.T) {
			chain := loadChain(t, c.pem)
			recs := parseTLSARecords(parseDelvYAML(fixture(t, c.fixture), "TLSA").Records)
			check(t, "matches served chain", matchTLSA(recs, chain, false), TLSAMatch)
			check(t, "mismatch against another chain", matchTLSA(recs, loadChain(t, "www_torproject_org"), false), TLSAMismatch)
		})
	}
	check(t, "no records", matchTLSA(nil, loadChain(t, "www_huque_com"), true), TLSANone)
}

func TestTLSAMatches_UsagesSelectorsMatching(t *testing.T) {
	ca := newTestCA(t, "TLSA test CA")
	inter, _ := ca.issue(t, certSpec{sans: []string{"Intermediate"}, issuer: ca, isCA: true})
	leaf, _ := ca.issue(t, certSpec{sans: []string{"example.test"}, issuer: ca})
	chain := []*x509.Certificate{leaf, inter}

	digest := func(c *x509.Certificate, sel, match int) []byte { return tlsaDigest(c, sel, match) }
	check(t, "selector 0 matching 0 is raw cert", digest(leaf, 0, 0), leaf.Raw)
	s256 := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	check(t, "selector 1 matching 1", digest(leaf, 1, 1), s256[:])
	s512 := sha512.Sum512(leaf.Raw)
	check(t, "selector 0 matching 2", digest(leaf, 0, 2), s512[:])

	rec := func(usage, sel, match int, c *x509.Certificate) tlsaRecord {
		return tlsaRecord{Usage: usage, Selector: sel, Matching: match, Data: digest(c, sel, match)}
	}
	check(t, "DANE-EE leaf", tlsaMatches(rec(3, 1, 1, leaf), chain, false), true)
	check(t, "DANE-EE does not accept the intermediate", tlsaMatches(rec(3, 1, 1, inter), chain, false), false)
	check(t, "DANE-TA any chain cert", tlsaMatches(rec(2, 0, 1, inter), chain, false), true)
	check(t, "PKIX-EE needs PKIX validity", tlsaMatches(rec(1, 1, 1, leaf), chain, false), false)
	check(t, "PKIX-EE with valid chain", tlsaMatches(rec(1, 1, 1, leaf), chain, true), true)
	check(t, "PKIX-TA with valid chain", tlsaMatches(rec(0, 0, 2, inter), chain, true), true)
	check(t, "PKIX-TA without validity", tlsaMatches(rec(0, 0, 2, inter), chain, false), false)
	check(t, "empty chain", tlsaMatches(rec(3, 1, 1, leaf), nil, true), false)
	check(t, "wrong data", tlsaMatches(tlsaRecord{Usage: 3, Selector: 1, Matching: 1, Data: []byte{1, 2, 3}}, chain, true), false)
	_ = hex.EncodeToString
}

// A TLSA lookup that never answered is not a domain without DANE, and the
// signed flag must not claim a validated denial we never received.
func TestAssessTLSA_UnansweredIsNotAbsence(t *testing.T) {
	web := WebSection{}
	unk := assessTLSA(Lookup{Status: StatusTimeout}, Lookup{Status: StatusTimeout}, web)
	check(t, "unknown, not none", unk.Result, TLSAUnknown)
	check(t, "no validated denial claimed", unk.Signed, false)

	// A signed zone denying the records is a real, useful absence.
	denied := Lookup{Status: StatusNXRRSet, Trust: TrustSecure}
	none := assessTLSA(denied, denied, web)
	check(t, "absence observed", none.Result, TLSANone)
	check(t, "and it was validated", none.Signed, true)
}
