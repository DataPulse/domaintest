package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"strconv"
	"strings"
)

// TLSA outcomes per address.
const (
	TLSANone     = "none"
	TLSAMatch    = "match"
	TLSAMismatch = "mismatch"
)

// tlsaRecord is a parsed TLSA RR (RFC 6698).
type tlsaRecord struct {
	Usage    int // 0 PKIX-TA, 1 PKIX-EE, 2 DANE-TA, 3 DANE-EE
	Selector int // 0 full certificate, 1 SubjectPublicKeyInfo
	Matching int // 0 exact, 1 SHA-256, 2 SHA-512
	Data     []byte
}

// parseTLSA parses rdata "3 1 1 <hex...>" (hex may contain spaces).
func parseTLSA(rdata string) (tlsaRecord, bool) {
	f := strings.Fields(rdata)
	if len(f) < 4 {
		return tlsaRecord{}, false
	}
	var rec tlsaRecord
	var err error
	if rec.Usage, err = strconv.Atoi(f[0]); err != nil || rec.Usage > 3 {
		return tlsaRecord{}, false
	}
	if rec.Selector, err = strconv.Atoi(f[1]); err != nil || rec.Selector > 1 {
		return tlsaRecord{}, false
	}
	if rec.Matching, err = strconv.Atoi(f[2]); err != nil || rec.Matching > 2 {
		return tlsaRecord{}, false
	}
	if rec.Data, err = hex.DecodeString(strings.Join(f[3:], "")); err != nil || len(rec.Data) == 0 {
		return tlsaRecord{}, false
	}
	return rec, true
}

func parseTLSARecords(records []string) []tlsaRecord {
	var out []tlsaRecord
	for _, r := range records {
		if rec, ok := parseTLSA(r); ok {
			out = append(out, rec)
		}
	}
	return out
}

// tlsaDigest applies selector and matching type to a certificate.
func tlsaDigest(c *x509.Certificate, selector, matching int) []byte {
	data := c.Raw
	if selector == 1 {
		data = c.RawSubjectPublicKeyInfo
	}
	switch matching {
	case 1:
		s := sha256.Sum256(data)
		return s[:]
	case 2:
		s := sha512.Sum512(data)
		return s[:]
	default:
		return data
	}
}

// tlsaMatches reports whether one record is satisfied by the served chain.
// pkixValid is required for usages 0 and 1, which also demand PKIX
// validation.
func tlsaMatches(rec tlsaRecord, chain []*x509.Certificate, pkixValid bool) bool {
	if len(chain) == 0 {
		return false
	}
	if (rec.Usage == 0 || rec.Usage == 1) && !pkixValid {
		return false
	}
	candidates := chain[:1] // end-entity usages
	if rec.Usage == 0 || rec.Usage == 2 {
		candidates = chain // trust-anchor usages: any cert in the chain
	}
	for _, c := range candidates {
		if bytes.Equal(tlsaDigest(c, rec.Selector, rec.Matching), rec.Data) {
			return true
		}
	}
	return false
}

// matchTLSA returns match when any record matches the chain, mismatch
// otherwise, and none when there are no records.
func matchTLSA(records []tlsaRecord, chain []*x509.Certificate, pkixValid bool) string {
	if len(records) == 0 {
		return TLSANone
	}
	for _, rec := range records {
		if tlsaMatches(rec, chain, pkixValid) {
			return TLSAMatch
		}
	}
	return TLSAMismatch
}
