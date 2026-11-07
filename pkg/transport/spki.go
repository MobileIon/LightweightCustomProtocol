package transport

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
)

var (
	ErrNoPeerCertificates = errors.New("lcp: peer presented no certificates")
	ErrSPKIPinningFailed  = errors.New("lcp: peer certificate public key does not match any pinned SPKI hash")
)

// ComputeSPKIHash computes the SHA-256 hash of a certificate's ASN.1 SubjectPublicKeyInfo (SPKI).
func ComputeSPKIHash(cert *x509.Certificate) [32]byte {
	return sha256.Sum256(cert.RawSubjectPublicKeyInfo)
}

// ComputeSPKIHex returns the uppercase hexadecimal representation of the SPKI SHA-256 hash.
func ComputeSPKIHex(cert *x509.Certificate) string {
	h := ComputeSPKIHash(cert)
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

// ValidateSPKIPinning verifies that the peer's leaf certificate matches at least one pinned SPKI hash.
// This allows bypassing expired/mismatched Web PKI domain checks in disaster recovery mode (855) while
// cryptographically guaranteeing 100% protection against MITM attacks.
func ValidateSPKIPinning(rawCerts [][]byte, pinnedHexHashes []string) error {
	if len(rawCerts) == 0 {
		return ErrNoPeerCertificates
	}

	leafCert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}

	actualHex := ComputeSPKIHex(leafCert)
	for _, expected := range pinnedHexHashes {
		if strings.EqualFold(actualHex, expected) {
			return nil
		}
	}

	return ErrSPKIPinningFailed
}
