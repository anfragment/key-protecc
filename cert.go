package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- SHA-1 is the standard for X.509 SubjectKeyId.
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

const orgName = "key-protecc"

// runCertTest tests the signer the way Zen does:
// 1. Builds a self-signed root CA whose private key is the TPM-backed signer
// 2. Issues a leaf certificate signed by that root
// 3. Cryptographically verifies the leaf against the root.
// A bad TPM signature comes up as a verification error.
func runCertTest(signer crypto.Signer) error {
	rootCert, err := createRootCert(signer)
	if err != nil {
		return fmt.Errorf("create root certificate: %w", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate leaf key: %w", err)
	}

	leafCert, err := createLeafCert(signer, rootCert, &leafKey.PublicKey)
	if err != nil {
		return fmt.Errorf("create leaf certificate: %w", err)
	}

	// Direct check: the leaf's signature is valid under the root's public key, and the root is
	// a usable CA (IsCA + KeyUsageCertSign).
	if err := leafCert.CheckSignatureFrom(rootCert); err != nil {
		return fmt.Errorf("leaf signature check: %w", err)
	}

	// Full chain build through the standard verifier.
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	if _, err := leafCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "example.net",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("verify leaf chain: %w", err)
	}

	return nil
}

// createRootCert builds a self-signed CA certificate signed by signer (whose private key lives
// in the TPM). Mirrors the root template used in Zen's diskcertstore.
func createRootCert(signer crypto.Signer) (*x509.Certificate, error) {
	serialNumber, err := randomSerial()
	if err != nil {
		return nil, err
	}

	skid, err := subjectKeyID(signer.Public())
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{orgName},
			CommonName:   orgName + " Root",
		},
		SubjectKeyId: skid,

		NotBefore: now,
		NotAfter:  now.Add(7 * 24 * time.Hour),

		KeyUsage: x509.KeyUsageCertSign,

		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	return x509.ParseCertificate(der)
}

// createLeafCert builds a leaf certificate for leafPub, signed by the root.
// Mirrors the leaf template used in Zen's certgen.
func createLeafCert(signer crypto.Signer, rootCert *x509.Certificate, leafPub crypto.PublicKey) (*x509.Certificate, error) {
	serialNumber, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{orgName},
		},
		NotBefore: now,
		NotAfter:  now.Add(24 * time.Hour),

		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,
		DNSNames:              []string{"example.net"},
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, rootCert, leafPub, signer)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	return x509.ParseCertificate(der)
}

// randomSerial returns a random 128-bit certificate serial number.
func randomSerial() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	return serialNumber, nil
}

func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	spkiASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spkiASN1, &spki); err != nil {
		return nil, fmt.Errorf("unmarshal public key: %w", err)
	}

	skid := sha1.Sum(spki.SubjectPublicKey.Bytes) // #nosec G401 -- SubjectKeyId uses SHA-1 by convention.
	return skid[:], nil
}
