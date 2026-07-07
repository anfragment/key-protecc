package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"testing"

	"github.com/google/uuid"
)

// newBenchSigner creates a throwaway hardware-backed key for the duration of the benchmark.
// Key creation and deletion happen outside the timed loop.
func newBenchSigner(b *testing.B) signCloser {
	name := uuid.NewString()
	signer, err := createKey(name)
	if err != nil {
		b.Fatalf("create key: %v", err)
	}
	b.Cleanup(func() {
		signer.Close()
		if err := deleteKey(name); err != nil {
			log.Printf("warning: delete throwaway key %q: %v", name, err)
		}
	})
	return signer
}

func BenchmarkCreateRootCert(b *testing.B) {
	signer := newBenchSigner(b)

	for b.Loop() {
		if _, err := createRootCert(signer); err != nil {
			b.Fatalf("create root certificate: %v", err)
		}
	}
}

func BenchmarkCreateLeafCert(b *testing.B) {
	signer := newBenchSigner(b)

	rootCert, err := createRootCert(signer)
	if err != nil {
		b.Fatalf("create root certificate: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("generate leaf key: %v", err)
	}

	for b.Loop() {
		if _, err := createLeafCert(signer, rootCert, &leafKey.PublicKey); err != nil {
			b.Fatalf("create leaf certificate: %v", err)
		}
	}
}
