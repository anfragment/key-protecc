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

// BenchmarkCreateLeafCertParallel measures whether concurrent signing scales. Hardware
// backends fan every operation through a single device, so throughput may be flat no matter
// how many goroutines ask: run with -cpu=1,2,4,8,12 and compare ns/op. Flat ns/op across the
// list means the backend serialises, and a browser opening N connections to new hosts at once
// pays N times the single-op cost. This is the number that decides whether an in-memory
// intermediate CA is worth the key-exposure trade.
func BenchmarkCreateLeafCertParallel(b *testing.B) {
	signer := newBenchSigner(b)

	rootCert, err := createRootCert(signer)
	if err != nil {
		b.Fatalf("create root certificate: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("generate leaf key: %v", err)
	}

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// b.Error, not b.Fatal: Fatal calls Goexit, which would only unwind this
			// goroutine and leave the benchmark hanging.
			if _, err := createLeafCert(signer, rootCert, &leafKey.PublicKey); err != nil {
				b.Errorf("create leaf certificate: %v", err)
				return
			}
		}
	})
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
