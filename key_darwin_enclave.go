//go:build darwin && !kpsoftkey

package main

// Fall back to the file-based keychain to test locally without keychain access entitlements (which need a real developer certificate).

// #cgo CFLAGS: -DKP_SECURE_ENCLAVE
import "C"

const backendName = "Secure Enclave"
