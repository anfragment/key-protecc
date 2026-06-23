package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <stdlib.h>
#include "keychain_darwin.h"
*/
import "C"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"io"
	"unsafe"
)

// errBufLen is the size of the buffer handed to the C layer for error messages.
const errBufLen = 256

// enclaveSigner is a crypto.Signer backed by a Secure Enclave ECDSA P-256 key.
// It mirrors the Windows tpmSigner: Public returns the cached public key, Sign produces
// an ASN.1 DER ECDSA signature, and Close releases the underlying SecKeyRef. The private
// key reference is held as an opaque pointer because the C layer hides SecKeyRef.
type enclaveSigner struct {
	priv unsafe.Pointer // SecKeyRef
	pub  *ecdsa.PublicKey
}

// createKey creates a new permanent Secure Enclave key tagged with name and returns a
// signer backed by it. On any failure after the key is persisted the key is deleted so
// no orphaned enclave item is left behind.
func createKey(name string) (signCloser, error) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	errBuf := make([]byte, errBufLen)

	// Fail on a pre-existing name instead of silently creating a second key. The keychain
	// enforces uniqueness on the public-key label, not the application tag (the name), so
	// two keys could otherwise share a name - loadKey would then return an arbitrary one
	// and deleteKey would remove all of them. This mirrors the Windows backend, where
	// NCryptCreatePersistedKey fails with NTE_EXISTS on a duplicate name.
	var existing unsafe.Pointer
	if C.kp_load_key(cName, C.size_t(len(name)), &existing,
		(*C.char)(unsafe.Pointer(&errBuf[0])), C.size_t(errBufLen)) == 0 {
		C.kp_release(existing)
		return nil, fmt.Errorf("create persisted key: key %q already exists", name)
	}

	var priv unsafe.Pointer
	ret := C.kp_create_key(cName, C.size_t(len(name)), &priv,
		(*C.char)(unsafe.Pointer(&errBuf[0])), C.size_t(errBufLen))
	if ret != 0 {
		return nil, fmt.Errorf("create persisted key: %s", secError(ret, errBuf))
	}

	// On any error the persisted key must be released and removed. On success the
	// returned signer owns the reference and releases it via Close.
	var success bool
	defer func() {
		if !success {
			C.kp_release(priv)
			delBuf := make([]byte, errBufLen)
			C.kp_delete_key(cName, C.size_t(len(name)),
				(*C.char)(unsafe.Pointer(&delBuf[0])), C.size_t(errBufLen))
		}
	}()

	pub, err := copyPublicKey(priv)
	if err != nil {
		return nil, err
	}

	success = true
	return &enclaveSigner{priv: priv, pub: pub}, nil
}

// loadKey opens a previously created key by name and returns a signer backed by it.
func loadKey(name string) (signCloser, error) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	errBuf := make([]byte, errBufLen)
	var priv unsafe.Pointer

	ret := C.kp_load_key(cName, C.size_t(len(name)), &priv,
		(*C.char)(unsafe.Pointer(&errBuf[0])), C.size_t(errBufLen))
	if ret != 0 {
		return nil, fmt.Errorf("open key: %s", secError(ret, errBuf))
	}

	var success bool
	defer func() {
		if !success {
			C.kp_release(priv)
		}
	}()

	pub, err := copyPublicKey(priv)
	if err != nil {
		return nil, err
	}

	success = true
	return &enclaveSigner{priv: priv, pub: pub}, nil
}

// deleteKey permanently removes the key identified by name from the keychain.
func deleteKey(name string) error {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	errBuf := make([]byte, errBufLen)
	ret := C.kp_delete_key(cName, C.size_t(len(name)),
		(*C.char)(unsafe.Pointer(&errBuf[0])), C.size_t(errBufLen))
	if ret != 0 {
		return fmt.Errorf("delete key: %s", secError(ret, errBuf))
	}
	return nil
}

// copyPublicKey exports and parses the public key of a private key reference.
func copyPublicKey(priv unsafe.Pointer) (*ecdsa.PublicKey, error) {
	errBuf := make([]byte, errBufLen)
	var buf *C.uint8_t
	var n C.size_t

	ret := C.kp_copy_public_key(priv, &buf, &n,
		(*C.char)(unsafe.Pointer(&errBuf[0])), C.size_t(errBufLen))
	if ret != 0 {
		return nil, fmt.Errorf("copy public key: %s", secError(ret, errBuf))
	}
	defer C.free(unsafe.Pointer(buf))

	raw := C.GoBytes(unsafe.Pointer(buf), C.int(n))
	return parseECPublicKey(raw)
}

// parseECPublicKey parses an ANSI X9.63 uncompressed point (0x04 || X || Y) into an
// ecdsa.PublicKey on the P-256 curve, the format SecKeyCopyExternalRepresentation emits.
func parseECPublicKey(raw []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), raw) //nolint:staticcheck // SA1019: X9.63 point, no PKIX wrapper.
	if x == nil {
		return nil, fmt.Errorf("parse EC public key: invalid X9.63 point (%d bytes)", len(raw))
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

func (s *enclaveSigner) Public() crypto.PublicKey {
	return s.pub
}

// Sign implements crypto.Signer using ECDSA over the Secure Enclave key.
func (s *enclaveSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.priv == nil {
		return nil, fmt.Errorf("enclaveSigner: signer is closed")
	}
	if _, ok := opts.(*rsa.PSSOptions); ok {
		return nil, fmt.Errorf("enclaveSigner: RSA-PSS is not supported")
	}

	var hash C.int
	switch opts.HashFunc() {
	case crypto.SHA256:
		hash = 256
	case crypto.SHA384:
		hash = 384
	case crypto.SHA512:
		hash = 512
	default:
		return nil, fmt.Errorf("enclaveSigner: unsupported hash %v", opts.HashFunc())
	}

	if len(digest) == 0 {
		return nil, fmt.Errorf("enclaveSigner: empty digest")
	}

	errBuf := make([]byte, errBufLen)
	var sig *C.uint8_t
	var n C.size_t

	ret := C.kp_sign(s.priv, hash,
		(*C.uint8_t)(unsafe.Pointer(&digest[0])), C.size_t(len(digest)),
		&sig, &n,
		(*C.char)(unsafe.Pointer(&errBuf[0])), C.size_t(errBufLen))
	if ret != 0 {
		return nil, fmt.Errorf("sign: %s", secError(ret, errBuf))
	}
	defer C.free(unsafe.Pointer(sig))

	return C.GoBytes(unsafe.Pointer(sig), C.int(n)), nil
}

func (s *enclaveSigner) Close() error {
	if s.priv != nil {
		C.kp_release(s.priv)
		s.priv = nil
	}
	return nil
}

// secError renders a C helper return code plus its error buffer into a readable string,
// naming common OSStatus values from the Security framework.
func secError(ret C.int, errBuf []byte) string {
	msg := cString(errBuf)
	code := int(ret)
	name := secStatusName(code)

	switch {
	case msg != "" && name != "":
		return fmt.Sprintf("%s (%d %s)", msg, code, name)
	case name != "":
		return fmt.Sprintf("%d %s", code, name)
	case msg != "":
		return fmt.Sprintf("%s (status %d)", msg, code)
	default:
		return fmt.Sprintf("status %d", code)
	}
}

// secStatusName maps a few OSStatus codes the backend is likely to surface to their
// symbolic names; returns "" for anything else.
func secStatusName(code int) string {
	switch code {
	case -25291:
		return "errSecNotAvailable"
	case -25299:
		return "errSecDuplicateItem"
	case -25300:
		return "errSecItemNotFound"
	case -34018:
		return "errSecMissingEntitlement"
	case -128:
		return "errSecUserCanceled"
	case -50:
		return "errSecParam"
	default:
		return ""
	}
}

// cString returns the NUL-terminated prefix of a C-filled byte buffer as a Go string.
func cString(buf []byte) string {
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}
