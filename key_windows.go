package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"unsafe"

	"golang.org/x/sys/windows"
)

const backendName = "TPM (Microsoft Platform Crypto Provider)"

const (
	msKeyStorageProvider     = "Microsoft Software Key Storage Provider"
	msPlatformCryptoProvider = "Microsoft Platform Crypto Provider"

	nCryptECDSAP256Algorithm   = "ECDSA_P256"
	bCryptECDSAP256PublicMagic = 0x31534345 // BCRYPT_ECDSA_PUBLIC_P256_MAGIC ("ECS1")
	bCryptECCPublicBlob        = "ECCPUBLICBLOB"

	nCryptKeyUsageProperty = "Key Usage"

	nCryptAllowSigningFlag = 0x00000002

	p256CoordinateLength = 32
)

type nCryptProvHandle uintptr
type nCryptKeyHandle uintptr

func createKey(name string) (signCloser, error) {
	hProv, err := openProvider()
	if err != nil {
		return nil, err
	}
	// On any error both handles must be freed. On success they stay alive because the
	// returned signer owns them and releases them via Close.
	var success bool
	defer func() {
		if !success {
			nCryptFreeObject(uintptr(hProv))
		}
	}()

	algId, err := windows.UTF16PtrFromString(nCryptECDSAP256Algorithm)
	if err != nil {
		return nil, fmt.Errorf("convert algorithm id: %w", err)
	}
	keyName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("convert key name: %w", err)
	}

	var hKey nCryptKeyHandle
	ret := nCryptCreatePersistedKey(hProv, &hKey, algId, keyName, 0, 0)
	if ret != 0 {
		return nil, fmt.Errorf("create persisted key: 0x%08x", ret)
	}
	defer func() {
		if !success {
			nCryptFreeObject(uintptr(hKey))
		}
	}()

	usage := uint32(nCryptAllowSigningFlag)
	usageProp, err := windows.UTF16PtrFromString(nCryptKeyUsageProperty)
	if err != nil {
		return nil, fmt.Errorf("convert key usage property: %w", err)
	}
	ret = nCryptSetProperty(hKey, usageProp,
		(*byte)(unsafe.Pointer(&usage)), uint32(unsafe.Sizeof(usage)), 0)
	if ret != 0 {
		return nil, fmt.Errorf("set key usage: 0x%08x", ret)
	}

	ret = nCryptFinalizeKey(hKey, 0)
	if ret != 0 {
		return nil, fmt.Errorf("finalize key: 0x%08x", ret)
	}

	pub, err := exportECCPublicKey(hKey)
	if err != nil {
		return nil, err
	}

	success = true
	return &tpmSigner{hProv: hProv, hKey: hKey, pub: pub}, nil
}

// loadKey opens a previously created persisted key by name and returns a signer backed by it.
func loadKey(name string) (signCloser, error) {
	hProv, err := openProvider()
	if err != nil {
		return nil, err
	}
	var success bool
	defer func() {
		if !success {
			nCryptFreeObject(uintptr(hProv))
		}
	}()

	keyName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("convert key name: %w", err)
	}

	var hKey nCryptKeyHandle
	ret := nCryptOpenKey(hProv, &hKey, keyName, 0, 0)
	if ret != 0 {
		return nil, fmt.Errorf("open key: 0x%08x", ret)
	}
	defer func() {
		if !success {
			nCryptFreeObject(uintptr(hKey))
		}
	}()

	pub, err := exportECCPublicKey(hKey)
	if err != nil {
		return nil, err
	}

	success = true
	return &tpmSigner{hProv: hProv, hKey: hKey, pub: pub}, nil
}

func deleteKey(name string) error {
	hProv, err := openProvider()
	if err != nil {
		return err
	}
	defer nCryptFreeObject(uintptr(hProv))

	keyName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("convert key name: %w", err)
	}

	var hKey nCryptKeyHandle
	ret := nCryptOpenKey(hProv, &hKey, keyName, 0, 0)
	if ret != 0 {
		return fmt.Errorf("open key: 0x%08x", ret)
	}

	// NCryptDeleteKey frees hKey on success, so it is only freed here on failure.
	ret = nCryptDeleteKey(hKey, 0)
	if ret != 0 {
		nCryptFreeObject(uintptr(hKey))
		return fmt.Errorf("delete key: 0x%08x", ret)
	}
	return nil
}

func openProvider() (nCryptProvHandle, error) {
	provName, err := windows.UTF16PtrFromString(msPlatformCryptoProvider)
	if err != nil {
		return 0, fmt.Errorf("convert provider name: %w", err)
	}

	var hProv nCryptProvHandle
	ret := nCryptOpenStorageProvider(&hProv, provName, 0)
	if ret != 0 {
		return 0, fmt.Errorf("open storage provider: 0x%08x", ret)
	}
	return hProv, nil
}

func exportECCPublicKey(hKey nCryptKeyHandle) (*ecdsa.PublicKey, error) {
	blobType, err := windows.UTF16PtrFromString(bCryptECCPublicBlob)
	if err != nil {
		return nil, fmt.Errorf("convert blob type: %w", err)
	}

	var cb uint32
	ret := nCryptExportKey(hKey, 0, blobType, nil, nil, 0, &cb, 0)
	if ret != 0 {
		return nil, fmt.Errorf("export key (size): 0x%08x", ret)
	}
	buf := make([]byte, cb)
	ret = nCryptExportKey(hKey, 0, blobType, nil, &buf[0], cb, &cb, 0)
	if ret != 0 {
		return nil, fmt.Errorf("export key: 0x%08x", ret)
	}
	pub, err := parseECCPublicBlob(buf)
	if err != nil {
		return nil, fmt.Errorf("parse ECC public blob: %w", err)
	}
	return pub, nil
}

type tpmSigner struct {
	hProv nCryptProvHandle
	hKey  nCryptKeyHandle
	pub   *ecdsa.PublicKey
}

func (s *tpmSigner) Public() crypto.PublicKey {
	return s.pub
}

// Sign implements crypto.Signer using ECDSA over the TPM key. NCryptSignHash returns the
// signature as raw r || s coordinates; it is converted to the ASN.1 DER SEQUENCE{r,s} that
// x509.CreateCertificate expects from an ECDSA signer.
func (s *tpmSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, ok := opts.(*rsa.PSSOptions); ok {
		return nil, fmt.Errorf("tpmSigner: RSA-PSS is not supported")
	}

	switch opts.HashFunc() {
	case crypto.SHA256, crypto.SHA384, crypto.SHA512:
	default:
		return nil, fmt.Errorf("tpmSigner: unsupported hash %v", opts.HashFunc())
	}

	// Reject a digest whose length does not match the declared hash - a caller mistake that
	// would otherwise have the TPM sign over wrong-sized input.
	if len(digest) != opts.HashFunc().Size() {
		return nil, fmt.Errorf("tpmSigner: digest length %d does not match hash %v", len(digest), opts.HashFunc())
	}

	var cb uint32
	ret := nCryptSignHash(s.hKey, nil, &digest[0], uint32(len(digest)), nil, 0, &cb, 0)
	if ret != 0 {
		return nil, fmt.Errorf("sign hash (size): 0x%08x", ret)
	}
	sig := make([]byte, cb)
	ret = nCryptSignHash(s.hKey, nil, &digest[0], uint32(len(digest)), &sig[0], cb, &cb, 0)
	if ret != 0 {
		return nil, fmt.Errorf("sign hash: 0x%08x", ret)
	}
	sig = sig[:cb]

	if len(sig) != 2*p256CoordinateLength {
		return nil, fmt.Errorf("tpmSigner: unexpected raw signature length %d", len(sig))
	}
	r := new(big.Int).SetBytes(sig[:p256CoordinateLength])
	sVal := new(big.Int).SetBytes(sig[p256CoordinateLength:])
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, sVal})
	if err != nil {
		return nil, fmt.Errorf("encode signature: %w", err)
	}
	return der, nil
}

func (s *tpmSigner) Close() error {
	if s.hKey != 0 {
		nCryptFreeObject(uintptr(s.hKey))
		s.hKey = 0
	}
	if s.hProv != 0 {
		nCryptFreeObject(uintptr(s.hProv))
		s.hProv = 0
	}
	return nil
}

// bCryptECCKeyBlob mirrors BCRYPT_ECCKEY_BLOB.
// See: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob.
type bCryptECCKeyBlob struct {
	Magic uint32
	CbKey uint32
}

func parseECCPublicBlob(blob []byte) (*ecdsa.PublicKey, error) {
	const hdrLen = 8 // 2 * uint32
	if len(blob) < hdrLen {
		return nil, fmt.Errorf("blob too short: %d bytes", len(blob))
	}

	hdr := (*bCryptECCKeyBlob)(unsafe.Pointer(&blob[0]))
	if hdr.Magic != bCryptECDSAP256PublicMagic {
		return nil, fmt.Errorf("unexpected magic: 0x%08x", hdr.Magic)
	}
	keyLen := int(hdr.CbKey)
	if keyLen != p256CoordinateLength {
		return nil, fmt.Errorf("unexpected coordinate length %d for P-256", keyLen)
	}
	if len(blob) < hdrLen+2*keyLen {
		return nil, fmt.Errorf("blob truncated: need %d, have %d", hdrLen+2*keyLen, len(blob))
	}

	x := new(big.Int).SetBytes(blob[hdrLen : hdrLen+keyLen])
	y := new(big.Int).SetBytes(blob[hdrLen+keyLen : hdrLen+2*keyLen])
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}
