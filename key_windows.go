package main

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	msKeyStorageProvider     = "Microsoft Software Key Storage Provider"
	msPlatformCryptoProvider = "Microsoft Platform Crypto Provider"

	bCryptRSAAlgorithm   = "RSA"
	bCryptRSAPublicMagic = 0x31415352
	bCryptRSAPublicBlob  = "RSAPUBLICBLOB"

	nCryptLengthProperty   = "Length"
	nCryptKeyUsageProperty = "Key Usage"

	nCryptAllowSigningFlag = 0x00000002

	nCryptPadPKCS1Flag = 0x00000002

	bCryptSHA256Algorithm = "SHA256"
	bCryptSHA384Algorithm = "SHA384"
	bCryptSHA512Algorithm = "SHA512"

	rsaKeyLength = 2048
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

	algId, err := windows.UTF16PtrFromString(bCryptRSAAlgorithm)
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

	keyLen := uint32(rsaKeyLength)
	lenProp, err := windows.UTF16PtrFromString(nCryptLengthProperty)
	if err != nil {
		return nil, fmt.Errorf("convert length property: %w", err)
	}
	ret = nCryptSetProperty(hKey, lenProp, (*byte)(unsafe.Pointer(&keyLen)), uint32(unsafe.Sizeof(keyLen)), 0)
	if ret != 0 {
		return nil, fmt.Errorf("set length: 0x%08x", ret)
	}

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

	pub, err := exportRSAPublicKey(hKey)
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

	pub, err := exportRSAPublicKey(hKey)
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

func exportRSAPublicKey(hKey nCryptKeyHandle) (*rsa.PublicKey, error) {
	blobType, err := windows.UTF16PtrFromString(bCryptRSAPublicBlob)
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
	pub, err := parseRSAPublicBlob(buf)
	if err != nil {
		return nil, fmt.Errorf("parse RSA public blob: %w", err)
	}
	return pub, nil
}

type bCryptPKCS1PaddingInfo struct {
	pszAlgId *uint16
}

type tpmSigner struct {
	hProv nCryptProvHandle
	hKey  nCryptKeyHandle
	pub   *rsa.PublicKey
}

func (s *tpmSigner) Public() crypto.PublicKey {
	return s.pub
}

// Sign implements crypto.Signer using RSA PKCS#1 v1.5.
// RSA-PSS is intentionally unsupported - the callers of x509.CreateCertificate in Zen
// do not specify x509 template SignatureAlgorithm, which selects v1.5.
func (s *tpmSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, ok := opts.(*rsa.PSSOptions); ok {
		return nil, fmt.Errorf("tpmSigner: RSA-PSS is not supported")
	}

	var hashAlg string
	switch opts.HashFunc() {
	case crypto.SHA256:
		hashAlg = bCryptSHA256Algorithm
	case crypto.SHA384:
		hashAlg = bCryptSHA384Algorithm
	case crypto.SHA512:
		hashAlg = bCryptSHA512Algorithm
	default:
		return nil, fmt.Errorf("tpmSigner: unsupported hash %v", opts.HashFunc())
	}

	algId, err := windows.UTF16PtrFromString(hashAlg)
	if err != nil {
		return nil, fmt.Errorf("convert hash algorithm id: %w", err)
	}
	padInfo := bCryptPKCS1PaddingInfo{pszAlgId: algId}
	pPadInfo := (*byte)(unsafe.Pointer(&padInfo))

	var cb uint32
	ret := nCryptSignHash(s.hKey, pPadInfo, &digest[0], uint32(len(digest)), nil, 0, &cb, nCryptPadPKCS1Flag)
	if ret != 0 {
		return nil, fmt.Errorf("sign hash (size): 0x%08x", ret)
	}
	sig := make([]byte, cb)
	ret = nCryptSignHash(s.hKey, pPadInfo, &digest[0], uint32(len(digest)), &sig[0], cb, &cb, nCryptPadPKCS1Flag)
	if ret != 0 {
		return nil, fmt.Errorf("sign hash: 0x%08x", ret)
	}
	runtime.KeepAlive(padInfo)
	runtime.KeepAlive(algId)

	return sig[:cb], nil
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

// bCryptRSAKeyBlob mirrors BCRYPT_RSAKEY_BLOB.
// See: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob.
type bCryptRSAKeyBlob struct {
	Magic       uint32
	BitLength   uint32
	CbPublicExp uint32
	CbModulus   uint32
	CbPrime1    uint32
	CbPrime2    uint32
}

func parseRSAPublicBlob(blob []byte) (*rsa.PublicKey, error) {
	const hdrLen = 24 // 6 * uint32
	if len(blob) < hdrLen {
		return nil, fmt.Errorf("blob too short: %d bytes", len(blob))
	}

	hdr := (*bCryptRSAKeyBlob)(unsafe.Pointer(&blob[0]))
	if hdr.Magic != bCryptRSAPublicMagic {
		return nil, fmt.Errorf("unexpected magic: 0x%08x", hdr.Magic)
	}

	expLen := int(hdr.CbPublicExp)
	modLen := int(hdr.CbModulus)
	if len(blob) < hdrLen+expLen+modLen {
		return nil, fmt.Errorf("blob truncated: need %d, have %d", hdrLen+expLen+modLen, len(blob))
	}

	expBytes := blob[hdrLen : hdrLen+expLen]
	modBytes := blob[hdrLen+expLen : hdrLen+expLen+modLen]

	e := new(big.Int).SetBytes(expBytes)
	if !e.IsInt64() || e.Int64() > (1<<31-1) {
		return nil, fmt.Errorf("public exponent too large: %s", e)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(modBytes),
		E: int(e.Int64()),
	}, nil
}
