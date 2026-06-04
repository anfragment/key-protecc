package main

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"log"
	"math/big"
	"unsafe"

	"golang.org/x/sys/windows"
)

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zcreatekey_windows.go createkey_windows.go

//sys nCryptOpenStorageProvider(phProvider *nCryptProvHandle, pszProviderName *uint16, dwFlags uint32) (ret uint32) = ncrypt.NCryptOpenStorageProvider
//sys nCryptCreatePersistedKey(hProvider nCryptProvHandle, phKey *nCryptKeyHandle, pszAlgId *uint16, pszKeyName *uint16, dwLegacyKeySpec uint32, dwFlags uint32) (ret uint32) = ncrypt.NCryptCreatePersistedKey
//sys nCryptSetProperty(hObject nCryptKeyHandle, pszProperty *uint16, pbInput *byte, cbInput uint32, dwFlags uint32) (ret uint32) = ncrypt.NCryptSetProperty
//sys nCryptFinalizeKey(hKey nCryptKeyHandle, dwFlags uint32) (ret uint32) = ncrypt.NCryptFinalizeKey
//sys nCryptExportKey(hKey nCryptKeyHandle, hExportKey nCryptKeyHandle, pszBlobType *uint16, pParameterList *byte, pbOutput *byte, cbOutput uint32, pcbResult *uint32, dwFlags uint32) (ret uint32) = ncrypt.NCryptExportKey
//sys nCryptFreeObject(hObject uintptr) (ret uint32) = ncrypt.NCryptFreeObject

const (
	msKeyStorageProvider     = "Microsoft Software Key Storage Provider"
	msPlatformCryptoProvider = "Microsoft Platform Crypto Provider"

	bCryptRSAAlgorithm   = "RSA"
	bCryptRSAPublicMagic = 0x31415352
	bCryptRSAPublicBlob  = "RSAPUBLICBLOB"

	nCryptLengthProperty   = "Length"
	nCryptKeyUsageProperty = "Key Usage"

	nCryptAllowSigningFlag = 0x00000002

	rsaKeyLength = 2048
)

type nCryptProvHandle uintptr
type nCryptKeyHandle uintptr

func createKey(name string) (crypto.Signer, error) {
	var hProv nCryptProvHandle

	provName, err := windows.UTF16PtrFromString(msPlatformCryptoProvider)
	if err != nil {
		return nil, fmt.Errorf("convert provider name: %w", err)
	}

	ret := nCryptOpenStorageProvider(&hProv, provName, 0)
	if ret != 0 {
		return nil, fmt.Errorf("open storage provider: 0x%08x", ret)
	}
	defer nCryptFreeObject(uintptr(hProv))

	algId, err := windows.UTF16PtrFromString(bCryptRSAAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("convert algorithm id: %w", err)
	}
	keyName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("convert key name: %w", err)
	}

	var hKey nCryptKeyHandle
	ret = nCryptCreatePersistedKey(hProv, &hKey, algId, keyName, 0, 0)
	if ret != 0 {
		return nil, fmt.Errorf("create persisted key: 0x%08x", ret)
	}
	// On any error the key must be freed, on success it stays alive because the returned signer owns it.
	var success bool
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
	usageProp, _ := windows.UTF16PtrFromString(nCryptKeyUsageProperty)
	ret = nCryptSetProperty(hKey, usageProp,
		(*byte)(unsafe.Pointer(&usage)), uint32(unsafe.Sizeof(usage)), 0)

	ret = nCryptFinalizeKey(hKey, 0)
	if ret != 0 {
		return nil, fmt.Errorf("finalize key: 0x%08x", ret)
	}

	blobType, err := windows.UTF16PtrFromString(bCryptRSAPublicBlob)
	if err != nil {
		return nil, fmt.Errorf("convert blob type: %w", err)
	}

	var cb uint32
	ret = nCryptExportKey(hKey, 0, blobType, nil, nil, 0, &cb, 0)
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
	log.Println(pub)

	success = true
	return nil, nil
}

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
	if len(blob) <= hdrLen+expLen+modLen {
		return nil, fmt.Errorf("blob truncated: need %d, have %d", hdrLen+expLen+modLen+1, len(blob))
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
