package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// The Linux backend stores an ECDSA P-256 signing key in a TPM 2.0. It uses the pure-Go
// github.com/google/go-tpm library, so it needs no cgo.
//
// Persistence: the key is created under a Storage Root Key (SRK) and the TPM-wrapped key blob
// is stored on disk, then loaded back into a transient TPM handle when needed. The private
// portion is encrypted to the SRK and never leaves the chip in the clear. The SRK is a primary
// key in the owner hierarchy, derived deterministically from the standard ECC SRK template, so
// it is re-created on each operation rather than occupying one of the TPM's scarce
// persistent-handle slots.
//
// Because nothing is ever made persistent inside the TPM (no EvictControl), deleteKey just
// removes the on-disk blob and there can be no orphaned TPM objects.
//
// Caveats: the blob is bound to this TPM's owner-hierarchy seed - clearing the TPM or changing
// the owner authorization makes existing blobs unloadable, the same property as any
// TPM-protected key. The owner authorization is assumed empty (the common default).

// defaultTPMDevice is the Linux kernel TPM resource-manager device. The resource manager
// (unlike /dev/tpm0) virtualizes transient-object slots and flushes handles when the file
// descriptor closes, so a crash cannot leak TPM memory. Override with KP_TPM_DEVICE.
const defaultTPMDevice = "/dev/tpmrm0"

// On-disk blob format: magic, version, then a length-prefixed marshaled TPM2B_PUBLIC followed
// by a length-prefixed marshaled TPM2B_PRIVATE.
const (
	blobMagic   = "KPTM"
	blobVersion = 1
)

// tpmSigner is a crypto.Signer backed by a TPM 2.0 ECDSA P-256 key. Public returns the cached
// public key, Sign produces an ASN.1 DER ECDSA signature, and Close flushes the loaded key and
// closes the device. It owns the open TPM transport and the transient key handle until Close.
//
// crypto.Signer must be safe for concurrent use (x509/tls call Sign from many goroutines), but
// the signer wraps a single TPM device file descriptor and go-tpm does not serialize commands.
// mu serializes Sign and Close so concurrent callers cannot interleave command/response pairs
// on the device. The TPM executes commands serially anyway, so this costs nothing in practice.
type tpmSigner struct {
	mu     sync.Mutex
	tpm    transport.TPMCloser
	handle tpm2.TPMHandle // loaded transient key
	name   tpm2.TPM2BName // key Name, identifies the handle to the auth session
	pub    *ecdsa.PublicKey
}

// createKey creates a new TPM-backed key, writes its wrapped blob to disk under name, and
// returns a signer backed by it. On any failure after the device is opened the handles are
// flushed and the device closed; the blob is written last, so a failure leaves nothing behind.
func createKey(name string) (signCloser, error) {
	path, err := blobPath(name)
	if err != nil {
		return nil, err
	}

	// Fail on a pre-existing name instead of silently creating a second key.
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("create persisted key: key %q already exists", name)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("create persisted key: %w", err)
	}

	tpm, err := openTPM()
	if err != nil {
		return nil, fmt.Errorf("create persisted key: %w", err)
	}

	// On any error the device and any loaded handle must be released. On success the returned
	// signer owns them and releases them via Close.
	var success bool
	var childHandle tpm2.TPMHandle
	defer func() {
		if !success {
			flush(tpm, childHandle)
			tpm.Close()
		}
	}()

	parent, err := createPrimary(tpm)
	if err != nil {
		return nil, fmt.Errorf("create persisted key: %w", err)
	}
	defer flush(tpm, parent.ObjectHandle)

	create := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{Handle: parent.ObjectHandle, Name: parent.Name},
		InPublic:     eccSignTemplate(),
	}
	created, err := create.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("create persisted key: create: %w", err)
	}

	load := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{Handle: parent.ObjectHandle, Name: parent.Name},
		InPrivate:    created.OutPrivate,
		InPublic:     created.OutPublic,
	}
	loaded, err := load.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("create persisted key: load: %w", err)
	}
	childHandle = loaded.ObjectHandle

	pub, err := eccPublicKey(created.OutPublic)
	if err != nil {
		return nil, fmt.Errorf("create persisted key: %w", err)
	}

	if err := writeBlob(path, created.OutPublic, created.OutPrivate); err != nil {
		// A concurrent create may have published the same name between the os.Stat guard above
		// and the commit; writeBlob refuses to overwrite, surfacing it as os.ErrExist.
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create persisted key: key %q already exists", name)
		}
		return nil, fmt.Errorf("create persisted key: %w", err)
	}

	success = true
	return &tpmSigner{tpm: tpm, handle: loaded.ObjectHandle, name: loaded.Name, pub: pub}, nil
}

// loadKey opens a previously created key by name and returns a signer backed by it.
func loadKey(name string) (signCloser, error) {
	path, err := blobPath(name)
	if err != nil {
		return nil, err
	}

	pubBlob, privBlob, err := readBlob(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("open key: key %q not found", name)
		}
		return nil, fmt.Errorf("open key: %w", err)
	}

	tpm, err := openTPM()
	if err != nil {
		return nil, fmt.Errorf("open key: %w", err)
	}

	var success bool
	var childHandle tpm2.TPMHandle
	defer func() {
		if !success {
			flush(tpm, childHandle)
			tpm.Close()
		}
	}()

	parent, err := createPrimary(tpm)
	if err != nil {
		return nil, fmt.Errorf("open key: %w", err)
	}
	defer flush(tpm, parent.ObjectHandle)

	load := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{Handle: parent.ObjectHandle, Name: parent.Name},
		InPrivate:    privBlob,
		InPublic:     pubBlob,
	}
	loaded, err := load.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("open key: load: %w", err)
	}
	childHandle = loaded.ObjectHandle

	pub, err := eccPublicKey(pubBlob)
	if err != nil {
		return nil, fmt.Errorf("open key: %w", err)
	}

	success = true
	return &tpmSigner{tpm: tpm, handle: loaded.ObjectHandle, name: loaded.Name, pub: pub}, nil
}

// deleteKey permanently removes the key identified by name. The key only ever exists as a
// transient TPM handle plus the on-disk blob, so removing the file is sufficient.
func deleteKey(name string) error {
	path, err := blobPath(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("delete key: key %q not found", name)
		}
		return fmt.Errorf("delete key: %w", err)
	}
	return nil
}

func (s *tpmSigner) Public() crypto.PublicKey {
	return s.pub
}

// Sign implements crypto.Signer using ECDSA over the TPM key. It returns an ASN.1 DER
// SEQUENCE{r,s}, the format x509.CreateCertificate expects from an ECDSA signer.
func (s *tpmSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, ok := opts.(*rsa.PSSOptions); ok {
		return nil, fmt.Errorf("tpmSigner: RSA-PSS is not supported")
	}

	var hashAlg tpm2.TPMIAlgHash
	switch opts.HashFunc() {
	case crypto.SHA256:
		hashAlg = tpm2.TPMAlgSHA256
	case crypto.SHA384:
		hashAlg = tpm2.TPMAlgSHA384
	case crypto.SHA512:
		hashAlg = tpm2.TPMAlgSHA512
	default:
		return nil, fmt.Errorf("tpmSigner: unsupported hash %v", opts.HashFunc())
	}

	// Reject a digest whose length does not match the declared hash - a caller mistake that
	// would otherwise have the TPM sign over wrong-sized input.
	if len(digest) != opts.HashFunc().Size() {
		return nil, fmt.Errorf("tpmSigner: digest length %d does not match hash %v", len(digest), opts.HashFunc())
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tpm == nil {
		return nil, fmt.Errorf("tpmSigner: signer is closed")
	}

	// The key is created with a TPM_ALG_NULL scheme, so the signing scheme (and thus the hash)
	// is chosen here, per signature. The validation ticket is a null ticket: the key is
	// unrestricted and the digest is computed outside the TPM, so no proof of origin is needed.
	sign := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{Handle: s.handle, Name: s.name},
		Digest:    tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: hashAlg}),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}
	rsp, err := sign.Execute(s.tpm)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	ecc, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("extract ECDSA signature: %w", err)
	}

	r := new(big.Int).SetBytes(ecc.SignatureR.Buffer)
	sVal := new(big.Int).SetBytes(ecc.SignatureS.Buffer)
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, sVal})
	if err != nil {
		return nil, fmt.Errorf("encode signature: %w", err)
	}
	return der, nil
}

// Close flushes the loaded key and closes the TPM device. It is safe to call multiple times
// and concurrently with Sign.
func (s *tpmSigner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tpm == nil {
		return nil
	}
	flush(s.tpm, s.handle)
	s.handle = 0
	err := s.tpm.Close()
	s.tpm = nil
	return err
}

// createPrimary derives the Storage Root Key in the owner hierarchy from the standard ECC SRK
// template. The derivation is deterministic, so the same parent is produced on every call and
// can re-wrap/unwrap the stored child key.
func createPrimary(tpm transport.TPM) (*tpm2.CreatePrimaryResponse, error) {
	cp := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}
	rsp, err := cp.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("create primary: %w", err)
	}
	return rsp, nil
}

// eccSignTemplate is the template for the child key: an unrestricted ECDSA P-256 signing key
// with a TPM_ALG_NULL scheme so the hash algorithm is selected at sign time.
func eccSignTemplate() tpm2.TPM2BPublic {
	return tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme:    tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull},
			CurveID:   tpm2.TPMECCNistP256,
			KDF:       tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
	})
}

// eccPublicKey extracts the ECDSA public key from a TPM2B_PUBLIC.
func eccPublicKey(pub tpm2.TPM2BPublic) (*ecdsa.PublicKey, error) {
	contents, err := pub.Contents()
	if err != nil {
		return nil, fmt.Errorf("parse public area: %w", err)
	}
	parms, err := contents.Parameters.ECCDetail()
	if err != nil {
		return nil, fmt.Errorf("parse ECC parameters: %w", err)
	}
	point, err := contents.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("parse ECC point: %w", err)
	}
	key, err := tpm2.ECDSAPub(parms, point)
	if err != nil {
		return nil, fmt.Errorf("build public key: %w", err)
	}
	return key, nil
}

// flush releases a transient TPM handle. /dev/tpmrm0 also auto-flushes on close, so a missed
// flush is not fatal; errors are ignored: nothing can be done about them.
func flush(tpm transport.TPM, h tpm2.TPMHandle) {
	if h == 0 {
		return
	}
	fc := tpm2.FlushContext{FlushHandle: h}
	_, _ = fc.Execute(tpm)
}

// openTPM opens the TPM device (KP_TPM_DEVICE or /dev/tpmrm0).
func openTPM() (transport.TPMCloser, error) {
	dev := os.Getenv("KP_TPM_DEVICE")
	if dev == "" {
		dev = defaultTPMDevice
	}
	tpm, err := linuxtpm.Open(dev)
	if err != nil {
		return nil, fmt.Errorf("open TPM device %s (need access to the TPM device, e.g. membership in the 'tss' group): %w", dev, err)
	}
	return tpm, nil
}

// blobPath returns the on-disk path of the wrapped key blob for name. The name is base64url
// encoded so any name maps to a single safe, collision-free filename.
func blobPath(name string) (string, error) {
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate config directory: %w", err)
	}
	file := base64.RawURLEncoding.EncodeToString([]byte(name)) + ".tpmkey"
	return filepath.Join(cfg, "key-protecc", file), nil
}

// writeBlob writes the framed key blob to path atomically (temp file + link), mode 0600,
// creating the store directory (0700) if needed. It refuses to overwrite an existing file
// (returning os.ErrExist) because the blob is the only copy of the wrapped key.
func writeBlob(path string, pub tpm2.TPM2BPublic, priv tpm2.TPM2BPrivate) error {
	pubBytes := tpm2.Marshal(pub)
	privBytes := tpm2.Marshal(priv)

	var buf bytes.Buffer
	buf.WriteString(blobMagic)
	buf.WriteByte(blobVersion)
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(pubBytes)))
	buf.Write(pubBytes)
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(privBytes)))
	buf.Write(privBytes)

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create key store: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".tpmkey-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("set permissions: %w", err)
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close key file: %w", err)
	}

	// Commit with link, not rename: link fails with EEXIST if path already exists, so an
	// existing key is never silently clobbered (rename would overwrite it). The temp inode was
	// fully written and fsynced before linking, so path appears atomically complete. On
	// success the temp name is removed, leaving the inode reachable only via path.
	if err := os.Link(tmpName, path); err != nil {
		return fmt.Errorf("commit key file: %w", err)
	}
	os.Remove(tmpName)
	tmpName = "" // committed; the deferred cleanup must not touch path

	// Best-effort durability: flush the directory entry so the new file survives a crash. A
	// failure here is non-fatal - the key is already published - so the error is ignored.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// readBlob reads and decodes a framed key blob. A missing file surfaces as an os.IsNotExist
// error so the caller can report a clear "not found".
func readBlob(path string) (tpm2.TPM2BPublic, tpm2.TPM2BPrivate, error) {
	var pub tpm2.TPM2BPublic
	var priv tpm2.TPM2BPrivate

	data, err := os.ReadFile(path)
	if err != nil {
		return pub, priv, err
	}

	r := bytes.NewReader(data)
	magic := make([]byte, len(blobMagic))
	if _, err := io.ReadFull(r, magic); err != nil || string(magic) != blobMagic {
		return pub, priv, fmt.Errorf("invalid key file: bad magic")
	}
	ver, err := r.ReadByte()
	if err != nil || ver != blobVersion {
		return pub, priv, fmt.Errorf("invalid key file: unsupported version")
	}

	pubBytes, err := readChunk(r)
	if err != nil {
		return pub, priv, fmt.Errorf("read public blob: %w", err)
	}
	privBytes, err := readChunk(r)
	if err != nil {
		return pub, priv, fmt.Errorf("read private blob: %w", err)
	}

	pubPtr, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pubBytes)
	if err != nil {
		return pub, priv, fmt.Errorf("unmarshal public blob: %w", err)
	}
	privPtr, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privBytes)
	if err != nil {
		return pub, priv, fmt.Errorf("unmarshal private blob: %w", err)
	}
	return *pubPtr, *privPtr, nil
}

// readChunk reads a big-endian uint32 length followed by that many bytes. The length is
// bounded by the bytes actually remaining so a corrupt or truncated length prefix yields a
// clean error instead of a multi-gigabyte allocation.
func readChunk(r *bytes.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if int64(n) > int64(r.Len()) {
		return nil, fmt.Errorf("invalid key file: chunk length %d exceeds %d remaining bytes", n, r.Len())
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
