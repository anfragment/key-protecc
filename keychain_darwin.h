#ifndef KEY_PROTECC_KEYCHAIN_DARWIN_H
#define KEY_PROTECC_KEYCHAIN_DARWIN_H

#include <stddef.h>
#include <stdint.h>

// Thin C layer over the macOS Security framework for a Secure Enclave ECDSA P-256
// signing key.
//
// Every function returns 0 on success. On failure it returns a non-zero status: for
// SecItem* calls that is the raw OSStatus, otherwise -1,
// and a human-readable message is written into err (NUL-terminated, up to errLen).
// Key references are handed back to Go as opaque void* (SecKeyRef); release with
// kp_release. Output byte buffers are malloc'd and must be freed by the caller.

// kp_create_key creates a permanent Secure Enclave ECDSA P-256 key tagged with the
// given name and returns its private key reference in outPrivRef.
int kp_create_key(const char *tag, size_t tagLen, void **outPrivRef, char *err, size_t errLen);

// kp_load_key looks up an existing key by tag and returns its private key reference.
// Returns errSecItemNotFound (-25300) when no key matches the tag.
int kp_load_key(const char *tag, size_t tagLen, void **outPrivRef, char *err, size_t errLen);

// kp_delete_key removes the key identified by tag from the keychain.
int kp_delete_key(const char *tag, size_t tagLen, char *err, size_t errLen);

// kp_copy_public_key exports the public key of privRef in ANSI X9.63 form
// (0x04 || X || Y, 65 bytes for P-256) into a malloc'd buffer.
int kp_copy_public_key(void *privRef, uint8_t **outBuf, size_t *outLen, char *err, size_t errLen);

// kp_sign signs digest with privRef. hash selects the algorithm: 256, 384 or 512 for
// ECDSA-over-SHA-2 digest signing. The output is an ASN.1 DER SEQUENCE{r, s}.
int kp_sign(void *privRef, int hash, const uint8_t *digest, size_t digestLen,
            uint8_t **outSig, size_t *outLen, char *err, size_t errLen);

// kp_release releases a key reference returned by kp_create_key / kp_load_key.
void kp_release(void *ref);

#endif
