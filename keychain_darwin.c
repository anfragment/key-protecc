#include "keychain_darwin.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

// set_err writes a CFString message into the caller's error buffer.
static void set_err(char *err, size_t errLen, CFStringRef msg) {
    if (err == NULL || errLen == 0) {
        return;
    }
    if (msg == NULL || !CFStringGetCString(msg, err, (CFIndex)errLen, kCFStringEncodingUTF8)) {
        err[0] = '\0';
    }
}

// set_cferror renders a CFErrorRef's description into the caller's error buffer.
static void set_cferror(char *err, size_t errLen, CFErrorRef cfErr) {
    if (cfErr == NULL) {
        set_err(err, errLen, NULL);
        return;
    }
    CFStringRef desc = CFErrorCopyDescription(cfErr);
    set_err(err, errLen, desc);
    if (desc != NULL) {
        CFRelease(desc);
    }
}

static CFDataRef make_tag(const char *tag, size_t tagLen) {
    return CFDataCreate(kCFAllocatorDefault, (const UInt8 *)tag, (CFIndex)tagLen);
}

// make_query builds the dictionary that identifies a key by tag, shared by load and
// delete. The same attributes are used at creation time so lookups stay consistent.
static CFMutableDictionaryRef make_query(const char *tag, size_t tagLen) {
    CFMutableDictionaryRef q = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(q, kSecClass, kSecClassKey);
    CFDictionarySetValue(q, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionarySetValue(q, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
#ifdef KP_SECURE_ENCLAVE
    CFDictionarySetValue(q, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
    CFDictionarySetValue(q, kSecUseDataProtectionKeychain, kCFBooleanTrue);
#endif
    CFDataRef tagData = make_tag(tag, tagLen);
    CFDictionarySetValue(q, kSecAttrApplicationTag, tagData);
    CFRelease(tagData);
    return q;
}

// copy_to_buf copies a CFData's bytes into a freshly malloc'd buffer for the caller.
static int copy_to_buf(CFDataRef data, uint8_t **outBuf, size_t *outLen, char *err, size_t errLen) {
    CFIndex len = CFDataGetLength(data);
    // Avoid malloc(0), which may return NULL and be misreported as an allocation failure.
    uint8_t *buf = (uint8_t *)malloc(len > 0 ? (size_t)len : 1);
    if (buf == NULL) {
        set_err(err, errLen, CFSTR("malloc failed"));
        return -1;
    }
    memcpy(buf, CFDataGetBytePtr(data), (size_t)len);
    *outBuf = buf;
    *outLen = (size_t)len;
    return 0;
}

int kp_create_key(const char *tag, size_t tagLen, void **outPrivRef, char *err, size_t errLen) {
    CFErrorRef cfErr = NULL;

    CFDataRef tagData = make_tag(tag, tagLen);

    CFMutableDictionaryRef privAttrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(privAttrs, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionarySetValue(privAttrs, kSecAttrApplicationTag, tagData);

#ifdef KP_SECURE_ENCLAVE
    // CA key signs unattended, so the access control allows private-key usage without a
    // user-presence (biometric/passcode) requirement, scoped to this device.
    SecAccessControlRef access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        kSecAccessControlPrivateKeyUsage,
        &cfErr);
    if (access == NULL) {
        set_cferror(err, errLen, cfErr);
        if (cfErr != NULL) {
            CFRelease(cfErr);
        }
        CFRelease(privAttrs);
        CFRelease(tagData);
        return -1;
    }
    CFDictionarySetValue(privAttrs, kSecAttrAccessControl, access);
#endif

    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    int bits = 256;
    CFNumberRef bitsNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bits);
    CFDictionarySetValue(attrs, kSecAttrKeySizeInBits, bitsNum);
#ifdef KP_SECURE_ENCLAVE
    // Hardware-backed key in the data protection keychain. Without these two attributes
    // the key is an ordinary software key in the file-based keychain (build -tags
    // kpsoftkey), which is how create/sign/delete is exercised locally without the
    // keychain-access-groups entitlement or a code-signing identity.
    CFDictionarySetValue(attrs, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
    CFDictionarySetValue(attrs, kSecUseDataProtectionKeychain, kCFBooleanTrue);
#endif
    CFDictionarySetValue(attrs, kSecPrivateKeyAttrs, privAttrs);

    SecKeyRef privKey = SecKeyCreateRandomKey(attrs, &cfErr);

    CFRelease(bitsNum);
    CFRelease(attrs);
    CFRelease(privAttrs);
    CFRelease(tagData);
#ifdef KP_SECURE_ENCLAVE
    CFRelease(access);
#endif

    if (privKey == NULL) {
        set_cferror(err, errLen, cfErr);
        if (cfErr != NULL) {
            CFRelease(cfErr);
        }
        return -1;
    }

    *outPrivRef = (void *)privKey;
    return 0;
}

int kp_load_key(const char *tag, size_t tagLen, void **outPrivRef, char *err, size_t errLen) {
    CFMutableDictionaryRef q = make_query(tag, tagLen);
    CFDictionarySetValue(q, kSecReturnRef, kCFBooleanTrue);

    CFTypeRef result = NULL;
    OSStatus st = SecItemCopyMatching(q, &result);
    CFRelease(q);

    if (st != errSecSuccess) {
        if (err != NULL && errLen > 0) {
            err[0] = '\0';
        }
        return (int)st;
    }

    *outPrivRef = (void *)result; // SecKeyRef, retained; released via kp_release.
    return 0;
}

int kp_delete_key(const char *tag, size_t tagLen, char *err, size_t errLen) {
    CFMutableDictionaryRef q = make_query(tag, tagLen);
    OSStatus st = SecItemDelete(q);
    CFRelease(q);

    if (st != errSecSuccess) {
        if (err != NULL && errLen > 0) {
            err[0] = '\0';
        }
        return (int)st;
    }
    return 0;
}

int kp_copy_public_key(void *privRef, uint8_t **outBuf, size_t *outLen, char *err, size_t errLen) {
    SecKeyRef pub = SecKeyCopyPublicKey((SecKeyRef)privRef);
    if (pub == NULL) {
        set_err(err, errLen, CFSTR("SecKeyCopyPublicKey returned NULL"));
        return -1;
    }

    CFErrorRef cfErr = NULL;
    CFDataRef data = SecKeyCopyExternalRepresentation(pub, &cfErr);
    CFRelease(pub);
    if (data == NULL) {
        set_cferror(err, errLen, cfErr);
        if (cfErr != NULL) {
            CFRelease(cfErr);
        }
        return -1;
    }

    int rc = copy_to_buf(data, outBuf, outLen, err, errLen);
    CFRelease(data);
    return rc;
}

int kp_sign(void *privRef, int hash, const uint8_t *digest, size_t digestLen,
            uint8_t **outSig, size_t *outLen, char *err, size_t errLen) {
    SecKeyAlgorithm alg;
    switch (hash) {
    case 256:
        alg = kSecKeyAlgorithmECDSASignatureDigestX962SHA256;
        break;
    case 384:
        alg = kSecKeyAlgorithmECDSASignatureDigestX962SHA384;
        break;
    case 512:
        alg = kSecKeyAlgorithmECDSASignatureDigestX962SHA512;
        break;
    default:
        set_err(err, errLen, CFSTR("unsupported hash"));
        return -1;
    }

    CFDataRef digestData = CFDataCreate(kCFAllocatorDefault, digest, (CFIndex)digestLen);
    CFErrorRef cfErr = NULL;
    CFDataRef sig = SecKeyCreateSignature((SecKeyRef)privRef, alg, digestData, &cfErr);
    CFRelease(digestData);
    if (sig == NULL) {
        set_cferror(err, errLen, cfErr);
        if (cfErr != NULL) {
            CFRelease(cfErr);
        }
        return -1;
    }

    int rc = copy_to_buf(sig, outSig, outLen, err, errLen);
    CFRelease(sig);
    return rc;
}

void kp_release(void *ref) {
    if (ref != NULL) {
        CFRelease((CFTypeRef)ref);
    }
}
