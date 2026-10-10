package com.acns.dsig.core.api;

/**
 * Authoritative verification outcome codes matching the ACNS-DSIG specification.
 */
public enum ResultCode {
    /**
     * Signature mathematically valid, document hash matches, key fingerprint trusted, not revoked.
     */
    VALID_TRUSTED,

    /**
     * Signature valid and document hash matches, but signer key fingerprint is not in trust store.
     */
    VALID_UNTRUSTED_SIGNER,

    /**
     * Manifest signature is authentic, but recomputed document hash does not match signed digest.
     */
    DOCUMENT_TAMPERED,

    /**
     * Cryptographic RSA-PSS signature verification failed against manifest payload.
     */
    INVALID_SIGNATURE,

    /**
     * Malformed public key, key length below 3072 bits, or keyId fingerprint mismatch.
     */
    INVALID_KEY,

    /**
     * Unsupported package/manifest version or unrecognized cryptographic algorithm.
     */
    UNSUPPORTED_FORMAT,

    /**
     * Required envelope or manifest fields are missing or empty.
     */
    MISSING_METADATA,

    /**
     * Corrupted JSON, encoding errors, duplicate keys, or invalid Base64.
     */
    CORRUPTED_PACKAGE,

    /**
     * Cryptographically valid signature, but the signing key is explicitly revoked or retired.
     */
    REVOKED_OR_RETIRED_KEY
}
