package com.acns.dsig.core.verify;

import com.acns.dsig.core.error.KeyValidationException;

import java.security.PublicKey;

/**
 * Minimal verification-owned contract for parsing, validating, and fingerprinting RSA public keys.
 *
 * Owned by: Deven Thakkar (Member 1)
 * Isolates pending key management implementation (Atharv Vedant).
 */
public interface PublicKeyValidator {

    /**
     * Parses an RSA public key from its PEM or Base64 SPKI representation.
     *
     * @param encodedPublicKey Base64 SPKI or PEM string
     * @return parsed java.security.PublicKey instance
     * @throws KeyValidationException if decoding fails or the key is malformed
     */
    PublicKey parsePublicKey(String encodedPublicKey) throws KeyValidationException;

    /**
     * Validates that the public key satisfies the mandatory cryptographic constraints
     * (RSA modulus >= 3072 bits, exponent 65537).
     *
     * @param publicKey the public key to inspect
     * @throws KeyValidationException if the key fails constraints
     */
    void validatePublicKey(PublicKey publicKey) throws KeyValidationException;

    /**
     * Calculates the normalized lowercase hex SHA-256 fingerprint over DER SubjectPublicKeyInfo.
     *
     * @param publicKey the public key
     * @return lowercase 64-character hex SHA-256 fingerprint
     */
    String calculateFingerprint(PublicKey publicKey);
}
