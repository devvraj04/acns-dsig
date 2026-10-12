package com.acns.dsig.core.crypto;

import com.acns.dsig.core.error.CryptoException;
import com.acns.dsig.core.error.KeyValidationException;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PSSParameterSpec;

/**
 * Enterprise-grade Digital Signature Engine implementing RSASSA-PSS (RFC 8017 / PKCS #1 v2.2).
 *
 * Owned by: Tanmay Vishwakarma (Member 3)
 * Work Package: RSA-PSS Digital Signature Engine
 *
 * Cryptographic Baseline:
 * - Asymmetric Algorithm: RSA-3072 (e >= 65537)
 * - Signature Scheme: RSASSA-PSS
 * - Digest Algorithm: SHA-256
 * - Mask Generation: MGF1 with SHA-256
 * - Salt Length: 32 bytes (CSPRNG randomized)
 * - Trailer Field: 1 (0xBC)
 * - Domain Separation Label: "ACNS-DSIG-v1\0" prepended to manifest payloads
 */
public class SignatureService {

    /**
     * Constructs domain-separated message payload: LABEL || manifestBytes.
     * Enforces non-null and non-empty manifest byte constraints.
     *
     * @param manifestBytes raw serialized UTF-8 manifest bytes
     * @return composite byte array prepended with the fixed protocol domain separation label
     */
    public static byte[] applyDomainSeparation(byte[] manifestBytes) {
        if (manifestBytes == null) {
            throw new IllegalArgumentException("Manifest bytes cannot be null");
        }
        if (manifestBytes.length == 0) {
            throw new IllegalArgumentException("Manifest bytes cannot be empty");
        }
        byte[] payload = new byte[CryptoConfig.DOMAIN_LABEL.length + manifestBytes.length];
        System.arraycopy(CryptoConfig.DOMAIN_LABEL, 0, payload, 0, CryptoConfig.DOMAIN_LABEL.length);
        System.arraycopy(manifestBytes, 0, payload, CryptoConfig.DOMAIN_LABEL.length, manifestBytes.length);
        return payload;
    }

    /**
     * Validates that an algorithm identifier matches the authoritative RSASSA-PSS configuration.
     * Rejects legacy/unsupported algorithms (e.g. RSA PKCS#1 v1.5, ECDSA, SHA-1).
     *
     * @param algorithmIdentifier manifest signature algorithm string
     * @throws CryptoException if algorithm is null, blank, or unsupported
     */
    public void validateAlgorithm(String algorithmIdentifier) {
        if (algorithmIdentifier == null || algorithmIdentifier.isBlank()) {
            throw new CryptoException("Signature algorithm identifier cannot be null or blank");
        }
        if (!CryptoConfig.MANIFEST_SIG_ALG.equalsIgnoreCase(algorithmIdentifier.trim())) {
            throw new CryptoException("Unsupported signature algorithm: '" + algorithmIdentifier + "'. Only '"
                    + CryptoConfig.MANIFEST_SIG_ALG + "' is permitted.");
        }
    }

    /**
     * Validates that an RSA private key adheres to strict security parameters:
     * 1. Must not be null.
     * 2. Must be an instance of RSAPrivateKey.
     * 3. Modulus length must be >= 3072 bits.
     *
     * @param privateKey the private key to inspect
     * @throws KeyValidationException if key is null, non-RSA, or below 3072 bits
     */
    public void validatePrivateKey(PrivateKey privateKey) {
        if (privateKey == null) {
            throw new KeyValidationException("Private key cannot be null");
        }
        if (!(privateKey instanceof RSAPrivateKey rsaKey)) {
            throw new KeyValidationException("Key is not an RSA private key (got " + privateKey.getAlgorithm() + ")");
        }
        int bitLength = rsaKey.getModulus().bitLength();
        if (bitLength < CryptoConfig.RSA_KEY_BITS) {
            throw new KeyValidationException("RSA private key size is " + bitLength
                    + " bits, but minimum required size is " + CryptoConfig.RSA_KEY_BITS + " bits");
        }
    }

    /**
     * Enforces RSA public key validation:
     * 1. Must not be null.
     * 2. Must be an instance of RSAPublicKey.
     * 3. Modulus length must be >= 3072 bits.
     * 4. Public exponent must be >= 65537 (Fermat F4).
     *
     * @param publicKey the public key to inspect
     * @throws KeyValidationException if key is null, non-RSA, below 3072 bits, or has weak exponent
     */
    public void validatePublicKey(PublicKey publicKey) {
        if (publicKey == null) {
            throw new KeyValidationException("Public key cannot be null");
        }
        if (!(publicKey instanceof RSAPublicKey rsaKey)) {
            throw new KeyValidationException("Key is not an RSA public key (got " + publicKey.getAlgorithm() + ")");
        }
        int bitLength = rsaKey.getModulus().bitLength();
        if (bitLength < CryptoConfig.RSA_KEY_BITS) {
            throw new KeyValidationException("RSA key size is " + bitLength
                    + " bits, but minimum required size is " + CryptoConfig.RSA_KEY_BITS + " bits");
        }
        if (rsaKey.getPublicExponent().longValue() < CryptoConfig.RSA_PUBLIC_EXPONENT) {
            throw new KeyValidationException("RSA public exponent is insecure: " + rsaKey.getPublicExponent());
        }
    }

    /**
     * Signs manifest bytes with RSASSA-PSS after applying the domain separation label.
     *
     * @param privateKey RSA private key (>= 3072 bits)
     * @param manifestBytes exact UTF-8 bytes of the manifest JSON
     * @return raw 384-byte RSASSA-PSS digital signature
     */
    public byte[] signManifest(PrivateKey privateKey, byte[] manifestBytes) {
        validatePrivateKey(privateKey);
        byte[] payloadToSign = applyDomainSeparation(manifestBytes);
        return signRawBytes(privateKey, payloadToSign);
    }

    /**
     * Direct RSASSA-PSS signature primitive over raw byte payload without domain separation prefix.
     *
     * @param privateKey RSA private key (>= 3072 bits)
     * @param data arbitrary byte payload to sign
     * @return raw RSASSA-PSS signature bytes
     */
    public byte[] signData(PrivateKey privateKey, byte[] data) {
        validatePrivateKey(privateKey);
        if (data == null) {
            throw new IllegalArgumentException("Data to sign cannot be null");
        }
        return signRawBytes(privateKey, data);
    }

    private byte[] signRawBytes(PrivateKey privateKey, byte[] payload) {
        try {
            Signature signer = Signature.getInstance(CryptoConfig.SIGNATURE_ALGORITHM);
            signer.setParameter(CryptoConfig.createPssParameterSpec());
            signer.initSign(privateKey);
            signer.update(payload);
            return signer.sign();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Failed to generate RSA-PSS digital signature: " + e.getMessage(), e);
        }
    }

    /**
     * Verifies an RSASSA-PSS signature over domain-separated manifest bytes.
     *
     * @param publicKey signer's RSA public key (>= 3072 bits)
     * @param manifestBytes exact UTF-8 bytes of the manifest JSON
     * @param signatureBytes raw RSASSA-PSS signature bytes
     * @return true if mathematically valid, false if invalid or corrupted
     */
    public boolean verifyManifest(PublicKey publicKey, byte[] manifestBytes, byte[] signatureBytes) {
        validatePublicKey(publicKey);
        if (manifestBytes == null || signatureBytes == null || signatureBytes.length == 0) {
            return false;
        }
        try {
            byte[] expectedPayload = applyDomainSeparation(manifestBytes);
            return verifyRawBytes(publicKey, expectedPayload, signatureBytes);
        } catch (IllegalArgumentException e) {
            // e.g. empty manifestBytes
            return false;
        }
    }

    /**
     * Direct RSASSA-PSS verification primitive over raw byte payload without domain separation.
     *
     * @param publicKey signer's RSA public key (>= 3072 bits)
     * @param data raw byte payload
     * @param signatureBytes raw RSASSA-PSS signature bytes
     * @return true if mathematically valid, false otherwise
     */
    public boolean verifyData(PublicKey publicKey, byte[] data, byte[] signatureBytes) {
        validatePublicKey(publicKey);
        if (data == null || signatureBytes == null || signatureBytes.length == 0) {
            return false;
        }
        return verifyRawBytes(publicKey, data, signatureBytes);
    }

    private boolean verifyRawBytes(PublicKey publicKey, byte[] payload, byte[] signatureBytes) {
        try {
            Signature verifier = Signature.getInstance(CryptoConfig.SIGNATURE_ALGORITHM);
            verifier.setParameter(CryptoConfig.createPssParameterSpec());
            verifier.initVerify(publicKey);
            verifier.update(payload);
            return verifier.verify(signatureBytes);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /**
     * Returns the configured standard PSS Parameter Specification.
     */
    public PSSParameterSpec getPssParameterSpec() {
        return CryptoConfig.createPssParameterSpec();
    }

    /**
     * Returns authoritative algorithm metadata for auditing and diagnostics.
     */
    public SignatureEngineInfo describeEngine() {
        return new SignatureEngineInfo(
                CryptoConfig.SIGNATURE_ALGORITHM,
                CryptoConfig.MANIFEST_SIG_ALG,
                CryptoConfig.HASH_ALGORITHM,
                CryptoConfig.MGF_ALGORITHM,
                "SHA-256",
                CryptoConfig.SALT_LENGTH_BYTES,
                CryptoConfig.TRAILER_FIELD,
                CryptoConfig.RSA_KEY_BITS,
                new String(CryptoConfig.DOMAIN_LABEL, StandardCharsets.UTF_8)
        );
    }

    /**
     * Immutable specification descriptor for the RSA-PSS Signature Engine.
     */
    public record SignatureEngineInfo(
            String signatureAlgorithm,
            String manifestAlgorithmId,
            String hashAlgorithm,
            String mgfAlgorithm,
            String mgfHashAlgorithm,
            int saltLengthBytes,
            int trailerField,
            int minRsaKeyBits,
            String domainLabel
    ) {}
}
