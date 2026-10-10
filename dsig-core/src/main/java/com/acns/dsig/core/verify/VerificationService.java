package com.acns.dsig.core.verify;

import com.acns.dsig.core.api.HashResult;
import com.acns.dsns.core.api.ResultCode;
import com.acns.dsig.core.api.ResultCode;
import com.acns.dsig.core.api.TrustStatus;
import com.acns.dsig.core.api.VerificationResult;
import com.acns.dsig.core.crypto.ConstantTime;
import com.acns.dsig.core.crypto.CryptoConfig;
import com.acns.dsig.core.crypto.HashService;
import com.acns.dsig.core.crypto.SignatureService;
import com.acns.dsig.core.error.CorruptedPackageException;
import com.acns.dsig.core.error.DsigException;
import com.acns.dsig.core.format.Envelope;
import com.acns.dsig.core.format.EnvelopeCodec;
import com.acns.dsig.core.format.FormatLimits;
import com.acns.dsig.core.format.Manifest;
import com.acns.dsig.core.keys.Fingerprint;
import com.acns.dsig.core.keys.KeyStorage;
import com.acns.dsig.core.trust.TrustPolicy;

import java.io.InputStream;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Objects;

/**
 * Authoritative Verification Engine implementing Section 9 of the Master Plan.
 */
public class VerificationService {

    private final HashService hashService;
    private final SignatureService signatureService;
    private final EnvelopeCodec envelopeCodec;

    public VerificationService(HashService hashService, SignatureService signatureService, EnvelopeCodec envelopeCodec) {
        this.hashService = Objects.requireNonNull(hashService);
        this.signatureService = Objects.requireNonNull(signatureService);
        this.envelopeCodec = Objects.requireNonNull(envelopeCodec);
    }

    /**
     * Executes the authoritative verification sequence over document stream and raw envelope JSON.
     */
    public VerificationResult verify(InputStream documentStream, String envelopeJson, TrustPolicy trustPolicy) {
        // Step 1: Parse envelope strictly
        Envelope envelope;
        try {
            envelope = envelopeCodec.deserializeEnvelope(envelopeJson);
        } catch (CorruptedPackageException e) {
            return errorResult(ResultCode.CORRUPTED_PACKAGE, "Malformed envelope JSON or parse error: " + e.getMessage());
        } catch (Exception e) {
            return errorResult(ResultCode.CORRUPTED_PACKAGE, "Failed to parse envelope package");
        }

        // Step 2: Validate format & version
        if (!FormatLimits.PROTOCOL_FORMAT.equalsIgnoreCase(envelope.format()) ||
                envelope.version() != FormatLimits.SUPPORTED_VERSION) {
            return errorResult(ResultCode.UNSUPPORTED_FORMAT, "Unsupported envelope format or version");
        }

        if (envelope.base64Manifest() == null || envelope.base64Signature() == null || envelope.base64PublicKey() == null) {
            return errorResult(ResultCode.MISSING_METADATA, "Envelope is missing manifest, signature, or public key");
        }

        // Step 3: Decode Base64 payloads
        byte[] manifestBytes;
        byte[] signatureBytes;
        byte[] publicKeyBytes;
        try {
            manifestBytes = Base64.getDecoder().decode(envelope.base64Manifest());
            signatureBytes = Base64.getDecoder().decode(envelope.base64Signature());
            publicKeyBytes = Base64.getDecoder().decode(envelope.base64PublicKey());
        } catch (IllegalArgumentException e) {
            return errorResult(ResultCode.CORRUPTED_PACKAGE, "Base64 decoding failed in envelope contents");
        }

        // Step 4: Parse manifest strictly
        Manifest manifest;
        try {
            manifest = envelopeCodec.deserializeManifestFromBytes(manifestBytes);
        } catch (CorruptedPackageException e) {
            return errorResult(ResultCode.CORRUPTED_PACKAGE, "Malformed manifest JSON: " + e.getMessage());
        }

        // Step 5: Validate algorithms and required fields
        if (manifest.version() != FormatLimits.SUPPORTED_VERSION ||
                !CryptoConfig.MANIFEST_HASH_ALG.equalsIgnoreCase(manifest.hashAlg()) ||
                !CryptoConfig.MANIFEST_SIG_ALG.equalsIgnoreCase(manifest.sigAlg())) {
            return errorResult(ResultCode.UNSUPPORTED_FORMAT, "Unsupported signature or hash algorithm in manifest");
        }

        if (manifest.docHash() == null || manifest.keyId() == null) {
            return errorResult(ResultCode.MISSING_METADATA, "Required manifest digest or key identifier is missing");
        }

        // Step 6: Validate Public Key and check KeyId consistency
        PublicKey publicKey;
        try {
            publicKey = KeyStorage.parsePublicKeyFromPem(
                    "-----BEGIN PUBLIC KEY-----\n" + envelope.base64PublicKey() + "\n-----END PUBLIC KEY-----");
            signatureService.validatePublicKey(publicKey);
        } catch (DsigException e) {
            return errorResult(ResultCode.INVALID_KEY, "Public key validation failed: " + e.getMessage());
        } catch (Exception e) {
            return errorResult(ResultCode.INVALID_KEY, "Invalid public key encoding");
        }

        String derivedFingerprint = Fingerprint.calculate(publicKey);
        if (!ConstantTime.equals(derivedFingerprint.toLowerCase(), manifest.keyId().toLowerCase())) {
            return errorResult(ResultCode.INVALID_KEY, "Public key fingerprint does not match manifest keyId");
        }

        // Step 7: Cryptographically verify RSA-PSS signature over exact manifest bytes
        boolean sigValid = signatureService.verifyManifest(publicKey, manifestBytes, signatureBytes);
        if (!sigValid) {
            return new VerificationResult(
                    ResultCode.INVALID_SIGNATURE,
                    TrustStatus.UNKNOWN,
                    manifest.docName(),
                    manifest.docSize(),
                    manifest.docHash(),
                    null,
                    manifest.signer(),
                    derivedFingerprint,
                    manifest.signedAt(),
                    manifest.nonce(),
                    "Cryptographic RSA-PSS signature verification failed"
            );
        }

        // Step 8: Recompute SHA-256 of the received document
        HashResult recomputedHash;
        try {
            recomputedHash = hashService.hashStream(documentStream);
        } catch (Exception e) {
            return new VerificationResult(
                    ResultCode.CORRUPTED_PACKAGE,
                    TrustStatus.UNKNOWN,
                    manifest.docName(),
                    manifest.docSize(),
                    manifest.docHash(),
                    null,
                    manifest.signer(),
                    derivedFingerprint,
                    manifest.signedAt(),
                    manifest.nonce(),
                    "Failed to read or hash input document: " + e.getMessage()
            );
        }

        // Step 9: Compare recomputed hash with authenticated signed hash
        byte[] expectedHashBytes;
        try {
            expectedHashBytes = Base64.getDecoder().decode(manifest.docHash());
        } catch (IllegalArgumentException e) {
            return errorResult(ResultCode.CORRUPTED_PACKAGE, "Malformed base64 docHash in manifest");
        }

        boolean docMatches = ConstantTime.equals(recomputedHash.rawDigest(), expectedHashBytes) &&
                recomputedHash.byteCount() == manifest.docSize();

        if (!docMatches) {
            return new VerificationResult(
                    ResultCode.DOCUMENT_TAMPERED,
                    trustPolicy != null ? trustPolicy.getTrustStatus(derivedFingerprint) : TrustStatus.UNKNOWN,
                    manifest.docName(),
                    recomputedHash.byteCount(),
                    manifest.docHash(),
                    recomputedHash.base64Digest(),
                    manifest.signer(),
                    derivedFingerprint,
                    manifest.signedAt(),
                    manifest.nonce(),
                    "Document integrity verification failed! Document has been tampered with."
            );
        }

        // Step 10: Evaluate trust policy
        ResultCode finalCode = trustPolicy != null ?
                trustPolicy.evaluateTrust(derivedFingerprint) : ResultCode.VALID_UNTRUSTED_SIGNER;
        TrustStatus trustStatus = trustPolicy != null ?
                trustPolicy.getTrustStatus(derivedFingerprint) : TrustStatus.UNKNOWN;

        String description = switch (finalCode) {
            case VALID_TRUSTED -> "Document integrity and signer authenticity verified. Signer is TRUSTED.";
            case VALID_UNTRUSTED_SIGNER -> "Document is unchanged and signature is valid, but signer is NOT pinned in trust store.";
            case REVOKED_OR_RETIRED_KEY -> "Cryptographically valid signature, but the signing key is REVOKED or RETIRED.";
            default -> "Verification completed with status: " + finalCode;
        };

        return new VerificationResult(
                finalCode,
                trustStatus,
                manifest.docName(),
                recomputedHash.byteCount(),
                manifest.docHash(),
                recomputedHash.base64Digest(),
                manifest.signer(),
                derivedFingerprint,
                manifest.signedAt(),
                manifest.nonce(),
                description
        );
    }

    private VerificationResult errorResult(ResultCode code, String message) {
        return new VerificationResult(
                code,
                TrustStatus.UNKNOWN,
                null,
                0,
                null,
                null,
                null,
                null,
                null,
                null,
                message
        );
    }
}
