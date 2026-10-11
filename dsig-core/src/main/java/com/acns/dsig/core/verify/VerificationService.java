package com.acns.dsig.core.verify;

import com.acns.dsig.core.api.HashResult;
import com.acns.dsig.core.api.ResultCode;
import com.acns.dsig.core.api.TrustStatus;
import com.acns.dsig.core.api.VerificationResult;
import com.acns.dsig.core.crypto.ConstantTime;
import com.acns.dsig.core.crypto.CryptoConfig;
import com.acns.dsig.core.crypto.HashService;
import com.acns.dsig.core.crypto.SignatureService;
import com.acns.dsig.core.error.CorruptedPackageException;
import com.acns.dsig.core.error.DocumentReadException;
import com.acns.dsig.core.error.DsigException;
import com.acns.dsig.core.error.EmptyDocumentException;
import com.acns.dsig.core.error.KeyValidationException;
import com.acns.dsig.core.format.EnvelopeCodec;
import com.acns.dsig.core.format.FormatLimits;
import com.acns.dsig.core.keys.Fingerprint;
import com.acns.dsig.core.keys.KeyStorage;
import com.acns.dsig.core.trust.TrustPolicy;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Objects;

/**
 * Authoritative Verification Engine implementing Section 9 of the Master Plan.
 *
 * Owned by: Deven Thakkar (Member 1)
 * Work Package: Verification Engine & Result Model
 *
 * Enforces the strict security-sensitive verification order:
 * 1. Strict envelope decode & format limits check
 * 2. Format version & algorithm allow-list validation
 * 3. RSA public key constraint validation & fingerprint-to-keyId binding
 * 4. RSASSA-PSS signature verification over domain-separated exact manifest bytes FIRST
 * 5. Document streaming SHA-256 recalculation (via HashService) and digest/size comparison
 * 6. Signer trust evaluation via TrustPolicy
 */
public class VerificationService {

    private final HashService hashService;
    private final ManifestSignatureVerifier signatureVerifier;
    private final PublicKeyValidator keyValidator;
    private final PackageDecoder packageDecoder;

    /**
     * Primary decoupled constructor using verification-owned interfaces.
     * Allows complete unit testing with test doubles without requiring unfinished dependencies.
     */
    public VerificationService(
            HashService hashService,
            ManifestSignatureVerifier signatureVerifier,
            PublicKeyValidator keyValidator,
            PackageDecoder packageDecoder
    ) {
        this.hashService = Objects.requireNonNull(hashService, "hashService cannot be null");
        this.signatureVerifier = Objects.requireNonNull(signatureVerifier, "signatureVerifier cannot be null");
        this.keyValidator = Objects.requireNonNull(keyValidator, "keyValidator cannot be null");
        this.packageDecoder = Objects.requireNonNull(packageDecoder, "packageDecoder cannot be null");
    }

    /**
     * Integration / Backward-compatibility constructor wiring scaffolded components via default adapters.
     * Preserves exact compatibility with CLI and Server modules.
     */
    public VerificationService(
            HashService hashService,
            SignatureService signatureService,
            EnvelopeCodec envelopeCodec
    ) {
        this(
                Objects.requireNonNull(hashService, "hashService cannot be null"),
                (publicKey, exactManifestBytes, signatureBytes) -> signatureService.verifyManifest(publicKey, exactManifestBytes, signatureBytes),
                new PublicKeyValidator() {
                    @Override
                    public PublicKey parsePublicKey(String encodedPublicKey) {
                        String pem = "-----BEGIN PUBLIC KEY-----\n" + encodedPublicKey + "\n-----END PUBLIC KEY-----";
                        return KeyStorage.parsePublicKeyFromPem(pem);
                    }

                    @Override
                    public void validatePublicKey(PublicKey publicKey) {
                        signatureService.validatePublicKey(publicKey);
                    }

                    @Override
                    public String calculateFingerprint(PublicKey publicKey) {
                        return Fingerprint.calculate(publicKey);
                    }
                },
                new DefaultPackageDecoder(Objects.requireNonNull(envelopeCodec, "envelopeCodec cannot be null"))
        );
    }

    /**
     * Verifies document authenticity, integrity, and signer trust from an InputStream and raw envelope JSON.
     */
    public VerificationResult verify(InputStream documentStream, String envelopeJson, TrustPolicy trustPolicy) {
        Objects.requireNonNull(documentStream, "documentStream cannot be null");
        if (envelopeJson == null || envelopeJson.isBlank()) {
            return errorResult(ResultCode.CORRUPTED_PACKAGE, null, null, "Envelope package payload cannot be null or empty");
        }

        VerificationPackage pkg;
        try {
            pkg = packageDecoder.decode(envelopeJson);
        } catch (CorruptedPackageException e) {
            return errorResult(ResultCode.CORRUPTED_PACKAGE, null, null, "Malformed envelope package: " + e.getMessage());
        } catch (Exception e) {
            return errorResult(ResultCode.CORRUPTED_PACKAGE, null, null, "Failed to parse signature envelope package: " + e.getMessage());
        }

        return verify(documentStream, pkg, trustPolicy);
    }

    /**
     * Core verification pipeline operating on an InputStream and decoded VerificationPackage.
     */
    public VerificationResult verify(InputStream documentStream, VerificationPackage pkg, TrustPolicy trustPolicy) {
        Objects.requireNonNull(documentStream, "documentStream cannot be null");
        if (pkg == null) {
            return errorResult(ResultCode.CORRUPTED_PACKAGE, null, null, "Verification package cannot be null");
        }

        // Step 1: Validate envelope metadata
        if (pkg.format() == null || pkg.exactManifestBytes() == null || pkg.signatureBytes() == null || pkg.encodedPublicKey() == null) {
            return errorResult(ResultCode.MISSING_METADATA, pkg, null, "Envelope is missing required payload components");
        }

        // Step 2: Validate envelope format identifier and version
        if (!FormatLimits.PROTOCOL_FORMAT.equalsIgnoreCase(pkg.format())
                || pkg.version() != FormatLimits.SUPPORTED_VERSION) {
            return errorResult(ResultCode.UNSUPPORTED_FORMAT, pkg, null,
                    "Unsupported envelope format (" + pkg.format() + ") or version (" + pkg.version() + ")");
        }

        // Step 3: Validate mandatory manifest metadata fields
        if (pkg.declaredDocumentHash() == null || pkg.declaredDocumentHash().isBlank()
                || pkg.keyId() == null || pkg.keyId().isBlank()
                || pkg.documentName() == null || pkg.documentName().isBlank()
                || pkg.signedAt() == null
                || pkg.nonce() == null || pkg.nonce().isBlank()
                || pkg.declaredDocumentSize() <= 0) {
            return errorResult(ResultCode.MISSING_METADATA, pkg, null, "Required manifest metadata fields are missing or invalid");
        }

        // Step 4: Validate manifest version and cryptographic algorithm allow-list
        if (pkg.manifestVersion() != FormatLimits.SUPPORTED_VERSION
                || !CryptoConfig.MANIFEST_HASH_ALG.equalsIgnoreCase(pkg.hashAlgorithm())
                || !CryptoConfig.MANIFEST_SIG_ALG.equalsIgnoreCase(pkg.signatureAlgorithm())) {
            return errorResult(ResultCode.UNSUPPORTED_FORMAT, pkg, null,
                    "Unsupported manifest algorithm configuration (" + pkg.hashAlgorithm() + ", " + pkg.signatureAlgorithm() + ") or version (" + pkg.manifestVersion() + ")");
        }

        // Step 5: Parse and validate Public Key; enforce RSA constraints and keyId consistency
        PublicKey publicKey;
        try {
            publicKey = keyValidator.parsePublicKey(pkg.encodedPublicKey());
        } catch (KeyValidationException e) {
            return errorResult(ResultCode.INVALID_KEY, pkg, null, "Public key parsing failed.");
        } catch (Exception e) {
            return errorResult(ResultCode.INVALID_KEY, pkg, null, "Invalid public key encoding");
        }

        try {
            keyValidator.validatePublicKey(publicKey);
        } catch (DsigException e) {
            return errorResult(ResultCode.INVALID_KEY, pkg, null, "Public key validation failed.");
        } catch (Exception e) {
            return errorResult(ResultCode.INVALID_KEY, pkg, null, "Public key violates cryptographic constraints");
        }

        String derivedFingerprint;
        try {
            derivedFingerprint = keyValidator.calculateFingerprint(publicKey);
        } catch (Exception e) {
            return errorResult(ResultCode.INVALID_KEY, pkg, null, "Failed to calculate public key fingerprint.");
        }

        if (!ConstantTime.equals(derivedFingerprint.toLowerCase(), pkg.keyId().toLowerCase())) {
            return errorResult(ResultCode.INVALID_KEY, pkg, derivedFingerprint,
                    "Public key fingerprint (" + derivedFingerprint + ") does not match manifest keyId (" + pkg.keyId() + ")");
        }

        // Step 6: Authenticate manifest FIRST: Cryptographically verify RSASSA-PSS signature over exact manifest bytes
        boolean sigValid;
        try {
            sigValid = signatureVerifier.verifyManifestSignature(publicKey, pkg.exactManifestBytes(), pkg.signatureBytes());
        } catch (Exception e) {
            sigValid = false;
        }

        if (!sigValid) {
            return new VerificationResult(
                    ResultCode.INVALID_SIGNATURE,
                    TrustStatus.UNKNOWN,
                    pkg.documentName(),
                    pkg.declaredDocumentSize(),
                    pkg.declaredDocumentHash(),
                    null, // Do NOT recompute document hash; manifest is unauthenticated
                    pkg.signerLabel(),
                    derivedFingerprint,
                    pkg.signedAt(),
                    pkg.nonce(),
                    "Cryptographic RSA-PSS signature verification failed over exact manifest bytes"
            );
        }

        // Step 7: Stream received document through HashService and calculate SHA-256 + byte count
        HashResult recomputedHash;
        try {
            recomputedHash = hashService.hashStream(documentStream);
        } catch (EmptyDocumentException e) {
            if (pkg.declaredDocumentSize() > 0) {
                return new VerificationResult(
                        ResultCode.DOCUMENT_TAMPERED,
                        trustPolicy != null ? trustPolicy.getTrustStatus(derivedFingerprint) : TrustStatus.UNKNOWN,
                        pkg.documentName(),
                        0L,
                        pkg.declaredDocumentHash(),
                        null,
                        pkg.signerLabel(),
                        derivedFingerprint,
                        pkg.signedAt(),
                        pkg.nonce(),
                        "Document integrity verification failed! Received document is empty (0 bytes), but authenticated manifest declared "
                                + pkg.declaredDocumentSize() + " bytes."
                );
            } else {
                return errorResult(ResultCode.DOCUMENT_TAMPERED, pkg, derivedFingerprint, "Received document is empty (0 bytes).");
            }
        } catch (DocumentReadException e) {
            // Propagate operational I/O read failures; do not mislabel as tampering or package corruption
            throw e;
        }

        // Step 8: Compare recomputed hash and byte count against authenticated manifest values in constant time
        byte[] expectedHashBytes;
        try {
            expectedHashBytes = Base64.getDecoder().decode(pkg.declaredDocumentHash());
        } catch (IllegalArgumentException e) {
            return errorResult(ResultCode.CORRUPTED_PACKAGE, pkg, derivedFingerprint, "Malformed Base64 document hash in manifest");
        }

        boolean hashMatches = ConstantTime.equals(recomputedHash.rawDigest(), expectedHashBytes);
        boolean sizeMatches = recomputedHash.byteCount() == pkg.declaredDocumentSize();

        if (!hashMatches || !sizeMatches) {
            return new VerificationResult(
                    ResultCode.DOCUMENT_TAMPERED,
                    trustPolicy != null ? trustPolicy.getTrustStatus(derivedFingerprint) : TrustStatus.UNKNOWN,
                    pkg.documentName(),
                    recomputedHash.byteCount(),
                    pkg.declaredDocumentHash(),
                    recomputedHash.base64Digest(),
                    pkg.signerLabel(),
                    derivedFingerprint,
                    pkg.signedAt(),
                    pkg.nonce(),
                    "Document integrity verification failed! Received document "
                            + (!hashMatches ? "digest differs from authenticated manifest." : "size differs from authenticated manifest.")
            );
        }

        // Step 9: Evaluate Trust Policy
        ResultCode finalCode = trustPolicy != null ?
                trustPolicy.evaluateTrust(derivedFingerprint) : ResultCode.VALID_UNTRUSTED_SIGNER;
        TrustStatus trustStatus = trustPolicy != null ?
                trustPolicy.getTrustStatus(derivedFingerprint) : TrustStatus.UNKNOWN;

        String description = switch (finalCode) {
            case VALID_TRUSTED -> "Document integrity and signer authenticity verified. Signer is TRUSTED.";
            case VALID_UNTRUSTED_SIGNER -> "Document is unchanged and signature is valid, but signer is NOT pinned in trust store.";
            case REVOKED_OR_RETIRED_KEY -> "Cryptographically valid signature and intact document, but signing key is " + trustStatus + ".";
            default -> "Verification completed with status: " + finalCode;
        };

        // Step 10: Return complete verification result
        return new VerificationResult(
                finalCode,
                trustStatus,
                pkg.documentName(),
                recomputedHash.byteCount(),
                pkg.declaredDocumentHash(),
                recomputedHash.base64Digest(),
                pkg.signerLabel(),
                derivedFingerprint,
                pkg.signedAt(),
                pkg.nonce(),
                description
        );
    }

    /**
     * File-based convenience overload verifying document from a file path.
     */
    public VerificationResult verify(Path documentPath, String envelopeJson, TrustPolicy trustPolicy) {
        Objects.requireNonNull(documentPath, "documentPath cannot be null");
        if (!Files.exists(documentPath) || Files.isDirectory(documentPath)) {
            throw new DocumentReadException("Target document file does not exist or is a directory: " + documentPath.toAbsolutePath());
        }
        try (InputStream in = new BufferedInputStream(Files.newInputStream(documentPath))) {
            return verify(in, envelopeJson, trustPolicy);
        } catch (IOException e) {
            throw new DocumentReadException("Failed to read document file: " + documentPath + " (" + e.getMessage() + ")", e);
        }
    }

    /**
     * File-based convenience overload verifying document from a file path and decoded VerificationPackage.
     */
    public VerificationResult verify(Path documentPath, VerificationPackage pkg, TrustPolicy trustPolicy) {
        Objects.requireNonNull(documentPath, "documentPath cannot be null");
        if (!Files.exists(documentPath) || Files.isDirectory(documentPath)) {
            throw new DocumentReadException("Target document file does not exist or is a directory: " + documentPath.toAbsolutePath());
        }
        try (InputStream in = new BufferedInputStream(Files.newInputStream(documentPath))) {
            return verify(in, pkg, trustPolicy);
        } catch (IOException e) {
            throw new DocumentReadException("Failed to read document file: " + documentPath + " (" + e.getMessage() + ")", e);
        }
    }

    private VerificationResult errorResult(ResultCode code, VerificationPackage pkg, String fingerprint, String message) {
        return new VerificationResult(
                code,
                TrustStatus.UNKNOWN,
                pkg != null ? pkg.documentName() : null,
                pkg != null ? pkg.declaredDocumentSize() : 0L,
                pkg != null ? pkg.declaredDocumentHash() : null,
                null,
                pkg != null ? pkg.signerLabel() : null,
                fingerprint != null ? fingerprint : (pkg != null ? pkg.keyId() : null),
                pkg != null ? pkg.signedAt() : null,
                pkg != null ? pkg.nonce() : null,
                message
        );
    }
}
