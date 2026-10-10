package com.acns.dsig.core.api;

import java.time.Instant;

/**
 * Complete, frozen verification result model containing both cryptographic and trust decisions.
 */
public record VerificationResult(
        ResultCode resultCode,
        TrustStatus trustStatus,
        String documentName,
        long documentSize,
        String signedDocHash,
        String recomputedDocHash,
        String signerName,
        String keyFingerprint,
        Instant signedAt,
        String nonce,
        String message
) {
    /**
     * Helper indicating whether the verification succeeded with full cryptographic authenticity and pinned trust.
     */
    public boolean isValidTrusted() {
        return resultCode == ResultCode.VALID_TRUSTED;
    }

    /**
     * Helper indicating whether document tampering was definitively detected.
     */
    public boolean isTampered() {
        return resultCode == ResultCode.DOCUMENT_TAMPERED;
    }
}
