package com.acns.dsig.core.verify;

import java.time.Instant;

/**
 * Immutable verification input representation holding package data and the exact signed manifest bytes.
 *
 * Owned by: Deven Thakkar (Member 1)
 * Work Package: Verification Engine & Result Model
 *
 * Design invariant: Holds the exact, unmodified bytes of the manifest received over the wire.
 * Re-serializing the manifest model to generate signed bytes is strictly prohibited by protocol.
 */
public record VerificationPackage(
        String format,
        int version,
        byte[] exactManifestBytes,
        byte[] signatureBytes,
        String encodedPublicKey,
        int manifestVersion,
        String documentName,
        long declaredDocumentSize,
        String hashAlgorithm,
        String declaredDocumentHash,
        String signatureAlgorithm,
        String keyId,
        Instant signedAt,
        String nonce,
        String signerLabel
) {
    public VerificationPackage {
        exactManifestBytes = exactManifestBytes != null ? exactManifestBytes.clone() : null;
        signatureBytes = signatureBytes != null ? signatureBytes.clone() : null;
    }

    @Override
    public byte[] exactManifestBytes() {
        return exactManifestBytes != null ? exactManifestBytes.clone() : null;
    }

    @Override
    public byte[] signatureBytes() {
        return signatureBytes != null ? signatureBytes.clone() : null;
    }
}
