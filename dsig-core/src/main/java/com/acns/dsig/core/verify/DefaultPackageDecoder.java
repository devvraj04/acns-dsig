package com.acns.dsig.core.verify;

import com.acns.dsig.core.error.CorruptedPackageException;
import com.acns.dsig.core.format.Envelope;
import com.acns.dsig.core.format.EnvelopeCodec;
import com.acns.dsig.core.format.Manifest;

import java.util.Base64;
import java.util.Objects;

/**
 * Package-private default adapter bridging EnvelopeCodec into the verification-owned PackageDecoder contract.
 *
 * Owned by: Deven Thakkar (Member 1)
 * Preserves the exact UTF-8 manifest bytes decoded from Base64 for domain-separated signature verification.
 */
class DefaultPackageDecoder implements PackageDecoder {

    private final EnvelopeCodec envelopeCodec;

    DefaultPackageDecoder(EnvelopeCodec envelopeCodec) {
        this.envelopeCodec = Objects.requireNonNull(envelopeCodec, "envelopeCodec cannot be null");
    }

    @Override
    public VerificationPackage decode(String packagePayload) throws CorruptedPackageException {
        if (packagePayload == null || packagePayload.isBlank()) {
            throw new CorruptedPackageException("Package payload cannot be null or empty");
        }

        Envelope envelope = envelopeCodec.deserializeEnvelope(packagePayload);

        // Check if mandatory envelope Base64 fields are missing
        if (envelope.base64Manifest() == null || envelope.base64Signature() == null || envelope.base64PublicKey() == null) {
            return new VerificationPackage(
                    envelope.format(),
                    envelope.version(),
                    null,
                    null,
                    envelope.base64PublicKey(),
                    0, null, 0, null, null, null, null, null, null, null
            );
        }

        byte[] manifestBytes;
        byte[] signatureBytes;
        try {
            manifestBytes = Base64.getDecoder().decode(envelope.base64Manifest());
            signatureBytes = Base64.getDecoder().decode(envelope.base64Signature());
        } catch (IllegalArgumentException e) {
            throw new CorruptedPackageException("Base64 decoding failed in envelope contents: " + e.getMessage(), e);
        }

        Manifest manifest = envelopeCodec.deserializeManifestFromBytes(manifestBytes);

        return new VerificationPackage(
                envelope.format(),
                envelope.version(),
                manifestBytes,
                signatureBytes,
                envelope.base64PublicKey(),
                manifest.version(),
                manifest.docName(),
                manifest.docSize(),
                manifest.hashAlg(),
                manifest.docHash(),
                manifest.sigAlg(),
                manifest.keyId(),
                manifest.signedAt(),
                manifest.nonce(),
                manifest.signer()
        );
    }
}
