package com.acns.dsig.core.sign;

import com.acns.dsig.core.api.HashResult;
import com.acns.dsig.core.crypto.CryptoConfig;
import com.acns.dsig.core.crypto.HashService;
import com.acns.dsig.core.crypto.SignatureService;
import com.acns.dsig.core.format.Envelope;
import com.acns.dsig.core.format.EnvelopeCodec;
import com.acns.dsig.core.format.FormatLimits;
import com.acns.dsig.core.format.Manifest;
import com.acns.dsig.core.keys.Fingerprint;

import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;

/**
 * Orchestrates the end-to-end digital document signing workflow.
 */
public class SigningService {

    private final HashService hashService;
    private final SignatureService signatureService;
    private final EnvelopeCodec envelopeCodec;

    public SigningService(HashService hashService, SignatureService signatureService, EnvelopeCodec envelopeCodec) {
        this.hashService = Objects.requireNonNull(hashService);
        this.signatureService = Objects.requireNonNull(signatureService);
        this.envelopeCodec = Objects.requireNonNull(envelopeCodec);
    }

    public record SignResult(
            Envelope envelope,
            String envelopeJson,
            String documentHash,
            String keyFingerprint,
            long documentSize
    ) {}

    /**
     * Signs a document stream using the provided private and public key pair.
     */
    public SignResult sign(
            InputStream documentStream,
            String documentName,
            PrivateKey privateKey,
            PublicKey publicKey,
            String signerName
    ) throws IOException {
        // 1. Stream document through SHA-256
        HashResult hashResult = hashService.hashStream(documentStream);

        // 2. Derive keyId from public key SPKI DER
        String keyFingerprint = Fingerprint.calculate(publicKey);

        // 3. Generate 16-byte random nonce
        byte[] nonceBytes = new byte[FormatLimits.MIN_NONCE_BYTES];
        new SecureRandom().nextBytes(nonceBytes);
        String base64Nonce = Base64.getEncoder().encodeToString(nonceBytes);

        // 4. Construct manifest
        Manifest manifest = new Manifest(
                FormatLimits.SUPPORTED_VERSION,
                documentName,
                hashResult.byteCount(),
                CryptoConfig.MANIFEST_HASH_ALG,
                hashResult.base64Digest(),
                CryptoConfig.MANIFEST_SIG_ALG,
                keyFingerprint,
                Instant.now(),
                base64Nonce,
                signerName != null ? signerName : "Unknown"
        );

        // 5. Serialize exact manifest bytes UTF-8
        byte[] manifestBytes = envelopeCodec.serializeManifestToBytes(manifest);

        // 6. Sign domain-separated manifest bytes with RSA-PSS
        byte[] signatureBytes = signatureService.signManifest(privateKey, manifestBytes);

        // 7. Construct detached Envelope
        String base64Manifest = Base64.getEncoder().encodeToString(manifestBytes);
        String base64Signature = Base64.getEncoder().encodeToString(signatureBytes);
        String base64PublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());

        Envelope envelope = new Envelope(
                FormatLimits.PROTOCOL_FORMAT,
                FormatLimits.SUPPORTED_VERSION,
                base64Manifest,
                base64Signature,
                base64PublicKey
        );

        String envelopeJson = envelopeCodec.serializeEnvelope(envelope);

        return new SignResult(
                envelope,
                envelopeJson,
                hashResult.hexDigest(),
                keyFingerprint,
                hashResult.byteCount()
        );
    }
}
