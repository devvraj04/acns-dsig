package com.acns.dsig.core;

import com.acns.dsig.core.api.HashResult;
import com.acns.dsig.core.api.ResultCode;
import com.acns.dsig.core.api.TrustLookup;
import com.acns.dsig.core.api.TrustStatus;
import com.acns.dsig.core.api.VerificationResult;
import com.acns.dsig.core.crypto.ConstantTime;
import com.acns.dsig.core.crypto.HashService;
import com.acns.dsig.core.crypto.SignatureService;
import com.acns.dsig.core.format.EnvelopeCodec;
import com.acns.dsig.core.keys.Fingerprint;
import com.acns.dsig.core.keys.KeyService;
import com.acns.dsig.core.sign.SigningService;
import com.acns.dsig.core.trust.TrustPolicy;
import com.acns.dsig.core.verify.VerificationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

public class CryptoCoreTest {

    private HashService hashService;
    private SignatureService signatureService;
    private EnvelopeCodec envelopeCodec;
    private KeyService keyService;
    private SigningService signingService;
    private VerificationService verificationService;

    @BeforeEach
    void setUp() {
        hashService = new HashService();
        signatureService = new SignatureService();
        envelopeCodec = new EnvelopeCodec();
        keyService = new KeyService();
        signingService = new SigningService(hashService, signatureService, envelopeCodec);
        verificationService = new VerificationService(hashService, signatureService, envelopeCodec);
    }

    @Test
    @DisplayName("Streaming SHA-256 computes consistent 32-byte digest")
    void testHashing() throws IOException {
        byte[] docBytes = "Hello ACNS-DSIG World".getBytes(StandardCharsets.UTF_8);
        HashResult res = hashService.hashStream(new ByteArrayInputStream(docBytes));

        assertNotNull(res);
        assertEquals(32, res.rawDigest().length);
        assertEquals(docBytes.length, res.byteCount());
        assertTrue(ConstantTime.equals(res.hexDigest(), res.hexDigest()));
    }

    @Test
    @DisplayName("RSA-3072 Key Generation and Fingerprinting")
    void testKeyGeneration() {
        KeyService.GeneratedKeyPair kp = keyService.generateKeyPair();
        assertNotNull(kp);
        assertNotNull(kp.keyPair().getPublic());
        assertNotNull(kp.keyPair().getPrivate());
        assertNotNull(kp.fingerprint());
        assertEquals(64, kp.fingerprint().length()); // SHA-256 hex is 64 characters
    }

    @Test
    @DisplayName("End-to-End Signing and Verification (VALID_TRUSTED)")
    void testEndToEndValidTrusted() throws Exception {
        KeyService.GeneratedKeyPair aliceKey = keyService.generateKeyPair();
        byte[] docBytes = "Confidential Contract Document".getBytes(StandardCharsets.UTF_8);

        // Sign
        SigningService.SignResult signResult = signingService.sign(
                new ByteArrayInputStream(docBytes),
                "contract.txt",
                aliceKey.keyPair().getPrivate(),
                aliceKey.keyPair().getPublic(),
                "Alice"
        );

        assertNotNull(signResult);
        assertNotNull(signResult.envelopeJson());

        // Setup mock trust store with Alice's fingerprint pinned
        Map<String, TrustStatus> store = new HashMap<>();
        store.put(aliceKey.fingerprint().toLowerCase(), TrustStatus.TRUSTED);
        TrustLookup lookup = new TrustLookup() {
            @Override
            public TrustStatus getTrustStatus(String fingerprint) {
                return store.getOrDefault(fingerprint.toLowerCase(), TrustStatus.UNKNOWN);
            }
            @Override
            public Optional<String> getSignerLabel(String fingerprint) {
                return Optional.of("Alice");
            }
        };

        // Verify
        VerificationResult result = verificationService.verify(
                new ByteArrayInputStream(docBytes),
                signResult.envelopeJson(),
                new TrustPolicy(lookup)
        );

        assertEquals(ResultCode.VALID_TRUSTED, result.resultCode());
        assertTrue(result.isValidTrusted());
        assertEquals("Alice", result.signerName());
    }

    @Test
    @DisplayName("Tampered Document Detection (DOCUMENT_TAMPERED)")
    void testTamperedDocument() throws Exception {
        KeyService.GeneratedKeyPair aliceKey = keyService.generateKeyPair();
        byte[] docBytes = "Original Unmodified Document".getBytes(StandardCharsets.UTF_8);

        SigningService.SignResult signResult = signingService.sign(
                new ByteArrayInputStream(docBytes),
                "doc.txt",
                aliceKey.keyPair().getPrivate(),
                aliceKey.keyPair().getPublic(),
                "Alice"
        );

        byte[] tamperedBytes = "Modified / Tampered Document".getBytes(StandardCharsets.UTF_8);

        VerificationResult result = verificationService.verify(
                new ByteArrayInputStream(tamperedBytes),
                signResult.envelopeJson(),
                null
        );

        assertEquals(ResultCode.DOCUMENT_TAMPERED, result.resultCode());
        assertTrue(result.isTampered());
    }

    @Test
    @DisplayName("Untrusted Signer Detection (VALID_UNTRUSTED_SIGNER)")
    void testUntrustedSigner() throws Exception {
        KeyService.GeneratedKeyPair malloryKey = keyService.generateKeyPair();
        byte[] docBytes = "Legitimate Document signed by Mallory".getBytes(StandardCharsets.UTF_8);

        SigningService.SignResult signResult = signingService.sign(
                new ByteArrayInputStream(docBytes),
                "doc.txt",
                malloryKey.keyPair().getPrivate(),
                malloryKey.keyPair().getPublic(),
                "Mallory"
        );

        // Verifier trust lookup without Mallory pinned
        TrustLookup emptyLookup = new TrustLookup() {
            @Override
            public TrustStatus getTrustStatus(String fingerprint) {
                return TrustStatus.UNKNOWN;
            }
            @Override
            public Optional<String> getSignerLabel(String fingerprint) {
                return Optional.empty();
            }
        };

        VerificationResult result = verificationService.verify(
                new ByteArrayInputStream(docBytes),
                signResult.envelopeJson(),
                new TrustPolicy(emptyLookup)
        );

        assertEquals(ResultCode.VALID_UNTRUSTED_SIGNER, result.resultCode());
        assertFalse(result.isValidTrusted());
    }
}
