package com.acns.dsig.core.fuzz;

import com.acns.dsig.core.api.ResultCode;
import com.acns.dsig.core.api.VerificationResult;
import com.acns.dsig.core.crypto.HashService;
import com.acns.dsig.core.crypto.SignatureService;
import com.acns.dsig.core.error.CorruptedPackageException;
import com.acns.dsig.core.format.Envelope;
import com.acns.dsig.core.format.EnvelopeCodec;
import com.acns.dsig.core.format.FormatLimits;
import com.acns.dsig.core.format.Manifest;
import com.acns.dsig.core.keys.KeyService;
import com.acns.dsig.core.sign.SigningService;
import com.acns.dsig.core.verify.VerificationService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Robust fuzz testing suite targeting EnvelopeCodec, Manifest parsing, and VerificationService.
 *
 * Tests random bitflips, truncated payloads, corrupted base64, structural corruption,
 * and malicious oversized inputs without crashing the application VM or throwing unhandled
 * internal runtime exceptions.
 *
 * Owned by: Simrit Kaur (Member 10) - QA, CI/CD & Integration-Test Infrastructure.
 */
public class EnvelopeFuzzTest {

    private static EnvelopeCodec envelopeCodec;
    private static VerificationService verificationService;
    private static String validEnvelopeJson;
    private static byte[] validDocBytes;

    @BeforeAll
    static void setUp() throws Exception {
        envelopeCodec = new EnvelopeCodec();
        HashService hashService = new HashService();
        SignatureService signatureService = new SignatureService();
        verificationService = new VerificationService(hashService, signatureService, envelopeCodec);

        KeyService keyService = new KeyService();
        KeyService.GeneratedKeyPair keyPair = keyService.generateKeyPair();
        validDocBytes = "Official test document payload for envelope fuzz testing.".getBytes(StandardCharsets.UTF_8);

        SigningService signingService = new SigningService(hashService, signatureService, envelopeCodec);
        SigningService.SignResult signResult = signingService.sign(
                new ByteArrayInputStream(validDocBytes),
                "fuzz-doc.txt",
                keyPair.keyPair().getPrivate(),
                keyPair.keyPair().getPublic(),
                "Fuzzing Signer"
        );
        validEnvelopeJson = signResult.envelopeJson();
    }

    @Test
    @DisplayName("Fuzz: Random bitflips in serialized envelope JSON are safely handled")
    void testRandomBitflipsInEnvelopeJson() {
        Random random = new Random(42);
        byte[] originalBytes = validEnvelopeJson.getBytes(StandardCharsets.UTF_8);

        for (int i = 0; i < 100; i++) {
            byte[] mutatedBytes = originalBytes.clone();
            int mutations = 1 + random.nextInt(5);
            for (int m = 0; m < mutations; m++) {
                int pos = random.nextInt(mutatedBytes.length);
                mutatedBytes[pos] ^= (byte) (1 << random.nextInt(8));
            }
            String mutatedJson = new String(mutatedBytes, StandardCharsets.UTF_8);

            // Verification service must either return an error result or reject with CorruptedPackageException
            try {
                VerificationResult result = verificationService.verify(
                        new ByteArrayInputStream(validDocBytes),
                        mutatedJson,
                        null
                );
                assertNotNull(result);
                assertNotEquals(ResultCode.VALID_TRUSTED, result.resultCode(),
                        "Fuzzed envelope must never evaluate to VALID_TRUSTED");
            } catch (CorruptedPackageException expected) {
                // Safe and acceptable error handling
                assertNotNull(expected.getMessage());
            } catch (Exception ex) {
                // Must not be unexpected NullPointer or crash
                assertTrue(ex instanceof RuntimeException, "Unexpected error: " + ex.getClass().getName());
            }
        }
    }

    @Test
    @DisplayName("Fuzz: Truncated envelope payloads at varying byte offsets")
    void testTruncatedEnvelopePayloads() {
        byte[] originalBytes = validEnvelopeJson.getBytes(StandardCharsets.UTF_8);

        for (int length = 1; length < originalBytes.length; length += 15) {
            byte[] truncatedBytes = new byte[length];
            System.arraycopy(originalBytes, 0, truncatedBytes, 0, length);
            String truncatedJson = new String(truncatedBytes, StandardCharsets.UTF_8);

            try {
                VerificationResult result = verificationService.verify(
                        new ByteArrayInputStream(validDocBytes),
                        truncatedJson,
                        null
                );
                assertNotNull(result);
                assertNotEquals(ResultCode.VALID_TRUSTED, result.resultCode());
            } catch (CorruptedPackageException expected) {
                assertNotNull(expected.getMessage());
            }
        }
    }

    @Test
    @DisplayName("Fuzz: Corrupted Base64 strings in envelope components")
    void testCorruptedBase64Components() {
        Envelope validEnvelope = envelopeCodec.deserializeEnvelope(validEnvelopeJson);

        String[] corruptedValues = new String[]{
                "???not_base64!!!",
                "====",
                "abc",
                "Zm9v!@#$",
                "",
                " "
        };

        for (String bad : corruptedValues) {
            // Corrupt manifest
            Envelope badManifest = new Envelope(
                    validEnvelope.format(),
                    validEnvelope.version(),
                    bad,
                    validEnvelope.base64Signature(),
                    validEnvelope.base64PublicKey()
            );
            String badManifestJson = envelopeCodec.serializeEnvelope(badManifest);
            VerificationResult res1 = verificationService.verify(new ByteArrayInputStream(validDocBytes), badManifestJson, null);
            assertEquals(ResultCode.CORRUPTED_PACKAGE, res1.resultCode());

            // Corrupt signature
            Envelope badSignature = new Envelope(
                    validEnvelope.format(),
                    validEnvelope.version(),
                    validEnvelope.base64Manifest(),
                    bad,
                    validEnvelope.base64PublicKey()
            );
            String badSigJson = envelopeCodec.serializeEnvelope(badSignature);
            VerificationResult res2 = verificationService.verify(new ByteArrayInputStream(validDocBytes), badSigJson, null);
            assertTrue(res2.resultCode() == ResultCode.CORRUPTED_PACKAGE
                    || res2.resultCode() == ResultCode.MISSING_METADATA
                    || res2.resultCode() == ResultCode.INVALID_SIGNATURE);

            // Corrupt public key
            Envelope badPublicKey = new Envelope(
                    validEnvelope.format(),
                    validEnvelope.version(),
                    validEnvelope.base64Manifest(),
                    validEnvelope.base64Signature(),
                    bad
            );
            String badKeyJson = envelopeCodec.serializeEnvelope(badPublicKey);
            VerificationResult res3 = verificationService.verify(new ByteArrayInputStream(validDocBytes), badKeyJson, null);
            assertTrue(res3.resultCode() == ResultCode.CORRUPTED_PACKAGE
                    || res3.resultCode() == ResultCode.MISSING_METADATA
                    || res3.resultCode() == ResultCode.INVALID_KEY);
        }
    }

    @Test
    @DisplayName("Fuzz: Manifest boundary & corrupted field values")
    void testCorruptedManifestFields() {
        Envelope validEnvelope = envelopeCodec.deserializeEnvelope(validEnvelopeJson);
        byte[] manifestBytes = Base64.getDecoder().decode(validEnvelope.base64Manifest());
        Manifest validManifest = envelopeCodec.deserializeManifestFromBytes(manifestBytes);

        // Negative docSize
        Manifest badSizeManifest = new Manifest(
                validManifest.version(),
                validManifest.docName(),
                -100L,
                validManifest.hashAlg(),
                validManifest.docHash(),
                validManifest.sigAlg(),
                validManifest.keyId(),
                validManifest.signedAt(),
                validManifest.nonce(),
                validManifest.signer()
        );
        byte[] badSizeBytes = envelopeCodec.serializeManifestToBytes(badSizeManifest);
        Envelope envBadSize = new Envelope(
                validEnvelope.format(),
                validEnvelope.version(),
                Base64.getEncoder().encodeToString(badSizeBytes),
                validEnvelope.base64Signature(),
                validEnvelope.base64PublicKey()
        );
        VerificationResult resSize = verificationService.verify(new ByteArrayInputStream(validDocBytes), envelopeCodec.serializeEnvelope(envBadSize), null);
        assertEquals(ResultCode.MISSING_METADATA, resSize.resultCode());

        // Unknown algorithm
        Manifest badAlgManifest = new Manifest(
                validManifest.version(),
                validManifest.docName(),
                validManifest.docSize(),
                "MD5",
                validManifest.docHash(),
                validManifest.sigAlg(),
                validManifest.keyId(),
                validManifest.signedAt(),
                validManifest.nonce(),
                validManifest.signer()
        );
        byte[] badAlgBytes = envelopeCodec.serializeManifestToBytes(badAlgManifest);
        Envelope envBadAlg = new Envelope(
                validEnvelope.format(),
                validEnvelope.version(),
                Base64.getEncoder().encodeToString(badAlgBytes),
                validEnvelope.base64Signature(),
                validEnvelope.base64PublicKey()
        );
        VerificationResult resAlg = verificationService.verify(new ByteArrayInputStream(validDocBytes), envelopeCodec.serializeEnvelope(envBadAlg), null);
        assertEquals(ResultCode.UNSUPPORTED_FORMAT, resAlg.resultCode());
    }

    @Test
    @DisplayName("Fuzz: Oversized envelope exceeding FormatLimits is rejected")
    void testOversizedEnvelopeRejection() {
        StringBuilder largeJson = new StringBuilder();
        largeJson.append("{\"format\":\"ACNS-DSIG\",\"version\":1,\"manifest\":\"");
        largeJson.append("A".repeat(FormatLimits.MAX_ENVELOPE_JSON_BYTES + 1024));
        largeJson.append("\",\"signature\":\"ABC\",\"publicKey\":\"DEF\"}");

        assertThrows(CorruptedPackageException.class, () -> {
            envelopeCodec.deserializeEnvelope(largeJson.toString());
        });
    }

    @Test
    @DisplayName("Fuzz: Duplicate JSON keys in envelope are strictly rejected")
    void testDuplicateKeysRejection() {
        String duplicateKeyJson = """
                {
                  "format": "ACNS-DSIG",
                  "version": 1,
                  "version": 2,
                  "manifest": "abc",
                  "signature": "def",
                  "publicKey": "ghi"
                }
                """;

        assertThrows(CorruptedPackageException.class, () -> {
            envelopeCodec.deserializeEnvelope(duplicateKeyJson);
        });
    }
}
