package com.acns.dsig.core.crypto;

import com.acns.dsig.core.error.CryptoException;
import com.acns.dsig.core.error.KeyValidationException;
import com.acns.dsig.core.keys.KeyService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive Unit Test Suite for RSA-PSS Digital Signature Engine.
 *
 * Owned by: Tanmay Vishwakarma (Member 3)
 * Work Package: RSA-PSS Digital Signature Engine
 */
class SignatureServiceTest {

    private static SignatureService signatureService;
    private static KeyService keyService;
    private static KeyPair aliceKeyPair;
    private static KeyPair bobKeyPair;
    private static final byte[] SAMPLE_MANIFEST = (
            "{\"v\":1,\"docName\":\"contract.pdf\",\"docSize\":1048576," +
            "\"hashAlg\":\"SHA-256\",\"docHash\":\"uU0nuZNNPgilLIlX2n2r+AZSEnk=\"," +
            "\"sigAlg\":\"RSASSA-PSS-SHA256-MGF1SHA256-S32\"," +
            "\"keyId\":\"a1b2c3d4e5f60718\",\"signedAt\":\"2026-10-12T10:00:00Z\"," +
            "\"nonce\":\"AAECAwQFBgcICQoLDA0ODw==\",\"signer\":\"Alice\"}"
    ).getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void setUp() {
        signatureService = new SignatureService();
        keyService = new KeyService();

        KeyService.GeneratedKeyPair alice = keyService.generateKeyPair();
        KeyService.GeneratedKeyPair bob = keyService.generateKeyPair();

        aliceKeyPair = alice.keyPair();
        bobKeyPair = bob.keyPair();
    }

    @Nested
    @DisplayName("1. Happy Path & Core Signature Verification")
    class HappyPathTests {

        @Test
        @DisplayName("Valid RSA-3072 manifest signature generates and verifies successfully")
        void testSignAndVerifyManifestSuccess() {
            byte[] signature = signatureService.signManifest(aliceKeyPair.getPrivate(), SAMPLE_MANIFEST);

            assertNotNull(signature);
            assertEquals(384, signature.length, "RSA-3072 signature must be exactly 384 bytes (3072 bits)");

            boolean verified = signatureService.verifyManifest(aliceKeyPair.getPublic(), SAMPLE_MANIFEST, signature);
            assertTrue(verified, "Cryptographically valid RSA-PSS signature must verify to true");
        }

        @Test
        @DisplayName("Raw data sign and verify primitive functions correctly")
        void testSignAndVerifyRawData() {
            byte[] rawData = "Direct binary payload without domain label".getBytes(StandardCharsets.UTF_8);
            byte[] signature = signatureService.signData(aliceKeyPair.getPrivate(), rawData);

            assertNotNull(signature);
            assertEquals(384, signature.length);

            boolean verified = signatureService.verifyData(aliceKeyPair.getPublic(), rawData, signature);
            assertTrue(verified, "Raw data signature must verify to true");
        }

        @Test
        @DisplayName("RSASSA-PSS randomized 32-byte salt produces distinct signatures for identical payload")
        void testRandomizedSaltProducesDistinctSignatures() {
            byte[] sig1 = signatureService.signManifest(aliceKeyPair.getPrivate(), SAMPLE_MANIFEST);
            byte[] sig2 = signatureService.signManifest(aliceKeyPair.getPrivate(), SAMPLE_MANIFEST);

            assertNotNull(sig1);
            assertNotNull(sig2);
            assertFalse(Arrays.equals(sig1, sig2),
                    "RSASSA-PSS with 32-byte randomized salt MUST produce distinct signatures on subsequent runs");

            assertTrue(signatureService.verifyManifest(aliceKeyPair.getPublic(), SAMPLE_MANIFEST, sig1));
            assertTrue(signatureService.verifyManifest(aliceKeyPair.getPublic(), SAMPLE_MANIFEST, sig2));
        }

        @Test
        @DisplayName("Large manifest payload (64 KB) signs and verifies reliably")
        void testLargeManifestSignAndVerify() {
            byte[] largeManifest = new byte[64 * 1024];
            Arrays.fill(largeManifest, (byte) 'M');

            byte[] signature = signatureService.signManifest(aliceKeyPair.getPrivate(), largeManifest);
            assertNotNull(signature);
            assertEquals(384, signature.length);

            assertTrue(signatureService.verifyManifest(aliceKeyPair.getPublic(), largeManifest, signature));
        }
    }

    @Nested
    @DisplayName("2. Negative Integrity, Tampering & Wrong Key Tests")
    class NegativeIntegrityTests {

        @Test
        @DisplayName("Wrong public key (Bob verifying Alice's signature) fails verification")
        void testWrongPublicKeyFails() {
            byte[] signature = signatureService.signManifest(aliceKeyPair.getPrivate(), SAMPLE_MANIFEST);

            boolean verified = signatureService.verifyManifest(bobKeyPair.getPublic(), SAMPLE_MANIFEST, signature);
            assertFalse(verified, "Verification with unassociated public key must fail");
        }

        @Test
        @DisplayName("Modified manifest bytes (single byte altered) fails verification")
        void testModifiedManifestBytesFails() {
            byte[] signature = signatureService.signManifest(aliceKeyPair.getPrivate(), SAMPLE_MANIFEST);

            byte[] tamperedManifest = SAMPLE_MANIFEST.clone();
            tamperedManifest[tamperedManifest.length / 2] ^= 0x01; // flip 1 bit

            boolean verified = signatureService.verifyManifest(aliceKeyPair.getPublic(), tamperedManifest, signature);
            assertFalse(verified, "Manifest with altered byte must fail cryptographic verification");
        }

        @Test
        @DisplayName("Modified signature bytes (single bit inverted) fails verification")
        void testModifiedSignatureBitFails() {
            byte[] signature = signatureService.signManifest(aliceKeyPair.getPrivate(), SAMPLE_MANIFEST);

            byte[] corruptedSignature = signature.clone();
            corruptedSignature[10] ^= 0x01; // flip 1 bit

            boolean verified = signatureService.verifyManifest(aliceKeyPair.getPublic(), SAMPLE_MANIFEST, corruptedSignature);
            assertFalse(verified, "Corrupted signature bytes must fail verification");
        }

        @Test
        @DisplayName("Truncated signature bytes fail verification safely")
        void testTruncatedSignatureFails() {
            byte[] signature = signatureService.signManifest(aliceKeyPair.getPrivate(), SAMPLE_MANIFEST);

            byte[] truncated = Arrays.copyOf(signature, signature.length - 16);

            boolean verified = signatureService.verifyManifest(aliceKeyPair.getPublic(), SAMPLE_MANIFEST, truncated);
            assertFalse(verified, "Truncated signature must fail safely");
        }

        @Test
        @DisplayName("Completely random signature bytes fail verification safely")
        void testRandomGarbageSignatureFails() {
            byte[] garbage = new byte[384];
            Arrays.fill(garbage, (byte) 0xAA);

            boolean verified = signatureService.verifyManifest(aliceKeyPair.getPublic(), SAMPLE_MANIFEST, garbage);
            assertFalse(verified, "Garbage signature must return false");
        }

        @Test
        @DisplayName("Signature generated without domain separation fails verifyManifest")
        void testSignatureWithoutDomainSeparationFails() {
            // Sign raw manifest bytes directly without domain label
            byte[] rawSignature = signatureService.signData(aliceKeyPair.getPrivate(), SAMPLE_MANIFEST);

            // Attempt to verify via verifyManifest (which expects the domain label prefix)
            boolean verified = signatureService.verifyManifest(aliceKeyPair.getPublic(), SAMPLE_MANIFEST, rawSignature);
            assertFalse(verified, "Signature missing domain separation prefix must fail verifyManifest");
        }

        @Test
        @DisplayName("Null manifest or signature bytes in verification return false safely")
        void testNullInputsInVerificationReturnFalse() {
            byte[] signature = signatureService.signManifest(aliceKeyPair.getPrivate(), SAMPLE_MANIFEST);

            assertFalse(signatureService.verifyManifest(aliceKeyPair.getPublic(), null, signature));
            assertFalse(signatureService.verifyManifest(aliceKeyPair.getPublic(), SAMPLE_MANIFEST, null));
            assertFalse(signatureService.verifyManifest(aliceKeyPair.getPublic(), SAMPLE_MANIFEST, new byte[0]));
        }
    }

    @Nested
    @DisplayName("3. RSA Key Size & Cryptographic Configuration Enforcement")
    class KeyEnforcementTests {

        @Test
        @DisplayName("validatePrivateKey accepts valid 3072-bit RSA private key")
        void testValidatePrivateKeyAccepts3072() {
            assertDoesNotThrow(() -> signatureService.validatePrivateKey(aliceKeyPair.getPrivate()));
        }

        @Test
        @DisplayName("validatePublicKey accepts valid 3072-bit RSA public key")
        void testValidatePublicKeyAccepts3072() {
            assertDoesNotThrow(() -> signatureService.validatePublicKey(aliceKeyPair.getPublic()));
        }

        @Test
        @DisplayName("Weak 2048-bit RSA private and public key rejected with KeyValidationException")
        void testWeak2048BitRsaKeyRejected() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair weakKp = kpg.generateKeyPair();

            KeyValidationException privEx = assertThrows(KeyValidationException.class,
                    () -> signatureService.validatePrivateKey(weakKp.getPrivate()));
            assertTrue(privEx.getMessage().contains("2048"), "Error must report the weak bit length");

            KeyValidationException pubEx = assertThrows(KeyValidationException.class,
                    () -> signatureService.validatePublicKey(weakKp.getPublic()));
            assertTrue(pubEx.getMessage().contains("2048"));

            assertThrows(KeyValidationException.class,
                    () -> signatureService.signManifest(weakKp.getPrivate(), SAMPLE_MANIFEST));
            assertThrows(KeyValidationException.class,
                    () -> signatureService.verifyManifest(weakKp.getPublic(), SAMPLE_MANIFEST, new byte[256]));
        }

        @Test
        @DisplayName("Weak 1024-bit RSA key rejected with KeyValidationException")
        void testWeak1024BitRsaKeyRejected() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            KeyPair weakKp = kpg.generateKeyPair();

            assertThrows(KeyValidationException.class,
                    () -> signatureService.validatePrivateKey(weakKp.getPrivate()));
            assertThrows(KeyValidationException.class,
                    () -> signatureService.validatePublicKey(weakKp.getPublic()));
        }

        @Test
        @DisplayName("Non-RSA key (e.g. Elliptic Curve secp256r1) rejected with KeyValidationException")
        void testNonRsaKeyRejected() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair ecKp = kpg.generateKeyPair();

            assertThrows(KeyValidationException.class,
                    () -> signatureService.validatePrivateKey(ecKp.getPrivate()));
            assertThrows(KeyValidationException.class,
                    () -> signatureService.validatePublicKey(ecKp.getPublic()));
        }

        @Test
        @DisplayName("Null private key or public key rejected with KeyValidationException")
        void testNullKeysRejected() {
            assertThrows(KeyValidationException.class, () -> signatureService.validatePrivateKey(null));
            assertThrows(KeyValidationException.class, () -> signatureService.validatePublicKey(null));
        }
    }

    @Nested
    @DisplayName("4. Domain Separation Specification Tests")
    class DomainSeparationTests {

        @Test
        @DisplayName("applyDomainSeparation correctly prepends fixed label 'ACNS-DSIG-v1\\0'")
        void testApplyDomainSeparation() {
            byte[] input = "test-manifest".getBytes(StandardCharsets.UTF_8);
            byte[] prefixed = SignatureService.applyDomainSeparation(input);

            assertEquals(CryptoConfig.DOMAIN_LABEL.length + input.length, prefixed.length);

            byte[] extractedPrefix = Arrays.copyOfRange(prefixed, 0, CryptoConfig.DOMAIN_LABEL.length);
            assertArrayEquals(CryptoConfig.DOMAIN_LABEL, extractedPrefix);

            byte[] extractedPayload = Arrays.copyOfRange(prefixed, CryptoConfig.DOMAIN_LABEL.length, prefixed.length);
            assertArrayEquals(input, extractedPayload);
        }

        @Test
        @DisplayName("applyDomainSeparation rejects null or empty manifest bytes")
        void testApplyDomainSeparationRejectsNullOrEmpty() {
            assertThrows(IllegalArgumentException.class, () -> SignatureService.applyDomainSeparation(null));
            assertThrows(IllegalArgumentException.class, () -> SignatureService.applyDomainSeparation(new byte[0]));
        }
    }

    @Nested
    @DisplayName("5. Algorithm Configuration & Diagnostics Specification Tests")
    class AlgorithmValidationTests {

        @Test
        @DisplayName("validateAlgorithm accepts official RSASSA-PSS identifier")
        void testValidateAlgorithmAcceptsOfficialIdentifier() {
            assertDoesNotThrow(() -> signatureService.validateAlgorithm(CryptoConfig.MANIFEST_SIG_ALG));
            assertDoesNotThrow(() -> signatureService.validateAlgorithm("RSASSA-PSS-SHA256-MGF1SHA256-S32"));
        }

        @Test
        @DisplayName("validateAlgorithm rejects unauthorized legacy/non-PSS schemes")
        void testValidateAlgorithmRejectsUnauthorizedSchemes() {
            assertThrows(CryptoException.class, () -> signatureService.validateAlgorithm("SHA256withRSA"));
            assertThrows(CryptoException.class, () -> signatureService.validateAlgorithm("NONEwithRSA"));
            assertThrows(CryptoException.class, () -> signatureService.validateAlgorithm("SHA256withECDSA"));
            assertThrows(CryptoException.class, () -> signatureService.validateAlgorithm("ED25519"));
            assertThrows(CryptoException.class, () -> signatureService.validateAlgorithm(""));
            assertThrows(CryptoException.class, () -> signatureService.validateAlgorithm(null));
        }

        @Test
        @DisplayName("describeEngine returns complete authoritative cryptographic parameters")
        void testDescribeEngineParameters() {
            SignatureService.SignatureEngineInfo info = signatureService.describeEngine();

            assertNotNull(info);
            assertEquals("RSASSA-PSS", info.signatureAlgorithm());
            assertEquals("RSASSA-PSS-SHA256-MGF1SHA256-S32", info.manifestAlgorithmId());
            assertEquals("SHA-256", info.hashAlgorithm());
            assertEquals("MGF1", info.mgfAlgorithm());
            assertEquals("SHA-256", info.mgfHashAlgorithm());
            assertEquals(32, info.saltLengthBytes());
            assertEquals(1, info.trailerField());
            assertEquals(3072, info.minRsaKeyBits());
            assertEquals("ACNS-DSIG-v1\0", info.domainLabel());
        }

        @Test
        @DisplayName("getPssParameterSpec matches official RFC 8017 / RFC 4055 configuration")
        void testPssParameterSpec() {
            var spec = signatureService.getPssParameterSpec();
            assertEquals("SHA-256", spec.getDigestAlgorithm());
            assertEquals("MGF1", spec.getMGFAlgorithm());
            assertEquals(32, spec.getSaltLength());
            assertEquals(1, spec.getTrailerField());
        }
    }
}
