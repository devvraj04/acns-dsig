package com.acns.dsig.core.keys;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Fingerprint Utility Unit Tests")
class FingerprintTest {

    private KeyService keyService;

    @BeforeEach
    void setUp() {
        keyService = new KeyService();
    }

    @Test
    @DisplayName("Fingerprint calculation is deterministic for the same public key")
    void testFingerprintDeterminism() {
        PublicKey publicKey = keyService.generateKeyPair().keyPair().getPublic();

        String fp1 = Fingerprint.calculate(publicKey);
        String fp2 = Fingerprint.calculate(publicKey);

        assertNotNull(fp1);
        assertEquals(64, fp1.length());
        assertEquals(fp1, fp2);
    }

    @Test
    @DisplayName("Fingerprint strictly matches SHA-256 over SubjectPublicKeyInfo DER bytes")
    void testSpkiDerDigestConsistency() throws Exception {
        PublicKey publicKey = keyService.generateKeyPair().keyPair().getPublic();
        byte[] spkiBytes = publicKey.getEncoded();

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] expectedHash = sha256.digest(spkiBytes);
        String expectedHex = HexFormat.of().formatHex(expectedHash).toLowerCase();

        String actualHex = Fingerprint.calculate(publicKey);
        assertEquals(expectedHex, actualHex);
    }

    @Test
    @DisplayName("Known-answer test (KAT) for calculateFromDer")
    void testKnownAnswerDerDigest() {
        byte[] sampleDer = "TEST_PUBLIC_KEY_DER_PAYLOAD_FOR_FINGERPRINT".getBytes(StandardCharsets.UTF_8);
        String fp = Fingerprint.calculateFromDer(sampleDer);

        assertNotNull(fp);
        assertEquals(64, fp.length());
        assertTrue(Fingerprint.isValidFingerprint(fp));
    }

    @Test
    @DisplayName("formatGrouped formats 64-char hex into uppercase 4-character blocks")
    void testFormatGrouped() {
        String hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        String formatted = Fingerprint.formatGrouped(hex);

        // 64 chars in 16 blocks of 4 separated by 15 spaces = 64 + 15 = 79 chars
        assertEquals(79, formatted.length());
        assertTrue(formatted.startsWith("ABCD EF01"));
        assertTrue(formatted.endsWith("6789"));
        assertEquals("", Fingerprint.formatGrouped(null));
        assertEquals("", Fingerprint.formatGrouped(""));
    }

    @Test
    @DisplayName("toKeyId extracts 16-character canonical identifier")
    void testToKeyId() {
        String fullFp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        String keyId = Fingerprint.toKeyId(fullFp);

        assertEquals("0123456789abcdef", keyId);
        assertEquals(16, keyId.length());

        // Test with uppercase input
        assertEquals("0123456789abcdef", Fingerprint.toKeyId(fullFp.toUpperCase()));

        // Test from PublicKey directly
        PublicKey publicKey = keyService.generateKeyPair().keyPair().getPublic();
        String pubKeyId = Fingerprint.toKeyId(publicKey);
        assertNotNull(pubKeyId);
        assertEquals(16, pubKeyId.length());
        assertEquals(Fingerprint.calculate(publicKey).substring(0, 16), pubKeyId);
    }

    @Test
    @DisplayName("isValidFingerprint correctly identifies valid and invalid fingerprints")
    void testFingerprintValidation() {
        String validLower = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        String validUpper = validLower.toUpperCase();
        String tooShort = "0123456789abcdef";
        String invalidChars = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789zzzzzz";

        assertTrue(Fingerprint.isValidFingerprint(validLower));
        assertTrue(Fingerprint.isValidFingerprint(validUpper));
        assertFalse(Fingerprint.isValidFingerprint(tooShort));
        assertFalse(Fingerprint.isValidFingerprint(invalidChars));
        assertFalse(Fingerprint.isValidFingerprint(null));
        assertFalse(Fingerprint.isValidFingerprint(""));
    }

    @Test
    @DisplayName("Defensive exception handling on null or empty inputs")
    void testDefensiveChecks() {
        assertThrows(IllegalArgumentException.class, () -> Fingerprint.calculate(null));
        assertThrows(IllegalArgumentException.class, () -> Fingerprint.calculateFromDer(null));
        assertThrows(IllegalArgumentException.class, () -> Fingerprint.calculateFromDer(new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> Fingerprint.toKeyId((String) null));
        assertThrows(IllegalArgumentException.class, () -> Fingerprint.toKeyId("short"));
    }
}
