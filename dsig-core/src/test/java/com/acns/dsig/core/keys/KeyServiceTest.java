package com.acns.dsig.core.keys;

import com.acns.dsig.core.crypto.CryptoConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("KeyService Unit Tests")
class KeyServiceTest {

    private KeyService keyService;

    @BeforeEach
    void setUp() {
        keyService = new KeyService();
    }

    @Test
    @DisplayName("Generated key pair strictly satisfies RSA-3072 and exponent 65537")
    void testGenerateCompliantKeyPair() {
        KeyService.GeneratedKeyPair result = keyService.generateKeyPair();

        assertNotNull(result);
        assertNotNull(result.keyPair());
        assertNotNull(result.keyPair().getPublic());
        assertNotNull(result.keyPair().getPrivate());

        assertInstanceOf(RSAPublicKey.class, result.keyPair().getPublic());
        assertInstanceOf(RSAPrivateKey.class, result.keyPair().getPrivate());

        RSAPublicKey pub = (RSAPublicKey) result.keyPair().getPublic();
        RSAPrivateKey priv = (RSAPrivateKey) result.keyPair().getPrivate();

        assertEquals(CryptoConfig.RSA_KEY_BITS, pub.getModulus().bitLength(),
                "Public key modulus must be exactly 3072 bits");
        assertEquals(CryptoConfig.RSA_KEY_BITS, priv.getModulus().bitLength(),
                "Private key modulus must be exactly 3072 bits");
        assertEquals(RSAKeyGenParameterSpec.F4, pub.getPublicExponent(),
                "Public exponent must be standard F4 (65537)");
    }

    @Test
    @DisplayName("Fingerprint and Key ID are correctly computed and bound to generated key")
    void testFingerprintAndKeyIdBinding() {
        KeyService.GeneratedKeyPair result = keyService.generateKeyPair();

        String rawFp = result.fingerprint();
        assertNotNull(rawFp);
        assertEquals(64, rawFp.length(), "SHA-256 fingerprint must be 64 hex characters");
        assertTrue(rawFp.matches("^[0-9a-f]{64}$"), "Fingerprint must be lowercase hex");

        // Verify matches direct Fingerprint utility calculation
        String expectedFp = Fingerprint.calculate(result.keyPair().getPublic());
        assertEquals(expectedFp, rawFp);

        // Verify formatted fingerprint
        String formatted = result.formattedFingerprint();
        assertNotNull(formatted);
        assertEquals(Fingerprint.formatGrouped(rawFp), formatted);

        // Verify key ID
        String keyId = result.keyId();
        assertNotNull(keyId);
        assertEquals(16, keyId.length(), "Key ID must be 16 characters");
        assertEquals(rawFp.substring(0, 16), keyId);
    }

    @Test
    @DisplayName("Consecutive key generations produce distinct, cryptographically random keys")
    void testKeyEntropyAndRandomness() {
        KeyService.GeneratedKeyPair kp1 = keyService.generateKeyPair();
        KeyService.GeneratedKeyPair kp2 = keyService.generateKeyPair();

        RSAPublicKey pub1 = (RSAPublicKey) kp1.keyPair().getPublic();
        RSAPublicKey pub2 = (RSAPublicKey) kp2.keyPair().getPublic();

        assertNotEquals(pub1.getModulus(), pub2.getModulus(),
                "Different key generations must not produce the same RSA modulus");
        assertNotEquals(kp1.fingerprint(), kp2.fingerprint(),
                "Different key pairs must yield distinct fingerprints");
        assertNotEquals(kp1.keyId(), kp2.keyId(),
                "Different key pairs must yield distinct key IDs");
    }
}
