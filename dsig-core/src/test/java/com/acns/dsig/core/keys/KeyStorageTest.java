package com.acns.dsig.core.keys;

import com.acns.dsig.core.crypto.CryptoConfig;
import com.acns.dsig.core.error.CryptoException;
import com.acns.dsig.core.error.KeyValidationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("KeyStorage Unit Tests")
class KeyStorageTest {

    private KeyStorage keyStorage;
    private KeyService keyService;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        keyStorage = new KeyStorage();
        keyService = new KeyService();
    }

    @Test
    @DisplayName("Encrypted private key save and load round-trip succeeds with valid passphrase")
    void testSaveAndLoadEncryptedPrivateKeyRoundtrip() throws Exception {
        KeyService.GeneratedKeyPair kp = keyService.generateKeyPair();
        Path keyPath = tempDir.resolve("test_key.pk8");
        char[] passphrase = "ValidSecretPassphrase!2026".toCharArray();

        keyStorage.saveEncryptedPrivateKey(kp.keyPair().getPrivate(), passphrase, keyPath);

        assertTrue(Files.exists(keyPath), "Encrypted private key file must exist on disk");
        String content = Files.readString(keyPath, StandardCharsets.UTF_8);
        assertTrue(content.contains(KeyStorage.PEM_ENCRYPTED_PRIVATE_BEGIN));
        assertTrue(content.contains(KeyStorage.PEM_ENCRYPTED_PRIVATE_END));

        PrivateKey loaded = keyStorage.loadEncryptedPrivateKey(keyPath, passphrase);
        assertNotNull(loaded);
        assertInstanceOf(RSAPrivateKey.class, loaded);

        RSAPrivateKey origPriv = (RSAPrivateKey) kp.keyPair().getPrivate();
        RSAPrivateKey loadedPriv = (RSAPrivateKey) loaded;

        assertEquals(origPriv.getModulus(), loadedPriv.getModulus(),
                "Loaded private key modulus must match original modulus");
        assertEquals(CryptoConfig.RSA_KEY_BITS, loadedPriv.getModulus().bitLength(),
                "Loaded private key bit length must be 3072");
    }

    @Test
    @DisplayName("Wrong passphrase on load throws generic CryptoException without leaking details")
    void testLoadWithWrongPassphrase() throws Exception {
        KeyService.GeneratedKeyPair kp = keyService.generateKeyPair();
        Path keyPath = tempDir.resolve("auth_test_key.pk8");
        char[] correctPass = "CorrectPassphrase123".toCharArray();
        char[] wrongPass = "WrongPassphrase456".toCharArray();

        keyStorage.saveEncryptedPrivateKey(kp.keyPair().getPrivate(), correctPass, keyPath);

        CryptoException ex = assertThrows(CryptoException.class, () ->
                keyStorage.loadEncryptedPrivateKey(keyPath, wrongPass));

        assertEquals("Invalid passphrase or corrupted key file", ex.getMessage());
    }

    @Test
    @DisplayName("Corrupted ciphertext or tampered file fails safely with generic error")
    void testLoadCorruptedKeyFile() throws Exception {
        KeyService.GeneratedKeyPair kp = keyService.generateKeyPair();
        Path keyPath = tempDir.resolve("corrupted_key.pk8");
        char[] pass = "Passphrase123".toCharArray();

        keyStorage.saveEncryptedPrivateKey(kp.keyPair().getPrivate(), pass, keyPath);

        // Tamper with file content
        Files.writeString(keyPath, KeyStorage.PEM_ENCRYPTED_PRIVATE_BEGIN + "\n"
                + "AAAABBBBCCCCDDDDCorruptedPayload====" + "\n"
                + KeyStorage.PEM_ENCRYPTED_PRIVATE_END);

        CryptoException ex = assertThrows(CryptoException.class, () ->
                keyStorage.loadEncryptedPrivateKey(keyPath, pass));

        assertTrue(ex.getMessage().contains("Invalid passphrase or corrupted key file"));
    }

    @Test
    @DisplayName("Loading non-existent key file throws CryptoException")
    void testLoadNonExistentFile() {
        Path missing = tempDir.resolve("missing.pk8");
        char[] pass = "Passphrase123".toCharArray();

        CryptoException ex = assertThrows(CryptoException.class, () ->
                keyStorage.loadEncryptedPrivateKey(missing, pass));

        assertTrue(ex.getMessage().contains("not found"));
    }

    @Test
    @DisplayName("Public key PEM export and import round-trip preserves key material")
    void testExportAndParsePublicKeyPemRoundtrip() {
        KeyService.GeneratedKeyPair kp = keyService.generateKeyPair();
        PublicKey pub = kp.keyPair().getPublic();

        String pem = KeyStorage.exportPublicKeyToPem(pub);
        assertNotNull(pem);
        assertTrue(pem.contains(KeyStorage.PEM_PUBLIC_BEGIN));
        assertTrue(pem.contains(KeyStorage.PEM_PUBLIC_END));

        PublicKey restored = KeyStorage.parsePublicKeyFromPem(pem);
        assertNotNull(restored);
        assertInstanceOf(RSAPublicKey.class, restored);

        RSAPublicKey origRsa = (RSAPublicKey) pub;
        RSAPublicKey restoredRsa = (RSAPublicKey) restored;

        assertEquals(origRsa.getModulus(), restoredRsa.getModulus());
        assertEquals(origRsa.getPublicExponent(), restoredRsa.getPublicExponent());
        assertEquals(CryptoConfig.RSA_KEY_BITS, restoredRsa.getModulus().bitLength());
    }

    @Test
    @DisplayName("Parsing public key from raw Base64 without PEM headers succeeds")
    void testParsePublicKeyRawBase64() {
        KeyService.GeneratedKeyPair kp = keyService.generateKeyPair();
        String rawBase64 = Base64.getEncoder().encodeToString(kp.keyPair().getPublic().getEncoded());

        PublicKey restored = KeyStorage.parsePublicKeyFromPem(rawBase64);
        assertNotNull(restored);
        assertInstanceOf(RSAPublicKey.class, restored);
        assertEquals(((RSAPublicKey) kp.keyPair().getPublic()).getModulus(),
                ((RSAPublicKey) restored).getModulus());
    }

    @Test
    @DisplayName("Weak RSA key (< 3072 bits) is rejected on export, import, and save")
    void testWeakKeyRejection() throws Exception {
        // Generate legacy weak 2048-bit key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair weakPair = kpg.generateKeyPair();

        // 1. Rejection on export
        KeyValidationException exExport = assertThrows(KeyValidationException.class, () ->
                KeyStorage.exportPublicKeyToPem(weakPair.getPublic()));
        assertTrue(exExport.getMessage().contains("below required minimum of 3072 bits"));

        // 2. Rejection on parsing PEM
        String weakRawBase64 = Base64.getEncoder().encodeToString(weakPair.getPublic().getEncoded());
        String weakPem = "-----BEGIN PUBLIC KEY-----\n" + weakRawBase64 + "\n-----END PUBLIC KEY-----\n";
        KeyValidationException exParse = assertThrows(KeyValidationException.class, () ->
                KeyStorage.parsePublicKeyFromPem(weakPem));
        assertTrue(exParse.getMessage().contains("below required minimum of 3072 bits"));

        // 3. Rejection on saving private key
        Path weakKeyPath = tempDir.resolve("weak.pk8");
        char[] pass = "SomePassword".toCharArray();
        KeyValidationException exSave = assertThrows(KeyValidationException.class, () ->
                keyStorage.saveEncryptedPrivateKey(weakPair.getPrivate(), pass, weakKeyPath));
        assertTrue(exSave.getMessage().contains("below required minimum of 3072 bits"));
    }

    @Test
    @DisplayName("Malformed or empty public key PEM strings are rejected")
    void testMalformedPublicKeyPem() {
        assertThrows(KeyValidationException.class, () -> KeyStorage.parsePublicKeyFromPem(null));
        assertThrows(KeyValidationException.class, () -> KeyStorage.parsePublicKeyFromPem(""));
        assertThrows(KeyValidationException.class, () -> KeyStorage.parsePublicKeyFromPem("    "));
        assertThrows(KeyValidationException.class, () -> KeyStorage.parsePublicKeyFromPem("NOT_BASE64_AT_ALL!!!"));
    }

    @Test
    @DisplayName("zeroize clears character arrays in memory")
    void testZeroizePassphrase() {
        char[] sensitive = "SuperSensitivePass123".toCharArray();
        KeyStorage.zeroize(sensitive);

        for (char c : sensitive) {
            assertEquals('\0', c, "Character must be zeroized to null byte");
        }
    }

    @Test
    @DisplayName("Defensive input validation on null or empty arguments")
    void testDefensiveArguments() {
        Path dummyPath = tempDir.resolve("dummy.pk8");
        char[] dummyPass = "pass".toCharArray();

        assertThrows(IllegalArgumentException.class, () ->
                KeyStorage.exportPublicKeyToPem(null));
        assertThrows(IllegalArgumentException.class, () ->
                keyStorage.saveEncryptedPrivateKey(null, dummyPass, dummyPath));
        assertThrows(IllegalArgumentException.class, () ->
                keyStorage.saveEncryptedPrivateKey(keyService.generateKeyPair().keyPair().getPrivate(), null, dummyPath));
        assertThrows(IllegalArgumentException.class, () ->
                keyStorage.saveEncryptedPrivateKey(keyService.generateKeyPair().keyPair().getPrivate(), dummyPass, null));

        assertThrows(IllegalArgumentException.class, () ->
                keyStorage.loadEncryptedPrivateKey(null, dummyPass));
        assertThrows(IllegalArgumentException.class, () ->
                keyStorage.loadEncryptedPrivateKey(dummyPath, null));
    }
}
