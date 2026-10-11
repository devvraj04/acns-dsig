package com.acns.dsig.core.keys;

import com.acns.dsig.core.crypto.CryptoConfig;
import com.acns.dsig.core.error.CryptoException;
import com.acns.dsig.core.error.KeyValidationException;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Storage and serialization service for RSA keys:
 * - Passphrase-based encrypted PKCS#8 storage using PBES2/PBEWithHmacSHA256AndAES_256
 * - Export/import of Public Keys in PEM SubjectPublicKeyInfo format
 */
public class KeyStorage {

    public static final String PBE_ALGORITHM = "PBEWithHmacSHA256AndAES_256";
    public static final int PBE_ITERATION_COUNT = 600_000;
    public static final int SALT_BYTES = 16;

    /**
     * Exports a public key into standard PEM format.
     */
    public static String exportPublicKeyToPem(PublicKey publicKey) {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(publicKey.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + base64 + "\n-----END PUBLIC KEY-----\n";
    }

    /**
     * Parses a public key from PEM text or Base64 SPKI.
     */
    public static PublicKey parsePublicKeyFromPem(String pem) {
        try {
            String clean = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] der = Base64.getDecoder().decode(clean);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
            KeyFactory kf = KeyFactory.getInstance(CryptoConfig.KEY_ALGORITHM);
            return kf.generatePublic(spec);
        } catch (Exception e) {
            throw new KeyValidationException("Failed to parse public key from PEM", e);
        }
    }

    /**
     * Encrypts a private key using PBES2 AES-256 and writes to a file in PKCS#8 encrypted format.
     */
    public void saveEncryptedPrivateKey(PrivateKey privateKey, char[] passphrase, Path targetPath) throws IOException {
        try {
            byte[] salt = new byte[SALT_BYTES];
            new SecureRandom().nextBytes(salt);

            PBEKeySpec pbeKeySpec = new PBEKeySpec(passphrase);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
            SecretKey pbeKey = keyFactory.generateSecret(pbeKeySpec);

            PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, PBE_ITERATION_COUNT);
            Cipher cipher = Cipher.getInstance(PBE_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

            byte[] encryptedKey = cipher.doFinal(privateKey.getEncoded());
            AlgorithmParameters algParams = cipher.getParameters();

            EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(algParams, encryptedKey);
            byte[] encoded = epki.getEncoded();

            String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(encoded);
            String pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + base64 + "\n-----END ENCRYPTED PRIVATE KEY-----\n";

            Files.writeString(targetPath, pem, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new CryptoException("Failed to encrypt and save private key", e);
        }
    }

    /**
     * Reads and decrypts an encrypted PKCS#8 private key using the supplied passphrase.
     */
    public PrivateKey loadEncryptedPrivateKey(Path keyPath, char[] passphrase) throws IOException {
        try {
            String pemContent = Files.readString(keyPath, StandardCharsets.UTF_8);
            String clean = pemContent
                    .replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "")
                    .replace("-----END ENCRYPTED PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");

            byte[] encoded = Base64.getDecoder().decode(clean);
            EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(encoded);

            PBEKeySpec pbeKeySpec = new PBEKeySpec(passphrase);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(epki.getAlgName());
            SecretKey pbeKey = keyFactory.generateSecret(pbeKeySpec);

            Cipher cipher = Cipher.getInstance(epki.getAlgName());
            cipher.init(Cipher.DECRYPT_MODE, pbeKey, epki.getAlgParameters());

            PKCS8EncodedKeySpec keySpec = epki.getKeySpec(cipher);
            KeyFactory kf = KeyFactory.getInstance(CryptoConfig.KEY_ALGORITHM);
            return kf.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new CryptoException("Invalid passphrase or corrupted key file", e);
        } catch (Exception e) {
            throw new CryptoException("Failed to load and decrypt private key", e);
        }
    }
}
