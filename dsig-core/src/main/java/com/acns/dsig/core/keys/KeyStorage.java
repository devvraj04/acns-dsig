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
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * Storage and serialization service for RSA keys:
 * - Passphrase-based encrypted PKCS#8 storage using PBES2/PBEWithHmacSHA256AndAES_256
 * - Minimum RSA key size enforcement (>= 3072 bits) on export and import
 * - Export/import of Public Keys in PEM SubjectPublicKeyInfo format
 * - In-memory passphrase zeroization support
 */
public class KeyStorage {

    public static final String PBE_ALGORITHM = "PBEWithHmacSHA256AndAES_256";
    public static final int PBE_ITERATION_COUNT = 600_000;
    public static final int SALT_BYTES = 16;

    public static final String PEM_PUBLIC_BEGIN = "-----BEGIN PUBLIC KEY-----";
    public static final String PEM_PUBLIC_END = "-----END PUBLIC KEY-----";
    public static final String PEM_ENCRYPTED_PRIVATE_BEGIN = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
    public static final String PEM_ENCRYPTED_PRIVATE_END = "-----END ENCRYPTED PRIVATE KEY-----";

    /**
     * Wipes sensitive character arrays from memory by overwriting with null characters.
     *
     * @param secret character array to clear
     */
    public static void zeroize(char[] secret) {
        if (secret != null) {
            Arrays.fill(secret, '\0');
        }
    }

    /**
     * Exports an RSA public key into standard PEM format.
     *
     * @param publicKey the RSA public key to export
     * @return PEM formatted string
     * @throws KeyValidationException if key is null, not RSA, or smaller than 3072 bits
     */
    public static String exportPublicKeyToPem(PublicKey publicKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("PublicKey cannot be null");
        }
        if (!(publicKey instanceof RSAPublicKey rsaPub)) {
            throw new KeyValidationException("Cannot export non-RSA public key");
        }
        int bitLength = rsaPub.getModulus().bitLength();
        if (bitLength < CryptoConfig.RSA_KEY_BITS) {
            throw new KeyValidationException("Cannot export RSA public key with bit length (" + bitLength
                    + ") below required minimum of " + CryptoConfig.RSA_KEY_BITS + " bits");
        }

        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(publicKey.getEncoded());
        return PEM_PUBLIC_BEGIN + "\n" + base64 + "\n" + PEM_PUBLIC_END + "\n";
    }

    /**
     * Parses and validates an RSA public key from PEM text or Base64 SPKI.
     * Enforces that the key is RSA and satisfies the mandatory minimum bit length (>= 3072 bits).
     *
     * @param pem PEM string or Base64 encoded SPKI bytes
     * @return validated RSAPublicKey instance
     * @throws KeyValidationException if parsing fails, key is not RSA, or bit length < 3072
     */
    public static PublicKey parsePublicKeyFromPem(String pem) {
        if (pem == null || pem.isBlank()) {
            throw new KeyValidationException("Public key PEM cannot be null or blank");
        }
        try {
            String clean = pem
                    .replace(PEM_PUBLIC_BEGIN, "")
                    .replace(PEM_PUBLIC_END, "")
                    .replaceAll("\\s+", "");

            if (clean.isEmpty()) {
                throw new KeyValidationException("Public key PEM contains no key payload");
            }

            byte[] der = Base64.getDecoder().decode(clean);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
            KeyFactory kf = KeyFactory.getInstance(CryptoConfig.KEY_ALGORITHM);
            PublicKey pub = kf.generatePublic(spec);

            if (!(pub instanceof RSAPublicKey rsaPub)) {
                throw new KeyValidationException("Parsed key is not an RSA public key");
            }

            int bitLength = rsaPub.getModulus().bitLength();
            if (bitLength < CryptoConfig.RSA_KEY_BITS) {
                throw new KeyValidationException("RSA public key bit length (" + bitLength
                        + ") is below required minimum of " + CryptoConfig.RSA_KEY_BITS + " bits");
            }

            return rsaPub;
        } catch (KeyValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new KeyValidationException("Failed to parse public key from PEM: " + e.getMessage(), e);
        }
    }

    /**
     * Encrypts an RSA private key using PBES2 AES-256 and writes to a file in PKCS#8 encrypted format.
     * Enforces that the key satisfies the mandatory minimum bit length (>= 3072 bits).
     *
     * @param privateKey the private key to encrypt and save
     * @param passphrase passphrase used for encryption
     * @param targetPath file destination path
     * @throws IOException if writing to targetPath fails
     * @throws KeyValidationException if key is not RSA or smaller than 3072 bits
     * @throws CryptoException if encryption fails
     */
    public void saveEncryptedPrivateKey(PrivateKey privateKey, char[] passphrase, Path targetPath) throws IOException {
        if (privateKey == null) {
            throw new IllegalArgumentException("PrivateKey cannot be null");
        }
        if (passphrase == null || passphrase.length == 0) {
            throw new IllegalArgumentException("Passphrase cannot be null or empty");
        }
        if (targetPath == null) {
            throw new IllegalArgumentException("Target path cannot be null");
        }

        if (!(privateKey instanceof RSAPrivateKey rsaPriv)) {
            throw new KeyValidationException("Cannot save non-RSA private key");
        }
        int bitLength = rsaPriv.getModulus().bitLength();
        if (bitLength < CryptoConfig.RSA_KEY_BITS) {
            throw new KeyValidationException("Cannot save RSA private key with bit length (" + bitLength
                    + ") below required minimum of " + CryptoConfig.RSA_KEY_BITS + " bits");
        }

        try {
            if (targetPath.getParent() != null && !Files.exists(targetPath.getParent())) {
                Files.createDirectories(targetPath.getParent());
            }

            byte[] salt = new byte[SALT_BYTES];
            new SecureRandom().nextBytes(salt);

            PBEKeySpec pbeKeySpec = new PBEKeySpec(passphrase);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
            SecretKey pbeKey = keyFactory.generateSecret(pbeKeySpec);

            PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, PBE_ITERATION_COUNT);
            Cipher cipher = Cipher.getInstance(PBE_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

            byte[] encryptedKey = cipher.doFinal(privateKey.getEncoded());

            // Initialize standard PBES2 parameters for standard PKCS#8 OID mapping
            AlgorithmParameters pbes2Params = AlgorithmParameters.getInstance("PBES2");
            pbes2Params.init(cipher.getParameters().getEncoded());

            EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(pbes2Params, encryptedKey);
            byte[] encoded = epki.getEncoded();

            String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(encoded);
            String pem = PEM_ENCRYPTED_PRIVATE_BEGIN + "\n" + base64 + "\n" + PEM_ENCRYPTED_PRIVATE_END + "\n";

            Files.writeString(targetPath, pem, StandardCharsets.UTF_8);
        } catch (KeyValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("Failed to encrypt and save private key", e);
        }
    }

    /**
     * Reads and decrypts an encrypted PKCS#8 private key using the supplied passphrase.
     * Enforces minimum RSA key size (>= 3072 bits) and masks decryption/passphrase errors
     * with generic sanitized messages.
     *
     * @param keyPath path to encrypted private key file
     * @param passphrase decryption passphrase
     * @return decrypted RSAPrivateKey instance
     * @throws IOException if reading the file fails
     * @throws KeyValidationException if key is smaller than 3072 bits
     * @throws CryptoException if passphrase is wrong or file is corrupted
     */
    public PrivateKey loadEncryptedPrivateKey(Path keyPath, char[] passphrase) throws IOException {
        if (keyPath == null) {
            throw new IllegalArgumentException("Key path cannot be null");
        }
        if (passphrase == null || passphrase.length == 0) {
            throw new IllegalArgumentException("Passphrase cannot be null or empty");
        }
        if (!Files.exists(keyPath)) {
            throw new CryptoException("Key file not found: " + keyPath);
        }

        try {
            String pemContent = Files.readString(keyPath, StandardCharsets.UTF_8);
            String clean = pemContent
                    .replace(PEM_ENCRYPTED_PRIVATE_BEGIN, "")
                    .replace(PEM_ENCRYPTED_PRIVATE_END, "")
                    .replaceAll("\\s+", "");

            if (clean.isEmpty()) {
                throw new CryptoException("Invalid passphrase or corrupted key file");
            }

            byte[] encoded = Base64.getDecoder().decode(clean);
            EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(encoded);

            PBEKeySpec pbeKeySpec = new PBEKeySpec(passphrase);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(epki.getAlgName());
            SecretKey pbeKey = keyFactory.generateSecret(pbeKeySpec);

            Cipher cipher = Cipher.getInstance(epki.getAlgName());
            cipher.init(Cipher.DECRYPT_MODE, pbeKey, epki.getAlgParameters());

            PKCS8EncodedKeySpec keySpec = epki.getKeySpec(cipher);
            KeyFactory kf = KeyFactory.getInstance(CryptoConfig.KEY_ALGORITHM);
            PrivateKey privKey = kf.generatePrivate(keySpec);

            if (!(privKey instanceof RSAPrivateKey rsaPriv)) {
                throw new KeyValidationException("Decrypted key is not an RSA private key");
            }

            int bitLength = rsaPriv.getModulus().bitLength();
            if (bitLength < CryptoConfig.RSA_KEY_BITS) {
                throw new KeyValidationException("Decrypted RSA private key bit length (" + bitLength
                        + ") is below required minimum of " + CryptoConfig.RSA_KEY_BITS + " bits");
            }

            return rsaPriv;
        } catch (KeyValidationException e) {
            throw e;
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            // Mask wrong passphrase and corrupted ciphertext with uniform error message
            throw new CryptoException("Invalid passphrase or corrupted key file", e);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("Failed to load and decrypt private key", e);
        }
    }
}
