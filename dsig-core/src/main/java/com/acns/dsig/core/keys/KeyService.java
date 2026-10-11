package com.acns.dsig.core.keys;

import com.acns.dsig.core.crypto.CryptoConfig;
import com.acns.dsig.core.error.CryptoException;
import com.acns.dsig.core.error.KeyValidationException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;

/**
 * Service for generating RSA-3072 cryptographic key pairs with SecureRandom.
 */
public class KeyService {

    public record GeneratedKeyPair(
            KeyPair keyPair,
            String fingerprint,
            String formattedFingerprint
    ) {
        /**
         * Returns the canonical 16-character short Key ID derived from the public key fingerprint.
         */
        public String keyId() {
            return Fingerprint.toKeyId(fingerprint);
        }
    }

    /**
     * Generates a compliant RSA-3072 key pair with exponent 65537 using SecureRandom.
     * Enforces key size and exponent validation before returning.
     *
     * @return GeneratedKeyPair containing KeyPair, full fingerprint, formatted fingerprint, and keyId
     */
    public GeneratedKeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(CryptoConfig.KEY_ALGORITHM);
            RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(
                    CryptoConfig.RSA_KEY_BITS,
                    RSAKeyGenParameterSpec.F4 // 65537
            );
            generator.initialize(spec, new SecureRandom());
            KeyPair pair = generator.generateKeyPair();

            if (!(pair.getPublic() instanceof RSAPublicKey pub) || !(pair.getPrivate() instanceof RSAPrivateKey priv)) {
                throw new KeyValidationException("Generated key pair is not RSA");
            }

            if (pub.getModulus().bitLength() < CryptoConfig.RSA_KEY_BITS) {
                throw new KeyValidationException("Generated RSA key modulus bit length ("
                        + pub.getModulus().bitLength() + ") is below required " + CryptoConfig.RSA_KEY_BITS + " bits");
            }

            if (!pub.getPublicExponent().equals(RSAKeyGenParameterSpec.F4)) {
                throw new KeyValidationException("Generated RSA key exponent must be 65537 (F4)");
            }

            String fp = Fingerprint.calculate(pub);
            String formattedFp = Fingerprint.formatGrouped(fp);

            return new GeneratedKeyPair(pair, fp, formattedFp);
        } catch (NoSuchAlgorithmException | java.security.InvalidAlgorithmParameterException e) {
            throw new CryptoException("Failed to generate RSA-3072 key pair", e);
        }
    }
}
