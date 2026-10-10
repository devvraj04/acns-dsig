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
    ) {}

    /**
     * Generates a compliant RSA-3072 key pair with exponent 65537 using SecureRandom.
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

            if (!(pair.getPublic() instanceof RSAPublicKey) || !(pair.getPrivate() instanceof RSAPrivateKey)) {
                throw new KeyValidationException("Generated key pair is not RSA");
            }

            String fp = Fingerprint.calculate(pair.getPublic());
            String formattedFp = Fingerprint.formatGrouped(fp);

            return new GeneratedKeyPair(pair, fp, formattedFp);
        } catch (NoSuchAlgorithmException | java.security.InvalidAlgorithmParameterException e) {
            throw new CryptoException("Failed to generate RSA-3072 key pair", e);
        }
    }
}
