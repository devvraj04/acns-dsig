package com.acns.dsig.core.crypto;

import com.acns.dsig.core.error.CryptoException;
import com.acns.dsig.core.error.KeyValidationException;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;

/**
 * Service for RSA-PSS digital signatures using SHA-256, MGF1, and 32-byte salt.
 * Incorporates protocol domain separation label "ACNS-DSIG-v1\0".
 */
public class SignatureService {

    /**
     * Constructs domain-separated message payload: LABEL || manifestBytes.
     */
    public static byte[] applyDomainSeparation(byte[] manifestBytes) {
        if (manifestBytes == null) {
            throw new IllegalArgumentException("Manifest bytes cannot be null");
        }
        byte[] payload = new byte[CryptoConfig.DOMAIN_LABEL.length + manifestBytes.length];
        System.arraycopy(CryptoConfig.DOMAIN_LABEL, 0, payload, 0, CryptoConfig.DOMAIN_LABEL.length);
        System.arraycopy(manifestBytes, 0, payload, CryptoConfig.DOMAIN_LABEL.length, manifestBytes.length);
        return payload;
    }

    /**
     * Signs the given manifest bytes using RSASSA-PSS with private key.
     */
    public byte[] signManifest(PrivateKey privateKey, byte[] manifestBytes) {
        try {
            byte[] payloadToSign = applyDomainSeparation(manifestBytes);
            Signature signer = Signature.getInstance(CryptoConfig.SIGNATURE_ALGORITHM);
            signer.setParameter(CryptoConfig.createPssParameterSpec());
            signer.initSign(privateKey);
            signer.update(payloadToSign);
            return signer.sign();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Failed to generate RSA-PSS digital signature", e);
        }
    }

    /**
     * Verifies an RSASSA-PSS signature over the domain-separated manifest bytes.
     */
    public boolean verifyManifest(PublicKey publicKey, byte[] manifestBytes, byte[] signatureBytes) {
        validatePublicKey(publicKey);
        try {
            byte[] expectedPayload = applyDomainSeparation(manifestBytes);
            Signature verifier = Signature.getInstance(CryptoConfig.SIGNATURE_ALGORITHM);
            verifier.setParameter(CryptoConfig.createPssParameterSpec());
            verifier.initVerify(publicKey);
            verifier.update(expectedPayload);
            return verifier.verify(signatureBytes);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /**
     * Enforces RSA key size >= 3072 bits.
     */
    public void validatePublicKey(PublicKey publicKey) {
        if (!(publicKey instanceof RSAPublicKey rsaKey)) {
            throw new KeyValidationException("Key is not an RSA public key");
        }
        if (rsaKey.getModulus().bitLength() < CryptoConfig.RSA_KEY_BITS) {
            throw new KeyValidationException("RSA key size is " + rsaKey.getModulus().bitLength()
                    + " bits, but minimum required size is " + CryptoConfig.RSA_KEY_BITS + " bits");
        }
    }
}
