package com.acns.dsig.core.keys;

import com.acns.dsig.core.crypto.CryptoConfig;
import com.acns.dsig.core.error.CryptoException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.HexFormat;

/**
 * Public key fingerprint calculation and formatting utility.
 * Fingerprint is calculated as SHA-256 over the DER-encoded SubjectPublicKeyInfo bytes.
 */
public final class Fingerprint {

    private Fingerprint() {}

    /**
     * Computes the normalized lowercase hex SHA-256 fingerprint from a PublicKey.
     */
    public static String calculate(PublicKey publicKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("PublicKey cannot be null");
        }
        return calculateFromDer(publicKey.getEncoded());
    }

    /**
     * Computes the normalized lowercase hex SHA-256 fingerprint from DER-encoded SPKI bytes.
     */
    public static String calculateFromDer(byte[] spkiDerBytes) {
        if (spkiDerBytes == null || spkiDerBytes.length == 0) {
            throw new IllegalArgumentException("SPKI DER bytes cannot be null or empty");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance(CryptoConfig.HASH_ALGORITHM);
            byte[] hash = digest.digest(spkiDerBytes);
            return HexFormat.of().formatHex(hash).toLowerCase();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("SHA-256 algorithm not available for fingerprint calculation", e);
        }
    }

    /**
     * Formats a hex fingerprint into uppercase grouped blocks (e.g., "AB12 34CD 56EF ...").
     */
    public static String formatGrouped(String hexFingerprint) {
        if (hexFingerprint == null) return "";
        String clean = hexFingerprint.replaceAll("\\s+", "").toUpperCase();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < clean.length(); i++) {
            if (i > 0 && i % 4 == 0) {
                sb.append(' ');
            }
            sb.append(clean.charAt(i));
        }
        return sb.toString();
    }
}
