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

    public static final int FINGERPRINT_HEX_LENGTH = 64;
    public static final int KEY_ID_HEX_LENGTH = 16;

    /**
     * Extracts a canonical short Key ID (first 16 lowercase hex characters) from a full fingerprint.
     *
     * @param hexFingerprint 64-character hex fingerprint
     * @return 16-character canonical key ID
     * @throws IllegalArgumentException if hexFingerprint is invalid or too short
     */
    public static String toKeyId(String hexFingerprint) {
        if (hexFingerprint == null) {
            throw new IllegalArgumentException("Fingerprint cannot be null");
        }
        String clean = hexFingerprint.replaceAll("\\s+", "").toLowerCase();
        if (clean.length() < KEY_ID_HEX_LENGTH) {
            throw new IllegalArgumentException("Fingerprint too short for Key ID extraction: " + clean.length());
        }
        return clean.substring(0, KEY_ID_HEX_LENGTH);
    }

    /**
     * Computes the canonical short Key ID directly from a PublicKey.
     *
     * @param publicKey the public key
     * @return 16-character canonical key ID
     */
    public static String toKeyId(PublicKey publicKey) {
        return toKeyId(calculate(publicKey));
    }

    /**
     * Checks if a string is a valid 64-character lowercase or uppercase SHA-256 hex fingerprint.
     *
     * @param hexFingerprint the fingerprint string to validate
     * @return true if valid 64-character hex, false otherwise
     */
    public static boolean isValidFingerprint(String hexFingerprint) {
        if (hexFingerprint == null) {
            return false;
        }
        String clean = hexFingerprint.replaceAll("\\s+", "");
        return clean.length() == FINGERPRINT_HEX_LENGTH && clean.matches("^[0-9a-fA-F]{64}$");
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
