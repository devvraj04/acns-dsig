package com.acns.dsig.core.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Constant-time comparison utilities to defend against timing side-channel attacks.
 *
 * Owned by: Devraj Sundrani (Member 2)
 *
 * Standard `Arrays.equals` and `String.equals` terminate comparison on the first mismatched
 * character/byte, which leaks timing information allowing an adversary to incrementally
 * guess matching digests.
 * This class uses standard `MessageDigest.isEqual` which guarantees constant-time evaluation.
 */
public final class ConstantTime {

    private ConstantTime() {}

    /**
     * Compares two byte arrays in constant time.
     *
     * @param a first byte array
     * @param b second byte array
     * @return true if arrays are equal in content, false otherwise
     */
    public static boolean equals(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return a == b;
        }
        return MessageDigest.isEqual(a, b);
    }

    /**
     * Compares two strings in constant time over UTF-8 bytes.
     *
     * @param a first string
     * @param b second string
     * @return true if strings match, false otherwise
     */
    public static boolean equals(String a, String b) {
        if (a == null || b == null) {
            return a == b;
        }
        byte[] bytesA = a.getBytes(StandardCharsets.UTF_8);
        byte[] bytesB = b.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(bytesA, bytesB);
    }

    /**
     * Compares two hex strings in constant time after case normalization.
     *
     * @param hexA first hex digest
     * @param hexB second hex digest
     * @return true if hex digests match, false otherwise
     */
    public static boolean equalsHex(String hexA, String hexB) {
        if (hexA == null || hexB == null) {
            return hexA == hexB;
        }
        String cleanA = hexA.replaceAll("\\s+", "").toLowerCase();
        String cleanB = hexB.replaceAll("\\s+", "").toLowerCase();
        return equals(cleanA, cleanB);
    }
}
