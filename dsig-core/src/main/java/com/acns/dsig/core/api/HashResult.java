package com.acns.dsig.core.api;

import java.util.Arrays;
import java.util.Objects;

/**
 * Immutable value representation of a cryptographic hashing outcome.
 */
public record HashResult(
        byte[] rawDigest,
        String hexDigest,
        String base64Digest,
        long byteCount,
        String algorithm
) {
    public HashResult {
        Objects.requireNonNull(rawDigest, "rawDigest cannot be null");
        Objects.requireNonNull(hexDigest, "hexDigest cannot be null");
        Objects.requireNonNull(base64Digest, "base64Digest cannot be null");
        Objects.requireNonNull(algorithm, "algorithm cannot be null");
        rawDigest = rawDigest.clone();
    }

    @Override
    public byte[] rawDigest() {
        return rawDigest.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof HashResult that)) return false;
        return byteCount == that.byteCount &&
                Arrays.equals(rawDigest, that.rawDigest) &&
                Objects.equals(hexDigest, that.hexDigest) &&
                Objects.equals(base64Digest, that.base64Digest) &&
                Objects.equals(algorithm, that.algorithm);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(hexDigest, base64Digest, byteCount, algorithm);
        result = 31 * result + Arrays.hashCode(rawDigest);
        return result;
    }
}
