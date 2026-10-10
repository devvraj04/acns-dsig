package com.acns.dsig.core.crypto;

import java.nio.charset.StandardCharsets;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * Authoritative cryptographic constants and fixed parameter specifications.
 * Strictly adheres to Section 4.1 & 4.4 of the Master Plan.
 */
public final class CryptoConfig {

    private CryptoConfig() {}

    // RSA Key Configuration
    public static final int RSA_KEY_BITS = 3072;
    public static final long RSA_PUBLIC_EXPONENT = 65537L;

    // Cryptographic Algorithms
    public static final String KEY_ALGORITHM = "RSA";
    public static final String SIGNATURE_ALGORITHM = "RSASSA-PSS";
    public static final String HASH_ALGORITHM = "SHA-256";
    public static final String MGF_ALGORITHM = "MGF1";

    // PSS Parameters
    public static final int SALT_LENGTH_BYTES = 32;
    public static final int TRAILER_FIELD = 1;

    // Algorithm Identifiers for Manifest
    public static final String MANIFEST_SIG_ALG = "RSASSA-PSS-SHA256-MGF1SHA256-S32";
    public static final String MANIFEST_HASH_ALG = "SHA-256";

    // Domain Separation: "ACNS-DSIG-v1" || 0x00
    public static final byte[] DOMAIN_LABEL = "ACNS-DSIG-v1\0".getBytes(StandardCharsets.UTF_8);

    // Buffer size for streaming IO
    public static final int STREAM_BUFFER_SIZE = 64 * 1024; // 64 KB

    /**
     * Creates standard PSSParameterSpec matching the authoritative specification.
     */
    public static PSSParameterSpec createPssParameterSpec() {
        return new PSSParameterSpec(
                HASH_ALGORITHM,
                MGF_ALGORITHM,
                MGF1ParameterSpec.SHA256,
                SALT_LENGTH_BYTES,
                TRAILER_FIELD
        );
    }
}
