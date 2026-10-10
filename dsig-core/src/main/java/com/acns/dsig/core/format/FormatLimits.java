package com.acns.dsig.core.format;

/**
 * Hard security bounds for parsing envelopes and manifests to prevent resource exhaustion attacks.
 */
public final class FormatLimits {

    private FormatLimits() {}

    public static final String PROTOCOL_FORMAT = "ACNS-DSIG";
    public static final int SUPPORTED_VERSION = 1;

    // Maximum payload sizes
    public static final int MAX_ENVELOPE_JSON_BYTES = 512 * 1024;    // 512 KB
    public static final int MAX_MANIFEST_JSON_BYTES = 64 * 1024;     // 64 KB
    public static final int MAX_DOCUMENT_NAME_LENGTH = 255;
    public static final int MAX_SIGNER_NAME_LENGTH = 128;

    // Minimum nonce size (16 bytes = 128 bits)
    public static final int MIN_NONCE_BYTES = 16;
}
