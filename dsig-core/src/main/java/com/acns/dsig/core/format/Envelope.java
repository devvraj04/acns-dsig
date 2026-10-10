package com.acns.dsig.core.format;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Top-level detached signature envelope (.dsig.json).
 */
public record Envelope(
        @JsonProperty("format") String format,
        @JsonProperty("version") int version,
        @JsonProperty("manifest") String base64Manifest,
        @JsonProperty("signature") String base64Signature,
        @JsonProperty("publicKey") String base64PublicKey
) {}
