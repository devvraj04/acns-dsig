package com.acns.dsig.core.format;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * Model of the signed manifest structure.
 * Notice: exact serialized UTF-8 bytes of this manifest are signed.
 */
public record Manifest(
        @JsonProperty("v") int version,
        @JsonProperty("docName") String docName,
        @JsonProperty("docSize") long docSize,
        @JsonProperty("hashAlg") String hashAlg,
        @JsonProperty("docHash") String docHash,
        @JsonProperty("sigAlg") String sigAlg,
        @JsonProperty("keyId") String keyId,
        @JsonProperty("signedAt") Instant signedAt,
        @JsonProperty("nonce") String nonce,
        @JsonProperty("signer") String signer
) {}
