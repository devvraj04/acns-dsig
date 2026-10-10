package com.acns.dsig.core.format;

import com.acns.dsig.core.error.CorruptedPackageException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.nio.charset.StandardCharsets;

/**
 * Strict JSON encoder/decoder for Manifest and Envelope.
 * Rejects duplicate keys and enforces strict payload limits.
 */
public class EnvelopeCodec {

    private final ObjectMapper mapper;

    public EnvelopeCodec() {
        this.mapper = new ObjectMapper();
        this.mapper.registerModule(new JavaTimeModule());
        this.mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        this.mapper.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
        this.mapper.enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    }

    /**
     * Serializes a Manifest record into exact canonical UTF-8 bytes for signing.
     */
    public byte[] serializeManifestToBytes(Manifest manifest) {
        try {
            return mapper.writeValueAsString(manifest).getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new CorruptedPackageException("Failed to serialize manifest", e);
        }
    }

    /**
     * Strictly deserializes manifest UTF-8 bytes into a Manifest record.
     */
    public Manifest deserializeManifestFromBytes(byte[] manifestBytes) {
        if (manifestBytes == null || manifestBytes.length == 0) {
            throw new CorruptedPackageException("Manifest bytes cannot be null or empty");
        }
        if (manifestBytes.length > FormatLimits.MAX_MANIFEST_JSON_BYTES) {
            throw new CorruptedPackageException("Manifest exceeds maximum size limit of "
                    + FormatLimits.MAX_MANIFEST_JSON_BYTES + " bytes");
        }
        try {
            return mapper.readValue(manifestBytes, Manifest.class);
        } catch (Exception e) {
            throw new CorruptedPackageException("Strict manifest parsing failed: " + e.getMessage(), e);
        }
    }

    /**
     * Serializes an Envelope record into pretty-printed JSON string.
     */
    public String serializeEnvelope(Envelope envelope) {
        try {
            return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(envelope);
        } catch (Exception e) {
            throw new CorruptedPackageException("Failed to serialize envelope", e);
        }
    }

    /**
     * Strictly parses an Envelope from a JSON string.
     */
    public Envelope deserializeEnvelope(String json) {
        if (json == null || json.isBlank()) {
            throw new CorruptedPackageException("Envelope JSON content cannot be empty");
        }
        if (json.getBytes(StandardCharsets.UTF_8).length > FormatLimits.MAX_ENVELOPE_JSON_BYTES) {
            throw new CorruptedPackageException("Envelope JSON exceeds maximum limit of "
                    + FormatLimits.MAX_ENVELOPE_JSON_BYTES + " bytes");
        }
        try {
            return mapper.readValue(json, Envelope.class);
        } catch (Exception e) {
            throw new CorruptedPackageException("Strict envelope parsing failed: " + e.getMessage(), e);
        }
    }
}
