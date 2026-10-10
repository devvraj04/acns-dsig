package com.acns.dsig.cli;

import com.acns.dsig.core.api.TrustLookup;
import com.acns.dsig.core.api.TrustStatus;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * File-based trust store implementation for the CLI, implementing TrustLookup.
 * Persists pinned fingerprints and metadata in JSON format.
 */
public class FileTrustStore implements TrustLookup {

    public record TrustEntry(
            String fingerprint,
            String label,
            TrustStatus status,
            Instant addedAt,
            Instant revokedAt,
            String notes
    ) {}

    private final Path storagePath;
    private final ObjectMapper mapper;
    private final Map<String, TrustEntry> entries = new HashMap<>();

    public FileTrustStore(Path storagePath) {
        this.storagePath = storagePath;
        this.mapper = new ObjectMapper();
        load();
    }

    public synchronized void load() {
        if (!Files.exists(storagePath)) {
            return;
        }
        try {
            Map<String, TrustEntry> loaded = mapper.readValue(
                    storagePath.toFile(),
                    new TypeReference<Map<String, TrustEntry>>() {}
            );
            entries.clear();
            entries.putAll(loaded);
        } catch (IOException e) {
            System.err.println("Warning: Could not read CLI trust store: " + e.getMessage());
        }
    }

    public synchronized void save() throws IOException {
        if (storagePath.getParent() != null && !Files.exists(storagePath.getParent())) {
            Files.createDirectories(storagePath.getParent());
        }
        mapper.writerWithDefaultPrettyPrinter().writeValue(storagePath.toFile(), entries);
    }

    public synchronized void addTrust(String fingerprint, String label, String notes) throws IOException {
        String cleanFp = fingerprint.replaceAll("\\s+", "").toLowerCase();
        TrustEntry entry = new TrustEntry(cleanFp, label, TrustStatus.TRUSTED, Instant.now(), null, notes);
        entries.put(cleanFp, entry);
        save();
    }

    public synchronized void revokeTrust(String fingerprint) throws IOException {
        String cleanFp = fingerprint.replaceAll("\\s+", "").toLowerCase();
        TrustEntry existing = entries.get(cleanFp);
        if (existing != null) {
            TrustEntry updated = new TrustEntry(
                    cleanFp,
                    existing.label(),
                    TrustStatus.REVOKED,
                    existing.addedAt(),
                    Instant.now(),
                    existing.notes()
            );
            entries.put(cleanFp, updated);
            save();
        }
    }

    public synchronized Map<String, TrustEntry> listEntries() {
        return new HashMap<>(entries);
    }

    @Override
    public synchronized TrustStatus getTrustStatus(String fingerprint) {
        if (fingerprint == null) return TrustStatus.UNKNOWN;
        String cleanFp = fingerprint.replaceAll("\\s+", "").toLowerCase();
        TrustEntry entry = entries.get(cleanFp);
        return entry != null ? entry.status() : TrustStatus.UNKNOWN;
    }

    @Override
    public synchronized Optional<String> getSignerLabel(String fingerprint) {
        if (fingerprint == null) return Optional.empty();
        String cleanFp = fingerprint.replaceAll("\\s+", "").toLowerCase();
        TrustEntry entry = entries.get(cleanFp);
        return entry != null ? Optional.ofNullable(entry.label()) : Optional.empty();
    }
}
