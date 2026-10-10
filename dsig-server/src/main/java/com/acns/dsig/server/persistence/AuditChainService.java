package com.acns.dsig.server.persistence;

import com.acns.dsig.core.crypto.ConstantTime;
import com.acns.dsig.core.crypto.CryptoConfig;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

@Service
public class AuditChainService {

    public static final String GENESIS_PREV_HASH = "0".repeat(64);

    private final AuditLogRepository auditLogRepository;

    public AuditChainService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    public record ChainVerificationResult(boolean valid, Long brokenSeq, String message) {}

    /**
     * Appends a new immutable audit record, cryptographically chained to the prior entry.
     */
    @Transactional
    public synchronized AuditLog recordEvent(Long userId, String action, String detail) {
        Optional<AuditLog> latest = auditLogRepository.findTopByOrderBySeqDesc();
        String prevHash = latest.map(AuditLog::getEntryHash).orElse(GENESIS_PREV_HASH);
        long nextSeq = latest.map(l -> l.getSeq() + 1).orElse(1L);

        Instant now = Instant.now();
        String entryHash = calculateEntryHash(prevHash, nextSeq, now, userId, action, detail);

        AuditLog log = new AuditLog();
        log.setTimestamp(now);
        log.setUserId(userId);
        log.setAction(action);
        log.setDetail(detail);
        log.setPrevHash(prevHash);
        log.setEntryHash(entryHash);

        return auditLogRepository.save(log);
    }

    /**
     * Traverses the entire audit log sequence and verifies cryptographic chain integrity.
     */
    @Transactional(readOnly = true)
    public ChainVerificationResult verifyChainIntegrity() {
        List<AuditLog> entries = auditLogRepository.findAllByOrderBySeqAsc();
        if (entries.isEmpty()) {
            return new ChainVerificationResult(true, null, "Audit log is empty; chain is valid.");
        }

        String expectedPrevHash = GENESIS_PREV_HASH;
        for (AuditLog entry : entries) {
            // 1. Check prev_hash link
            if (!ConstantTime.equals(entry.getPrevHash(), expectedPrevHash)) {
                return new ChainVerificationResult(
                        false,
                        entry.getSeq(),
                        "Audit chain broken at sequence " + entry.getSeq() + ": prev_hash mismatch."
                );
            }

            // 2. Recompute and verify entry_hash
            String computed = calculateEntryHash(
                    entry.getPrevHash(),
                    entry.getSeq(),
                    entry.getTimestamp(),
                    entry.getUserId(),
                    entry.getAction(),
                    entry.getDetail()
            );

            if (!ConstantTime.equals(entry.getEntryHash(), computed)) {
                return new ChainVerificationResult(
                        false,
                        entry.getSeq(),
                        "Tampering detected at sequence " + entry.getSeq() + ": entry_hash mismatch."
                );
            }

            expectedPrevHash = entry.getEntryHash();
        }

        return new ChainVerificationResult(true, null, "Audit log verified. All " + entries.size() + " links are cryptographically intact.");
    }

    public static String calculateEntryHash(
            String prevHash,
            long seq,
            Instant timestamp,
            Long userId,
            String action,
            String detail
    ) {
        try {
            MessageDigest digest = MessageDigest.getInstance(CryptoConfig.HASH_ALGORITHM);
            String payload = String.format("%s|%d|%s|%s|%s|%s",
                    prevHash,
                    seq,
                    timestamp.toString(),
                    userId != null ? userId.toString() : "SYSTEM",
                    action != null ? action : "",
                    detail != null ? detail : ""
            );
            byte[] hash = digest.digest(payload.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}
