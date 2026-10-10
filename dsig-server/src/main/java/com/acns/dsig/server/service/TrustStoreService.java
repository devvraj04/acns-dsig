package com.acns.dsig.server.service;

import com.acns.dsig.core.api.TrustLookup;
import com.acns.dsig.core.api.TrustStatus;
import com.acns.dsig.server.persistence.TrustedSigner;
import com.acns.dsig.server.persistence.TrustedSignerRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Service
public class TrustStoreService implements TrustLookup {

    private final TrustedSignerRepository trustedSignerRepository;

    public TrustStoreService(TrustedSignerRepository trustedSignerRepository) {
        this.trustedSignerRepository = trustedSignerRepository;
    }

    @Transactional(readOnly = true)
    public List<TrustedSigner> getSignersForUser(Long userId) {
        return trustedSignerRepository.findByOwnerId(userId);
    }

    @Transactional
    public TrustedSigner pinFingerprint(Long userId, String fingerprint, String label, String note) {
        String cleanFp = fingerprint.replaceAll("\\s+", "").toLowerCase();
        Optional<TrustedSigner> existing = trustedSignerRepository.findByOwnerIdAndFingerprint(userId, cleanFp);

        TrustedSigner signer = existing.orElseGet(TrustedSigner::new);
        signer.setOwnerId(userId);
        signer.setFingerprint(cleanFp);
        signer.setLabel(label);
        signer.setStatus("TRUSTED");
        signer.setAddedAt(Instant.now());
        signer.setNote(note);

        return trustedSignerRepository.save(signer);
    }

    @Transactional
    public void revokeSigner(Long userId, Long signerId) {
        trustedSignerRepository.findById(signerId).ifPresent(signer -> {
            if (signer.getOwnerId().equals(userId)) {
                signer.setStatus("REVOKED");
                signer.setRevokedAt(Instant.now());
                trustedSignerRepository.save(signer);
            }
        });
    }

    @Override
    @Transactional(readOnly = true)
    public TrustStatus getTrustStatus(String fingerprint) {
        if (fingerprint == null) return TrustStatus.UNKNOWN;
        String cleanFp = fingerprint.replaceAll("\\s+", "").toLowerCase();
        Optional<TrustedSigner> match = trustedSignerRepository.findFirstByFingerprint(cleanFp);
        if (match.isEmpty()) {
            return TrustStatus.UNKNOWN;
        }
        return switch (match.get().getStatus()) {
            case "TRUSTED" -> TrustStatus.TRUSTED;
            case "REVOKED" -> TrustStatus.REVOKED;
            case "RETIRED" -> TrustStatus.RETIRED;
            default -> TrustStatus.UNTRUSTED;
        };
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<String> getSignerLabel(String fingerprint) {
        if (fingerprint == null) return Optional.empty();
        String cleanFp = fingerprint.replaceAll("\\s+", "").toLowerCase();
        return trustedSignerRepository.findFirstByFingerprint(cleanFp).map(TrustedSigner::getLabel);
    }
}
