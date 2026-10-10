package com.acns.dsig.server.persistence;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TrustedSignerRepository extends JpaRepository<TrustedSigner, Long> {
    List<TrustedSigner> findByOwnerId(Long ownerId);
    Optional<TrustedSigner> findByOwnerIdAndFingerprint(Long ownerId, String fingerprint);
    Optional<TrustedSigner> findFirstByFingerprint(String fingerprint);
}
