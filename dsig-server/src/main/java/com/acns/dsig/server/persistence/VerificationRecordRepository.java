package com.acns.dsig.server.persistence;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface VerificationRecordRepository extends JpaRepository<VerificationRecord, Long> {
    List<VerificationRecord> findByUserIdOrderByVerifiedAtDesc(Long userId);
    List<VerificationRecord> findAllByOrderByVerifiedAtDesc();
}
