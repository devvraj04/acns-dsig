package com.acns.dsig.server.service;

import com.acns.dsig.server.persistence.VerificationRecord;
import com.acns.dsig.server.persistence.VerificationRecordRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class HistoryService {

    private final VerificationRecordRepository verificationRecordRepository;

    public HistoryService(VerificationRecordRepository verificationRecordRepository) {
        this.verificationRecordRepository = verificationRecordRepository;
    }

    @Transactional(readOnly = true)
    public List<VerificationRecord> getHistoryForUser(Long userId) {
        return verificationRecordRepository.findByUserIdOrderByVerifiedAtDesc(userId);
    }

    @Transactional(readOnly = true)
    public List<VerificationRecord> getAllHistory() {
        return verificationRecordRepository.findAllByOrderByVerifiedAtDesc();
    }
}
