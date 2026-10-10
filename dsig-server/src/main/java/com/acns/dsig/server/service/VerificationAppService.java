package com.acns.dsig.server.service;

import com.acns.dsig.core.api.VerificationResult;
import com.acns.dsig.core.crypto.HashService;
import com.acns.dsig.core.crypto.SignatureService;
import com.acns.dsig.core.format.EnvelopeCodec;
import com.acns.dsig.core.trust.TrustPolicy;
import com.acns.dsig.core.verify.VerificationService;
import com.acns.dsig.server.persistence.AuditChainService;
import com.acns.dsig.server.persistence.VerificationRecord;
import com.acns.dsig.server.persistence.VerificationRecordRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.InputStream;
import java.time.Instant;

@Service
public class VerificationAppService {

    private final TrustStoreService trustStoreService;
    private final VerificationRecordRepository verificationRecordRepository;
    private final AuditChainService auditChainService;
    private final VerificationService coreVerificationService;

    public VerificationAppService(
            TrustStoreService trustStoreService,
            VerificationRecordRepository verificationRecordRepository,
            AuditChainService auditChainService
    ) {
        this.trustStoreService = trustStoreService;
        this.verificationRecordRepository = verificationRecordRepository;
        this.auditChainService = auditChainService;
        this.coreVerificationService = new VerificationService(
                new HashService(),
                new SignatureService(),
                new EnvelopeCodec()
        );
    }

    @Transactional
    public VerificationResult verifyDocument(
            Long userId,
            InputStream documentStream,
            String envelopeJson
    ) {
        TrustPolicy policy = new TrustPolicy(trustStoreService);
        VerificationResult result = coreVerificationService.verify(documentStream, envelopeJson, policy);

        // Record verification history
        VerificationRecord record = new VerificationRecord();
        record.setUserId(userId);
        record.setDocName(result.documentName() != null ? result.documentName() : "unknown");
        record.setDocSha256(result.recomputedDocHash() != null ? result.recomputedDocHash() : "N/A");
        record.setKeyId(result.keyFingerprint());
        record.setResultCode(result.resultCode().name());
        record.setTrustStatus(result.trustStatus() != null ? result.trustStatus().name() : "UNKNOWN");
        record.setSignedAt(result.signedAt());
        record.setVerifiedAt(Instant.now());
        record.setNonce(result.nonce());
        verificationRecordRepository.save(record);

        // Record audit event
        auditChainService.recordEvent(
                userId,
                "VERIFY_DOCUMENT",
                "Verified document " + record.getDocName() + " Result=" + result.resultCode()
        );

        return result;
    }
}
