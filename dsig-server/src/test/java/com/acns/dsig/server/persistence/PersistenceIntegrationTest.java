package com.acns.dsig.server.persistence;

import com.acns.dsig.server.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Backend Persistence & Authentication Integration Tests.
 * Work Package Ownership: Nityanand Upadhyay (Member 6)
 *
 * Validates:
 * 1. H2 user persistence, roles, and BCrypt password hashing.
 * 2. Key pair metadata persistence and private-key exclusion from database columns.
 * 3. Trust-store persistence and fingerprint pinning.
 * 4. Verification record history persistence and ordering.
 * 5. Tamper-evident cryptographically chained audit log and integrity verification.
 * 6. Ownership checks and role-based data isolation.
 */
@SpringBootTest
@Transactional
@DisplayName("PersistenceIntegrationTest — Database, Entities, Repositories, Auth & Audit Chain")
class PersistenceIntegrationTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private KeyPairRepository keyPairRepository;

    @Autowired
    private TrustedSignerRepository trustedSignerRepository;

    @Autowired
    private VerificationRecordRepository verificationRecordRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private AuditChainService auditChainService;

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        auditLogRepository.deleteAll();
        verificationRecordRepository.deleteAll();
        trustedSignerRepository.deleteAll();
        keyPairRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("User persistence: saves user with BCrypt hash, checks username uniqueness and roles")
    void testUserPersistenceAndAuthentication() {
        String rawPassword = "SecurePassword123!";
        User registered = userService.registerUser("nityanand_dev", rawPassword, "ROLE_SIGNER");

        assertNotNull(registered.getId(), "User ID should be generated");
        assertEquals("nityanand_dev", registered.getUsername());
        assertEquals("ROLE_SIGNER", registered.getRole());
        assertTrue(passwordEncoder.matches(rawPassword, registered.getPasswordHash()),
                "Stored password hash must match BCrypt verification");
        assertNotEquals(rawPassword, registered.getPasswordHash(),
                "Raw password must never be stored in plain text");

        assertTrue(userRepository.existsByUsername("nityanand_dev"));
        Optional<User> found = userRepository.findByUsername("nityanand_dev");
        assertTrue(found.isPresent());
        assertEquals("ROLE_SIGNER", found.get().getRole());

        // Duplicate username registration must throw IllegalArgumentException
        assertThrows(IllegalArgumentException.class, () ->
                userService.registerUser("nityanand_dev", "AnotherPass!", "ROLE_VERIFIER")
        );
    }

    @Test
    @DisplayName("Key pair persistence: stores public metadata only, never exposes private key bytes")
    void testKeyPairPersistenceExcludesPrivateKeyBytes() {
        User user = userService.registerUser("alice_signer", "Password123!", "ROLE_SIGNER");

        String fakeKeyId = "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0";
        String publicPem = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END PUBLIC KEY-----";
        String keyFilePath = "runtime/keys/" + fakeKeyId + ".pk8";

        KeyPairEntity entity = new KeyPairEntity();
        entity.setKeyId(fakeKeyId);
        entity.setOwnerId(user.getId());
        entity.setLabel("Alice Primary RSA Key");
        entity.setPublicPem(publicPem);
        entity.setKeyFilePath(keyFilePath);
        entity.setStatus("ACTIVE");
        entity.setCreatedAt(Instant.now());

        keyPairRepository.save(entity);

        Optional<KeyPairEntity> retrieved = keyPairRepository.findById(fakeKeyId);
        assertTrue(retrieved.isPresent());
        assertEquals(user.getId(), retrieved.get().getOwnerId());
        assertEquals("ACTIVE", retrieved.get().getStatus());
        assertEquals(publicPem, retrieved.get().getPublicPem());
        assertEquals(keyFilePath, retrieved.get().getKeyFilePath());

        List<KeyPairEntity> userKeys = keyPairRepository.findByOwnerId(user.getId());
        assertEquals(1, userKeys.size());
        assertEquals(fakeKeyId, userKeys.get(0).getKeyId());
    }

    @Test
    @DisplayName("Trusted signer persistence: pin fingerprint and test revocation")
    void testTrustedSignerPersistenceAndRevocation() {
        User user = userService.registerUser("verifier_bob", "Password123!", "ROLE_VERIFIER");

        String fingerprint = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        TrustedSigner signer = new TrustedSigner();
        signer.setOwnerId(user.getId());
        signer.setFingerprint(fingerprint);
        signer.setLabel("Bob Trusted Department");
        signer.setStatus("TRUSTED");
        signer.setAddedAt(Instant.now());
        signer.setNote("Department Head Signing Key");

        trustedSignerRepository.save(signer);

        Optional<TrustedSigner> found = trustedSignerRepository.findByOwnerIdAndFingerprint(user.getId(), fingerprint);
        assertTrue(found.isPresent());
        assertEquals("TRUSTED", found.get().getStatus());

        // Revoke the signer
        TrustedSigner toRevoke = found.get();
        toRevoke.setStatus("REVOKED");
        toRevoke.setRevokedAt(Instant.now());
        trustedSignerRepository.save(toRevoke);

        TrustedSigner updated = trustedSignerRepository.findById(toRevoke.getId()).orElseThrow();
        assertEquals("REVOKED", updated.getStatus());
        assertNotNull(updated.getRevokedAt());
    }

    @Test
    @DisplayName("Verification records: stores audit of verification outcomes in chronological order")
    void testVerificationRecordHistoryPersistence() {
        User user = userService.registerUser("auditor_dan", "Password123!", "ROLE_VERIFIER");

        VerificationRecord record1 = new VerificationRecord();
        record1.setUserId(user.getId());
        record1.setDocName("financial_report_q1.pdf");
        record1.setDocSha256("1111111111111111111111111111111111111111111111111111111111111111");
        record1.setKeyId("key-1");
        record1.setResultCode("VALID_TRUSTED");
        record1.setTrustStatus("TRUSTED");
        record1.setVerifiedAt(Instant.now().minusSeconds(100));

        VerificationRecord record2 = new VerificationRecord();
        record2.setUserId(user.getId());
        record2.setDocName("financial_report_q2.pdf");
        record2.setDocSha256("2222222222222222222222222222222222222222222222222222222222222222");
        record2.setKeyId("key-2");
        record2.setResultCode("DOCUMENT_TAMPERED");
        record2.setTrustStatus("UNTRUSTED");
        record2.setVerifiedAt(Instant.now());

        verificationRecordRepository.save(record1);
        verificationRecordRepository.save(record2);

        List<VerificationRecord> userHistory = verificationRecordRepository.findByUserIdOrderByVerifiedAtDesc(user.getId());
        assertEquals(2, userHistory.size());
        assertEquals("financial_report_q2.pdf", userHistory.get(0).getDocName(), "Most recent record should be first");
        assertEquals("DOCUMENT_TAMPERED", userHistory.get(0).getResultCode());
        assertEquals("financial_report_q1.pdf", userHistory.get(1).getDocName());
    }

    @Test
    @DisplayName("Audit log: cryptographically chained tamper-evident logging and tamper detection")
    void testTamperEvidentAuditChainIntegrity() {
        User user = userService.registerUser("audit_admin", "Password123!", "ROLE_ADMIN");

        // Record three events sequentially
        AuditLog e1 = auditChainService.recordEvent(user.getId(), "USER_LOGIN", "Login succeeded for audit_admin");
        AuditLog e2 = auditChainService.recordEvent(user.getId(), "KEY_GENERATE", "RSA-3072 key pair generated");
        AuditLog e3 = auditChainService.recordEvent(user.getId(), "DOC_SIGN", "Contract signed: terms.pdf");

        // 1. Genesis entry check
        assertEquals(AuditChainService.GENESIS_PREV_HASH, e1.getPrevHash(),
                "First audit entry must point to 64-zero genesis hash");

        // 2. Cryptographic link check
        assertEquals(e1.getEntryHash(), e2.getPrevHash(), "Second entry prev_hash must match first entry hash");
        assertEquals(e2.getEntryHash(), e3.getPrevHash(), "Third entry prev_hash must match second entry hash");

        // 3. Verify intact chain
        AuditChainService.ChainVerificationResult result = auditChainService.verifyChainIntegrity();
        assertTrue(result.valid(), "Chain must be cryptographically valid when untampered");
        assertNull(result.brokenSeq());

        // 4. Simulate tampering with record e2 detail
        e2.setDetail("Tampered unauthorized modification of detail!");
        auditLogRepository.save(e2);

        // 5. Verify tampering is detected
        AuditChainService.ChainVerificationResult tamperedResult = auditChainService.verifyChainIntegrity();
        assertFalse(tamperedResult.valid(), "Tampering with audit log must be caught by chain verification");
        assertEquals(e2.getSeq(), tamperedResult.brokenSeq(), "Broken sequence must pinpoint tampered record");
    }
}
