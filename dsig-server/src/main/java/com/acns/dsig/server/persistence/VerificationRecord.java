package com.acns.dsig.server.persistence;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "verification_records")
public class VerificationRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id")
    private Long userId;

    @Column(name = "doc_name", nullable = false, length = 255)
    private String docName;

    @Column(name = "doc_sha256", nullable = false, length = 64)
    private String docSha256;

    @Column(name = "key_id", length = 64)
    private String keyId;

    @Column(name = "result_code", nullable = false, length = 32)
    private String resultCode;

    @Column(name = "trust_status", length = 32)
    private String trustStatus;

    @Column(name = "signed_at")
    private Instant signedAt;

    @Column(name = "verified_at", nullable = false)
    private Instant verifiedAt = Instant.now();

    @Column(length = 64)
    private String nonce;

    public VerificationRecord() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }
    public String getDocName() { return docName; }
    public void setDocName(String docName) { this.docName = docName; }
    public String getDocSha256() { return docSha256; }
    public void setDocSha256(String docSha256) { this.docSha256 = docSha256; }
    public String getKeyId() { return keyId; }
    public void setKeyId(String keyId) { this.keyId = keyId; }
    public String getResultCode() { return resultCode; }
    public void setResultCode(String resultCode) { this.resultCode = resultCode; }
    public String getTrustStatus() { return trustStatus; }
    public void setTrustStatus(String trustStatus) { this.trustStatus = trustStatus; }
    public Instant getSignedAt() { return signedAt; }
    public void setSignedAt(Instant signedAt) { this.signedAt = signedAt; }
    public Instant getVerifiedAt() { return verifiedAt; }
    public void setVerifiedAt(Instant verifiedAt) { this.verifiedAt = verifiedAt; }
    public String getNonce() { return nonce; }
    public void setNonce(String nonce) { this.nonce = nonce; }
}
