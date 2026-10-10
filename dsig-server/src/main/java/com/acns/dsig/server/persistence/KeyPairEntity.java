package com.acns.dsig.server.persistence;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "key_pairs")
public class KeyPairEntity {

    @Id
    @Column(name = "key_id", length = 64)
    private String keyId; // SHA-256 fingerprint

    @Column(name = "owner_id", nullable = false)
    private Long ownerId;

    @Column(nullable = false, length = 128)
    private String label;

    @Lob
    @Column(name = "public_pem", nullable = false)
    private String publicPem;

    @Column(name = "key_file_path", nullable = false, length = 512)
    private String keyFilePath;

    @Column(nullable = false, length = 32)
    private String status; // ACTIVE, RETIRED, REVOKED

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    public KeyPairEntity() {}

    public String getKeyId() { return keyId; }
    public void setKeyId(String keyId) { this.keyId = keyId; }
    public Long getOwnerId() { return ownerId; }
    public void setOwnerId(Long ownerId) { this.ownerId = ownerId; }
    public String getLabel() { return label; }
    public void setLabel(String label) { this.label = label; }
    public String getPublicPem() { return publicPem; }
    public void setPublicPem(String publicPem) { this.publicPem = publicPem; }
    public String getKeyFilePath() { return keyFilePath; }
    public void setKeyFilePath(String keyFilePath) { this.keyFilePath = keyFilePath; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
