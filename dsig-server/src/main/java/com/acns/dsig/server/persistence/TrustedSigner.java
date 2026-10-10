package com.acns.dsig.server.persistence;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "trusted_signers")
public class TrustedSigner {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "owner_id", nullable = false)
    private Long ownerId;

    @Column(nullable = false, length = 64)
    private String fingerprint;

    @Column(nullable = false, length = 128)
    private String label;

    @Column(nullable = false, length = 32)
    private String status; // TRUSTED, REVOKED, RETIRED, UNTRUSTED

    @Column(name = "added_at", nullable = false)
    private Instant addedAt = Instant.now();

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(length = 256)
    private String note;

    public TrustedSigner() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public Long getOwnerId() { return ownerId; }
    public void setOwnerId(Long ownerId) { this.ownerId = ownerId; }
    public String getFingerprint() { return fingerprint; }
    public void setFingerprint(String fingerprint) { this.fingerprint = fingerprint; }
    public String getLabel() { return label; }
    public void setLabel(String label) { this.label = label; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public Instant getAddedAt() { return addedAt; }
    public void setAddedAt(Instant addedAt) { this.addedAt = addedAt; }
    public Instant getRevokedAt() { return revokedAt; }
    public void setRevokedAt(Instant revokedAt) { this.revokedAt = revokedAt; }
    public String getNote() { return note; }
    public void setNote(String note) { this.note = note; }
}
