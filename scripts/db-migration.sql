-- ============================================================================
-- ACNS-DSIG Complete Database Schema & Migration Script
-- Author / Ownership: Nityanand Upadhyay (Member 6 — Database, Users, Authentication & Persistence)
-- Target Database: H2 (File-mode: runtime/acns-dsig or In-Memory) / ANSI SQL Compatible
-- ============================================================================

-- 1. Users Table (Authentication, BCrypt password hash, Role, Lockout tracking)
CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(128) NOT NULL,
    role VARCHAR(32) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    failed_logins INT DEFAULT 0,
    locked_until TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- 2. Key Pairs Table (Metadata, public PEM, encrypted file path - NEVER stores private key bytes)
CREATE TABLE IF NOT EXISTS key_pairs (
    key_id VARCHAR(64) PRIMARY KEY,
    owner_id BIGINT NOT NULL,
    label VARCHAR(128) NOT NULL,
    public_pem CLOB NOT NULL,
    key_file_path VARCHAR(512) NOT NULL,
    status VARCHAR(32) NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_key_pairs_owner ON key_pairs(owner_id);
CREATE INDEX IF NOT EXISTS idx_key_pairs_status ON key_pairs(status);

-- 3. Trusted Signers Table (Trust store, pinned fingerprints, revocation status)
CREATE TABLE IF NOT EXISTS trusted_signers (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    owner_id BIGINT NOT NULL,
    fingerprint VARCHAR(64) NOT NULL,
    label VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL,
    added_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    note VARCHAR(256)
);

CREATE INDEX IF NOT EXISTS idx_trusted_signers_owner ON trusted_signers(owner_id);
CREATE INDEX IF NOT EXISTS idx_trusted_signers_fingerprint ON trusted_signers(fingerprint);

-- 4. Verification Records Table (Verification history, audit of verification outcomes)
CREATE TABLE IF NOT EXISTS verification_records (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT,
    doc_name VARCHAR(255) NOT NULL,
    doc_sha256 VARCHAR(64) NOT NULL,
    key_id VARCHAR(64),
    result_code VARCHAR(32) NOT NULL,
    trust_status VARCHAR(32),
    signed_at TIMESTAMP,
    verified_at TIMESTAMP NOT NULL,
    nonce VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS idx_verif_records_user ON verification_records(user_id);
CREATE INDEX IF NOT EXISTS idx_verif_records_verified_at ON verification_records(verified_at DESC);

-- 5. Tamper-Evident Chained Audit Log Table (Cryptographically chained SHA-256 sequence)
CREATE TABLE IF NOT EXISTS audit_log (
    seq BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    user_id BIGINT,
    action VARCHAR(64) NOT NULL,
    detail VARCHAR(1024),
    prev_hash VARCHAR(64) NOT NULL,
    entry_hash VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_seq ON audit_log(seq);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp DESC);
