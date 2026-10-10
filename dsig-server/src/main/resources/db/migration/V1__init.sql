-- V1__init.sql: Core Schema Initialization
CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(128) NOT NULL,
    role VARCHAR(32) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    failed_logins INT DEFAULT 0,
    locked_until TIMESTAMP
);

CREATE TABLE IF NOT EXISTS key_pairs (
    key_id VARCHAR(64) PRIMARY KEY,
    owner_id BIGINT NOT NULL,
    label VARCHAR(128) NOT NULL,
    public_pem CLOB NOT NULL,
    key_file_path VARCHAR(512) NOT NULL,
    status VARCHAR(32) NOT NULL,
    created_at TIMESTAMP NOT NULL
);

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
