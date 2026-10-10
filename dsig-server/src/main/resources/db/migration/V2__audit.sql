-- V2__audit.sql: Chained Tamper-Evident Audit Table
CREATE TABLE IF NOT EXISTS audit_log (
    seq BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    user_id BIGINT,
    action VARCHAR(64) NOT NULL,
    detail VARCHAR(1024),
    prev_hash VARCHAR(64) NOT NULL,
    entry_hash VARCHAR(64) NOT NULL
);
