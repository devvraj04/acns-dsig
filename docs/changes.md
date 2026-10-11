# Project Initialization Changelog (`docs/changes.md`)

All modifications, file creations, and structural initializations for the **ACNS-DSIG** project are logged below.

---

## [Phase 1: Project Skeleton & Multi-Module Architecture Initialization] - 2026-10-10

### 1. Root Build & Automation Infrastructure
- **`pom.xml`**: Created multi-module parent POM (packaging: `pom`) managing dependencies and plugins for `dsig-core`, `dsig-cli`, and `dsig-server`. Configured Java 21 LTS baseline, Spring Boot 3.3.4, Picocli 4.7.6, Jackson 2.17.2, H2 Database 2.3.232, and JUnit Jupiter 5.10.3.
- **`mvnw`, `mvnw.cmd`, `.mvn/wrapper/maven-wrapper.properties`**: Created cross-platform Maven wrapper scripts (POSIX shell and Windows batch) targeting Apache Maven 3.9.9, eliminating the requirement for users to have Maven pre-installed in system PATH.
- **`.gitignore`**: Created comprehensive Git exclusion configuration ignoring compiled artifacts (`target/`), IDE caches, local keys (`*.pk8`, `*.key`), H2 database files (`*.mv.db`), and the runtime directory (`runtime/`).
- **`.github/workflows/ci.yml`**: Configured automated GitHub Actions CI pipeline executing `mvn clean verify` on Ubuntu with Temurin JDK 21 and archiving Surefire test reports.
- **`README.md`**: Created project documentation describing system architecture, team ownership, build workflow, and quickstart commands.

### 2. Cryptographic Core Module (`dsig-core`)
Pure Java library containing all cryptographic, key management, envelope codec, and verification primitives without external framework dependencies.
- **`dsig-core/pom.xml`**: Configured plain Java module POM with Jackson Databind and JUnit 5 test dependencies.
- **`api/` (Frozen Contracts)**:
  - `HashResult.java`: Immutable record encapsulating raw byte digest, hex string, base64 string, byte count, and algorithm identifier.
  - `ResultCode.java`: Enum defining all 9 authoritative verification outcomes (`VALID_TRUSTED`, `VALID_UNTRUSTED_SIGNER`, `DOCUMENT_TAMPERED`, `INVALID_SIGNATURE`, `INVALID_KEY`, `UNSUPPORTED_FORMAT`, `MISSING_METADATA`, `CORRUPTED_PACKAGE`, `REVOKED_OR_RETIRED_KEY`).
  - `TrustStatus.java`: Enum representing signer lifecycle states (`TRUSTED`, `UNTRUSTED`, `REVOKED`, `RETIRED`, `UNKNOWN`).
  - `TrustLookup.java`: Decoupled interface for resolving public key fingerprint trust status.
  - `VerificationResult.java`: Immutable record returning full cryptographic and trust evaluation results with human-readable explanations.
- **`crypto/`**:
  - `CryptoConfig.java`: Authoritative constants (RSA-3072, public exponent 65537, RSASSA-PSS, SHA-256, MGF1-SHA256, salt 32, domain separation label `ACNS-DSIG-v1\0`).
  - `ConstantTime.java`: Constant-time byte and string equality utilities using `MessageDigest.isEqual` to mitigate timing side-channels.
  - `HashService.java`: Fixed 64 KB buffer streaming SHA-256 implementation calculating digest and byte count simultaneously while rejecting 0-byte documents.
  - `SignatureService.java`: RSASSA-PSS digital signature engine enforcing key validation (modulus ≥ 3072 bits), domain separation prefixing, and signature verification.
- **`keys/`**:
  - `KeyStatus.java`: Key lifecycle enum (`ACTIVE`, `RETIRED`, `REVOKED`).
  - `Fingerprint.java`: Computes normalized lowercase hex SHA-256 over DER SubjectPublicKeyInfo with grouped format display utility.
  - `KeyService.java`: Secure key pair generator producing RSA-3072 keys via Java `SecureRandom`.
  - `KeyStorage.java`: PKCS#8 encrypted private key persistence using PBES2 (`PBEWithHmacSHA256AndAES_256`, 600,000 iterations) and public key PEM serialization.
- **`format/`**:
  - `FormatLimits.java`: Defensive security bounds (512 KB envelope limit, 64 KB manifest limit, 16-byte nonce minimum).
  - `Manifest.java`: JSON model representing signed metadata (`v`, `docName`, `docSize`, `hashAlg`, `docHash`, `sigAlg`, `keyId`, `signedAt`, `nonce`, `signer`).
  - `Envelope.java`: JSON model representing detached signature envelope (`format`, `version`, `manifest`, `signature`, `publicKey`).
  - `EnvelopeCodec.java`: Strict Jackson serializer/deserializer enforcing duplicate key detection and size limits.
- **`sign/`**:
  - `SigningService.java`: End-to-end signing orchestrator streaming document, building manifest, signing exact UTF-8 bytes, and creating detached `.dsig.json`.
- **`verify/`**:
  - `VerificationService.java`: Authoritative 10-step verification sequence authenticating manifest before verifying document hash and applying trust policy.
- **`trust/`**:
  - `TrustPolicy.java`: Decision logic mapping trust status lookups to final verification codes.
- **`error/`**:
  - `DsigException.java`, `CryptoException.java`, `CorruptedPackageException.java`, `KeyValidationException.java`, `FormatValidationException.java`: Specialized error hierarchy.
- **`src/test/java/.../CryptoCoreTest.java`**: Comprehensive JUnit 5 test suite covering hashing, keygen, signing, valid verification, tamper detection, and untrusted signer scenarios.

### 3. Command Line Interface Module (`dsig-cli`)
- **`dsig-cli/pom.xml`**: Configured shaded jar build with Picocli and `dsig-core`.
- **`DsigCli.java`**: Root Picocli command registrar.
- **`KeygenCommand.java`**: CLI command to generate RSA-3072 key pairs with encrypted private key storage.
- **`SignCommand.java`**: CLI command to sign arbitrary local documents with detached `.dsig.json` envelope output.
- **`VerifyCommand.java`**: CLI command verifying document integrity and checking local trust store.
- **`FingerprintCommand.java`**: CLI utility displaying SHA-256 public key fingerprints.
- **`TrustAddCommand.java`**: CLI utility to pin a signer fingerprint into local trust store.
- **`TrustListCommand.java`**: CLI utility listing all pinned signer fingerprints.
- **`FileTrustStore.java`**: Persistent JSON-backed trust store implementing `TrustLookup`.

### 4. Web Application Module (`dsig-server`)
- **`dsig-server/pom.xml`**: Configured Spring Boot 3 web application with Thymeleaf, Spring Security, Spring Data JPA, and embedded H2.
- **`DsigServerApplication.java`**: Spring Boot application entry point.
- **`persistence/`**:
  - `User.java` & `UserRepository.java`: User accounts and roles (`ROLE_SIGNER`, `ROLE_VERIFIER`, `ROLE_ADMIN`).
  - `KeyPairEntity.java` & `KeyPairRepository.java`: Server-managed key metadata.
  - `TrustedSigner.java` & `TrustedSignerRepository.java`: Pinned signer fingerprints.
  - `VerificationRecord.java` & `VerificationRecordRepository.java`: Historical verification log.
  - `AuditLog.java` & `AuditLogRepository.java`: Tamper-evident chained audit entity.
  - `AuditChainService.java`: Forward SHA-256 hash chaining service (`entry_hash = SHA-256(...)`) with full chain integrity verification.
- **`service/`**:
  - `UserService.java`: BCrypt registration and user lookup.
  - `KeyManagementService.java`: Server-assisted key pair generation and encrypted disk storage.
  - `TrustStoreService.java`: Server implementation of `TrustLookup`.
  - `SigningAppService.java`: Server-assisted document signing with audit event generation.
  - `VerificationAppService.java`: Server verification engine saving verification history.
  - `HistoryService.java`: Verification record queries.
- **`security/`**:
  - `SecurityConfig.java`: Spring Security configuration enforcing BCrypt, CSRF, session fixation migration, and path authorization.
  - `RateLimitFilter.java`: Sliding window rate limiter protecting `/login`, `/sign`, and `/verify`.
  - `UploadGuard.java`: File size enforcement and isolated temporary file lifecycle management.
  - `LoginAttemptService.java`: Account lockout protection preventing credential brute forcing.
  - `SecurityHeadersConfig.java`: Hardened CSP, HSTS, X-Content-Type-Options, and Frame-Options DENY headers.
  - `GlobalExceptionHandler.java`: Safe error handling generating incident reference IDs without internal detail leakage.
- **`web/`**:
  - `AuthController.java`: Login and registration routes.
  - `DashboardController.java`: Central dashboard with metrics.
  - `KeyController.java`: Key generation and export views.
  - `SignController.java`: Document signing and `.dsig.json` download.
  - `VerifyController.java`: Multipart document/envelope upload verification.
  - `TrustController.java`: Fingerprint pinning and revocation.
  - `HistoryController.java`: Verification history audit log view.
  - `AuditController.java`: Admin audit log view and cryptographic chain validation.
  - `ApiController.java`: REST health check endpoint (`/api/health`).
- **`resources/`**:
  - `application.yml` & `application-demo.yml`: Production HTTPS and local demo configurations.
  - `db/migration/V1__init.sql` & `V2__audit.sql`: Database migration scripts.
  - `templates/`: Full Thymeleaf views (`login.html`, `register.html`, `dashboard.html`, `keys.html`, `sign.html`, `verify.html`, `result.html`, `trust.html`, `history.html`, `audit.html`, `error.html`).
  - `templates/fragments/`: `layout.html`, `header.html`, `flash.html`.
  - `static/css/app.css`: Dark-mode interface styles with result status color badges.
  - `static/js/sign.js` & `verify.js`: Client-side validation scripts.

### 5. Documentation, Scripts & Test Fixtures
- **`docs/FORMAT.md`**: Detached envelope and manifest serialization specification.
- **`docs/THREAT_MODEL.md`**: Threat model matrix, attack vectors, and mitigations.
- **`docs/diagrams/architecture.mmd`**: Mermaid diagram of overall architecture and trust boundaries.
- **`docs/benchmark/README.md`**: Performance test suite documentation.
- **`docs/report/README.md`**: Academic report archive.
- **`scripts/gen-cert.sh` & `gen-cert.ps1`**: TLS 1.3 self-signed certificate generation scripts.
- **`scripts/run-demo.sh` & `run-demo.ps1`**: Automated demonstration scripts.
- **`scripts/fuzz.sh` & `bench.sh`**: Fuzzing and microbenchmark test runners.
- **`test-data/`**: Created `sample_1kb.txt`, `contract.txt`, `malformed_envelope.json`, and `tampered_envelope.json`.
- **`runtime/.gitkeep`**: Runtime directory placeholder.

---

## [Phase 2: Complete Implementation of Work Package 2 (Devraj Sundrani)] - 2026-10-10

### Member: Devraj Sundrani
### Work Package: Document Processing & SHA-256 Hashing

1. **Enhanced `HashService.java`**:
   - Implemented streaming SHA-256 computation over arbitrary `InputStream` instances using a fixed 64 KB buffer (`STREAM_BUFFER_SIZE = 65536`) to guarantee constant-memory execution regardless of document size.
   - Added `hashFile(Path filePath)` with buffered streaming for direct file paths on disk.
   - Added `hashBytes(byte[] data)` for fast in-memory hashing.
   - Implemented simultaneous byte counting (`totalBytes += bytesRead`) during digest updating, eliminating separate filesystem calls.
   - Added format agnosticism: operates purely on raw binary bytes (PDFs, executables, images, plain text).
   - Added strict input validation: rejects 0-byte files with `EmptyDocumentException`.
   - Added robust error handling: wraps low-level I/O read interruptions into `DocumentReadException`.
   - Added convenience constant-time comparison methods: `verifyHash` and `verifyHexHash`.

2. **Error Hierarchy Extensions**:
   - Created `EmptyDocumentException.java` (subclass of `DsigException`) to explicitly handle empty documents.
   - Created `DocumentReadException.java` (subclass of `DsigException`) to isolate and report I/O read errors.

3. **Enhanced `ConstantTime.java`**:
   - Implemented constant-time byte array equality via `MessageDigest.isEqual`.
   - Implemented constant-time UTF-8 string equality.
   - Added `equalsHex(String hexA, String hexB)` with whitespace and case normalization to prevent timing side-channels during digest comparisons.

4. **NIST FIPS 180-4 Known-Answer Tests (`HashServiceTest.java`)**:
   - Implemented official NIST Known-Answer Test (KAT) Vector 1: `"abc"`.
   - Implemented official NIST KAT Vector 2: `"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"`.
   - Implemented official NIST KAT Vector 3: 1,000,000 repetitions of `'a'` streamed in chunks without full memory allocation.
   - Tested multi-buffer streaming boundary crossing (150 KB stream over 64 KB buffer).
   - Tested custom small buffer sizes (16 bytes).
   - Tested arbitrary binary data (PDF headers, null bytes, EOF flags).
   - Tested rejection of empty streams and 0-byte byte arrays.
   - Tested simulated I/O errors and directory paths.
   - Tested constant-time equality evaluation.

5. **Performance Benchmarking Suite (`HashBenchmarkTest.java`)**:
   - Microbenchmark evaluating latency and throughput across 1 KB, 1 MB, and 25 MB streams.
   - Demonstrated constant memory invariance using virtual generator streams.

6. **Technical Documentation**:
   - Authored `docs/HASHING.md`: Comprehensive engineering specification on why hashing is decoupled from RSA, mathematical constraints ($m < n$), performance comparisons, side-channel protections, and NIST test vectors.
   - Authored `docs/benchmark/hashing_benchmark.md`: Detailed performance metrics recording throughput (~350–420 MB/s) and sub-3ms latency for typical 1 MB documents.

---

## [Phase 2: Key Generation, Secure Storage & Fingerprints Implementation] - 2026-10-11
### Member 4 — Atharv Vedant
### Work Package: Key Generation, Secure Storage & Fingerprints

1. **Enhanced `KeyStorage.java`**:
   - Implemented standard PBES2 PKCS#8 encrypted private key serialization with standard ASN.1 OID mapping (`1.2.840.113549.1.5.13`) via `AlgorithmParameters.getInstance("PBES2")`.
   - Enforced minimum RSA key size ($\ge 3072$ bits) across all public key exports, public key imports, private key saves, and private key loads, rejecting legacy/weak keys with `KeyValidationException`.
   - Sanitized decryption error handling: masked all cryptographic/format exceptions into uniform `CryptoException("Invalid passphrase or corrupted key file")` to eliminate side-channel error oracles.
   - Implemented in-memory passphrase zeroization utility (`KeyStorage.zeroize(char[])`) to overwrite secret buffers with null bytes (`'\0'`).
   - Added robust PEM parsing with support for standard headers, raw Base64 SPKI, and defensive malformed input validation.

2. **Enhanced `KeyService.java`**:
   - Enforced strict RSA-3072 modulus and standard Fermat-4 ($F_4 = 65537$) exponent checks on generated keys.
   - Integrated short Key ID derivation (`keyId()`) into `GeneratedKeyPair` container with full backward compatibility.

3. **Enhanced `Fingerprint.java`**:
   - Implemented canonical 16-character short Key ID extraction (`toKeyId(String)`, `toKeyId(PublicKey)`).
   - Added `isValidFingerprint(String)` 64-character hexadecimal format validator.
   - Added defensive bounds checking and null validation.

4. **Enhanced `KeyStatus.java`**:
   - Implemented cryptographic lifecycle permissions: `canSign()` (restricted strictly to `ACTIVE`), `canVerify()` (permitted for `ACTIVE` and `RETIRED`, rejected for `REVOKED`).
   - Implemented validated state machine transitions via `validateTransition(KeyStatus)` and `transitionTo(KeyStatus)`, enforcing non-reactivation of retired keys and terminal immutability of revoked keys.

5. **Key Management Unit Test Suite (`dsig-core/src/test/java/com/acns/dsig/core/keys/`)**:
   - `KeyServiceTest.java`: 3 tests verifying RSA-3072 modulus, $F_4$ exponent, CSPRNG randomness/entropy, and fingerprint/keyId binding.
   - `FingerprintTest.java`: 7 tests verifying determinism, SPKI hashing KATs, 4-char grouped formatting, 16-char Key ID derivation, hex validation, and defensive null checks.
   - `KeyStatusTest.java`: 5 tests verifying signing permissions, verification permissions, valid state transitions, and rejection of invalid state transitions.
   - `KeyStorageTest.java`: 10 tests verifying disk roundtrip encryption/decryption, wrong passphrase generic errors, corrupted ciphertext handling, non-existent file handling, PEM roundtrip, raw Base64 parsing, weak key (< 3072 bits) rejection across export/import/save, and memory zeroization.
   - **Total Core Suite:** 72 tests run, 0 failures, 0 errors, 100% build success.

6. **Technical Documentation**:
   - Authored `docs/KEY_MANAGEMENT.md`: Comprehensive engineering specification covering RSA-3072 parameter selection, PBES2 PBKDF2-HMAC-SHA256 encrypted storage, SPKI fingerprint formulas, lifecycle state machines, and threat countermeasures.

---

## [Phase 3: QA, CI/CD Pipeline Hardening, Test Infrastructure & Demo Automation] - 2026-10-11
### Member 10 — Simrit Kaur
### Work Package: QA Automation, CI/CD, Test Infrastructure & Shared Documentation

1. **End-to-End CLI Integration Testing (`DsigCliIntegrationTest.java`)**:
   - Built complete CLI lifecycle test suite in `dsig-cli` testing `keygen`, `fingerprint`, `trust-add`, `sign`, and `verify`.
   - Covered key outcomes: `VALID_TRUSTED` (exit 0), `VALID_UNTRUSTED_SIGNER` (exit 2), `DOCUMENT_TAMPERED` (exit 1), and `CORRUPTED_PACKAGE` (exit 1).
   - Validated command-line stream outputs and exit code semantics.

2. **Parser & Envelope Fuzz Testing Suite (`EnvelopeFuzzTest.java`)**:
   - Created comprehensive fuzz test suite in `dsig-core/src/test/java/com/acns/dsig/core/fuzz/`.
   - Evaluated 100 random bitflip mutations across envelope bytes, progressive length truncations, invalid and corrupted Base64 strings, negative/corrupted manifest properties, duplicate keys, and oversized envelope rejection against `FormatLimits`.
   - Verified that invalid inputs fail cleanly without throwing unexpected unchecked exceptions or crashing the JVM.

3. **Cryptographic Performance Benchmarking Suite (`CryptoBenchmarkTest.java`)**:
   - Created complementary microbenchmark suite profiling RSA-3072 key generation latency, RSASSA-PSS signing throughput (~229 ops/sec), and full verification pipeline throughput (~619 ops/sec).
   - Complemented Devraj's streaming SHA-256 microbenchmark without duplicating hashing measurements.

4. **Automation Scripts Hardening (`scripts/`)**:
   - **`scripts/bench.sh`**: Updated to invoke both `HashBenchmarkTest` and `CryptoBenchmarkTest` using the project Maven wrapper; removed silencing `|| true` so genuine performance regressions or failures return a failing exit code.
   - **`scripts/fuzz.sh`**: Linked directly to `EnvelopeFuzzTest`; removed `|| true` to preserve failure detection.
   - **`scripts/run-demo.ps1` & `scripts/run-demo.sh`**: Hardened end-to-end demo flows to use isolated directories (`runtime/demo-temp/`), complete keygen, fingerprint extraction, trust store pinning, signing, legitimate verification, tampering injection, and automated artifact cleanup in `try/finally` blocks and Bash traps.

5. **CI/CD Pipeline Hardening (`.github/workflows/ci.yml`)**:
   - Enhanced GitHub Actions workflow to set execute permissions on Maven wrapper (`chmod +x mvnw`) and execute `./mvnw clean verify --batch-mode`, ensuring reproducible builds regardless of hosted runner Maven versions.

6. **Documentation & Instructions**:
   - Updated `README.md` with dedicated section 5 covering test suite commands, microbenchmark execution, fuzz testing, and PowerShell/Bash demo scripts.
