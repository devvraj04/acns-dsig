# Project Implementation Report (`docs/report.md`)
## Secure Digital Document Authentication and Integrity Verification Using Digital Signatures

**Course:** Applied Cryptography and Network Security (CNS / ACNS-DC)  
**Project Architecture:** Multi-Module Maven (`dsig-core`, `dsig-cli`, `dsig-server`)  
**Target Platform:** Java 21 LTS / Spring Boot 3 / Picocli  

---

## 1. Executive Summary & Objective

In modern distributed workflows, digital documents (legal agreements, invoices, software packages, financial records) are constantly transmitted across untrusted communication channels such as public cloud storage, email, and portable USB devices. Attackers or malicious intermediaries can tamper with document contents, forge signatures, or replace signer public keys.

The objective of this project is to construct a complete, production-grade cryptographic system that provides:
1. **Document Integrity:** Bit-level detection of document alteration.
2. **Cryptographic Origin Authentication:** Proof of signature authenticity using asymmetric cryptography.
3. **Signer Identity Binding:** Out-of-band trust establishment via public-key fingerprint pinning to defeat public-key substitution.
4. **Auditability:** Tamper-evident, forward hash-chained logging of all signing, verification, and administrative actions.
5. **Transport Security:** Hardened communication using TLS 1.3, CSRF protection, and security headers.

---

## 2. Why Each Component Was Created & Architectural Rationale

### 2.1 Multi-Module Decomposition (`dsig-core`, `dsig-cli`, `dsig-server`)
- **Reason:** The cryptographic logic must remain framework-free, completely isolated from web frameworks or external networking libraries. This guarantees that cryptographic algorithms can be unit-tested in isolation, reused in offline CLI tools, and independently verified for correctness.
- **How Implemented:**
  - `dsig-core`: Pure Java using Java Cryptography Architecture (JCA) and Jackson for strictly-parsed JSON envelopes. Zero dependencies on Spring.
  - `dsig-cli`: Offline Command-Line Interface using Picocli. Allows signers to generate keys and sign documents locally where their private key never leaves their machine.
  - `dsig-server`: Spring Boot 3 web application providing user authentication, trust store management, verification history, and browser interfaces.

### 2.2 RSA-PSS (RSASSA-PSS) Instead of Textbook RSA
- **Reason:** Textbook RSA ("encrypting the hash") is cryptographically insecure and vulnerable to malleability attacks, chosen-ciphertext attacks, and mathematical relations between ciphertexts. Real-world standards (RFC 8017 / PKCS#1 v2.2) mandate **RSASSA-PSS** (Probabilistic Signature Scheme), which incorporates randomized salting, Mask Generation Function (MGF1), and provable security bounds reducible to the RSA problem in the random oracle model.
- **How Implemented:**
  - Configured in `SignatureService.java` using JCA `Signature.getInstance("RSASSA-PSS")` with `PSSParameterSpec` using SHA-256 for hashing, MGF1 with SHA-256, and a 32-byte salt (`SaltLength=32`).
  - Key validation strictly enforces RSA modulus size ≥ 3072 bits, ensuring security against factorization attacks beyond 2030 standards.

### 2.3 Streaming SHA-256 Document Hashing
- **Reason:** Real-world documents can range from a few kilobytes to several gigabytes. Loading an entire file into memory before computing a digest creates denial-of-service risks (OutOfMemoryError) and limits scalability.
- **How Implemented:**
  - Implemented in `HashService.java` with a fixed 64 KB buffer (`STREAM_BUFFER_SIZE = 65536`).
  - Document bytes are streamed incrementally through `MessageDigest.update()`. The byte count is computed simultaneously, and empty files (0 bytes) are rejected as an invalid signing target.

### 2.4 Domain Separation
- **Reason:** Cross-protocol attacks occur when signed bytes from one context can be replayed or misinterpreted in another protocol.
- **How Implemented:**
  - `SignatureService` prefixes all manifest bytes with the fixed protocol domain separation label: `ACNS-DSIG-v1\0` (`CryptoConfig.DOMAIN_LABEL`) before passing to RSA-PSS.

### 2.5 Detached Signature Package & Signed Manifest (`.dsig.json`)
- **Reason:** Modifying the original document (e.g., embedding signatures into PDF or docx) alters the file format, complicates verification of arbitrary formats (e.g., binaries, source code, text files), and risks format-specific parsing vulnerabilities. A detached signature package preserves the original file bit-for-bit.
- **How Implemented:**
  - Implemented in `format/Manifest.java` and `Envelope.java`.
  - The signed manifest binds the document hash, document byte size, hash algorithm (`SHA-256`), signature algorithm (`RSASSA-PSS-SHA256-MGF1SHA256-S32`), public key fingerprint (`keyId`), UTC timestamp, anti-replay nonce, and signer name.
  - The verifier validates the signature directly over the exact raw bytes of the manifest, preventing canonicalization attacks.
  - Strict parsing in `EnvelopeCodec.java` activates Jackson's `STRICT_DUPLICATE_DETECTION` and rejects unknown fields.

### 2.6 Public-Key Fingerprint Pinning & Trust Model
- **Reason:** Bundling a public key inside a signature envelope only proves that the document was signed by *some* private key; it does not prove *who* owns that key. An attacker could replace the document, recalculate the signature with their own key, and bundle their own public key. Without an explicit trust check, naive verifiers would report "Valid".
- **How Implemented:**
  - Calculated in `Fingerprint.java` as `SHA-256(DER SubjectPublicKeyInfo)`.
  - The user/verifier confirms the fingerprint through an out-of-band channel and pins it into the trust store (`FileTrustStore` or `TrustedSignerRepository`).
  - `TrustPolicy.java` maps the cryptographic outcome and trust status to distinct states:
    - `VALID_TRUSTED`: Signature valid, document unchanged, key fingerprint pinned as TRUSTED.
    - `VALID_UNTRUSTED_SIGNER`: Signature valid and document unchanged, but key is NOT in the trust store (amber warning; verifier is alerted).
    - `DOCUMENT_TAMPERED`: Signature valid, but document bytes do not match signed hash (red alert; tamper visualization displayed).

### 2.7 Encrypted Private Key Storage at Rest (PBES2 AES-256)
- **Reason:** Storing private keys in plaintext on disk exposes credentials to filesystem inspection, unauthorized user access, and accidental leaks.
- **How Implemented:**
  - `KeyStorage.java` encrypts private keys using Password-Based Encryption (PBES2) with `PBEWithHmacSHA256AndAES_256`, 16-byte cryptographic salt, and 600,000 PBKDF2 iterations.
  - Private keys are stored in encrypted PKCS#8 format (`.pk8`), requiring the owner's passphrase to decrypt in memory only during signing. Passphrases and decrypted key references are cleared after use.

### 2.8 Tamper-Evident Hash-Chained Audit Log
- **Reason:** Audit logs in relational databases are vulnerable to retroactive tampering or deletion by compromised accounts.
- **How Implemented:**
  - `AuditChainService.java` implements cryptographic chaining:
    $$\text{entry\_hash}_i = \text{SHA-256}(\text{prev\_hash}_{i-1} \parallel \text{seq}_i \parallel \text{timestamp}_i \parallel \text{user}_i \parallel \text{action}_i \parallel \text{detail}_i)$$
  - Initial genesis link uses 64 zeros.
  - The administrator can invoke `verifyChainIntegrity()`, which traverses the entire audit sequence from sequence 1 onwards, immediately detecting any modified, deleted, or inserted rows.

### 2.9 Application & Network Security Hardening
- **Reason:** The web tier must defend against web application vulnerabilities, automated brute-forcing, and transport interception.
- **How Implemented:**
  - **TLS 1.3:** Enforced via `application.yml` and self-signed keystore generation scripts (`scripts/gen-cert.sh` / `gen-cert.ps1`).
  - **Rate Limiting:** `RateLimitFilter.java` implements a sliding-window rate limiter on sensitive endpoints (`/login`, `/sign`, `/verify`).
  - **Brute-Force Lockout:** `LoginAttemptService.java` locks out accounts after 5 consecutive failures.
  - **Upload Hardening:** `UploadGuard.java` enforces size caps (50 MB), generates random temporary files in `runtime/uploads-tmp/`, and guarantees cleanup in `finally` blocks.
  - **Security Headers:** Configured Content Security Policy (CSP), HTTP Strict Transport Security (HSTS), `X-Content-Type-Options: nosniff`, and `X-Frame-Options: DENY`.
  - **Error Masking:** `GlobalExceptionHandler.java` generates opaque incident reference IDs (e.g. `Ref: a1b2c3d4`) without leaking stack traces or cryptographic internals.

---

## 3. Team Work Package Allocation & Deliverables

The project structure cleanly divides responsibilities across all 10 team members:

| Member | Work Package | Delivered Components |
|---|---|---|
| **Deven Thakkar** | Verification Engine & Result Model | `VerificationService`, `VerificationResult`, `ResultCode`, `TrustPolicy`, `DsigException` |
| **Devraj Sundrani** | Document Processing & SHA-256 Hashing | `HashService`, `ConstantTime`, `DsigCli`, CLI commands (`SignCommand`, `VerifyCommand`, etc.) |
| **Tanmay Vishwakarma** | RSA-PSS Signature Engine | `SignatureService`, `CryptoConfig`, `SigningService` |
| **Atharv Vedant** | Key Generation & Secure Key Storage | `KeyService`, `KeyStorage` (PBES2 AES-256), `Fingerprint`, `KeyStatus` |
| **Parth Zala** | Manifest, Envelope & Strict Codec | `Manifest`, `Envelope`, `EnvelopeCodec`, `FormatLimits`, `docs/FORMAT.md` |
| **Nityanand Upadhyay**| Users, Database & Audit Chain | JPA Entities (`User`, `KeyPairEntity`, `TrustedSigner`, `VerificationRecord`, `AuditLog`), `AuditChainService`, `UserService`, `HistoryService` |
| **KVS Varshith** | Signing Web Interface & Key UI | `KeyController`, `SignController`, `templates/keys.html`, `templates/sign.html`, `static/js/sign.js` |
| **Jay Pandya** | Verification Web Interface & Trust UI | `VerifyController`, `TrustController`, `AuditController`, `templates/verify.html`, `templates/result.html`, `templates/trust.html`, `templates/history.html` |
| **Diyaan Rambhia** | Network & Application Security | `SecurityConfig`, `RateLimitFilter`, `UploadGuard`, `docs/THREAT_MODEL.md`, `application.yml` |
| **Simrit Kaur** | QA, CI/CD, Documentation & Demo | Maven Wrapper (`mvnw`), GitHub Actions CI (`ci.yml`), `README.md`, shell scripts, test fixtures (`test-data/`), report archive |

---

## 4. Verification Flow & Decision Logic

When a verifier provides a document and a detached `.dsig.json` envelope, `VerificationService` executes the following sequence:

```text
Receive document stream + envelope JSON
               ↓
Parse envelope strictly (Reject duplicate keys & oversized JSON)
               ↓
Validate format ("ACNS-DSIG") and version (1)
               ↓
Decode Base64 manifest, signature, and public key
               ↓
Parse manifest strictly (validate algorithms: SHA-256, RSASSA-PSS-SHA256-MGF1SHA256-S32)
               ↓
Validate RSA public key (modulus >= 3072 bits)
               ↓
Verify public key fingerprint matches manifest keyId
               ↓
Verify RSASSA-PSS signature over LABEL || manifestBytes FIRST (authenticates manifest)
               ↓
Stream received document through SHA-256
               ↓
Compare recomputed hash with authenticated manifest docHash
     ├── Mismatch → Return DOCUMENT_TAMPERED (Show both digests)
     └── Match    → Continue to Trust Evaluation
               ↓
Check public key fingerprint against Trust Store
     ├── Key in Trust Store (TRUSTED)     → Return VALID_TRUSTED (Green)
     ├── Key Revoked or Retired           → Return REVOKED_OR_RETIRED_KEY (Red)
     └── Key Not in Trust Store (UNKNOWN) → Return VALID_UNTRUSTED_SIGNER (Amber)
               ↓
Record Verification in History & Append Event to Hash-Chained Audit Log
```

---

## 5. Verification & Testing Evidence

The initial project skeleton includes `CryptoCoreTest.java` running against `dsig-core`:
1. **Streaming Hash Test:** Confirms correct SHA-256 digest computation with constant-time equality.
2. **Key Generation Test:** Validates generation of 3072-bit RSA keys and derivation of 64-character hex fingerprints.
3. **End-to-End Positive Test:** Demonstrates signature creation and verification returning `VALID_TRUSTED` when the signer's key is pinned.
4. **Tampered Document Test:** Confirms that modifying document content immediately triggers `DOCUMENT_TAMPERED`.
5. **Untrusted Signer Test:** Confirms that an authentic signature generated by an unpinned signer correctly returns `VALID_UNTRUSTED_SIGNER` rather than a naive green status.

---

## 6. Work Package 2 Detailed Implementation Report (Devraj Sundrani)

### 6.1 Assigned Ownership & Responsibilities
- **Owner:** Devraj Sundrani (Member 2)
- **Work Package:** Document Processing & SHA-256 Hashing
- **Owned Components:**
  - `com.acns.dsig.core.crypto.HashService`
  - `com.acns.dsig.core.crypto.ConstantTime`
  - `com.acns.dsig.core.error.EmptyDocumentException`
  - `com.acns.dsig.core.error.DocumentReadException`
  - `com.acns.dsig.core.crypto.HashServiceTest` (NIST KAT suite)
  - `com.acns.dsig.core.crypto.HashBenchmarkTest` (Microbenchmarks)
  - `docs/HASHING.md` (Technical specification)
  - `docs/benchmark/hashing_benchmark.md` (Benchmark measurements)

### 6.2 Why Each Component Was Created & How It Was Implemented

#### 1. Streaming SHA-256 with Fixed 64 KB Buffer
- **Why:** Traditional `file.getBytes()` approaches load the entire file into memory at once, creating denial-of-service risks (OutOfMemoryError) when multiple concurrent users process large documents.
- **How Implemented:** `HashService.java` streams arbitrary `InputStream` or `Path` targets through a fixed 64 KB buffer (`STREAM_BUFFER_SIZE = 65536`). Heap memory consumption remains strictly constant ($\mathcal{O}(1)$) regardless of document file size.

#### 2. Simultaneous Document Size Calculation
- **Why:** Section 6 of the Master Plan requires binding the exact document byte size (`docSize`) into the signed manifest to prevent truncation or padding attacks. Relying on separate filesystem `length()` calls creates race conditions if files are modified concurrently.
- **How Implemented:** `HashService` increments `totalBytes += bytesRead` directly inside the streaming loop, atomically capturing size and hash during a single I/O pass.

#### 3. Format Agnosticism
- **Why:** The system authenticates digital documents of all types (PDF, Word, PNG, ZIP, binary executables, plain text).
- **How Implemented:** The service processes raw bytes without assuming character encodings or MIME types, computing bit-level digests across all formats identically.

#### 4. Handling Empty Files & Read Failures
- **Why:** Section 8.3 of the Master Plan explicitly mandates that empty files (0 bytes) cannot be signed or verified. In addition, hardware interruptions or unreadable files must produce clear, distinct errors.
- **How Implemented:**
  - Throws `EmptyDocumentException` when `totalBytes == 0`.
  - Catches low-level `IOException` during streaming and wraps it in `DocumentReadException` with full diagnostic context.

#### 5. Constant-Time Hash Comparison
- **Why:** Standard `Arrays.equals()` and `String.equals()` short-circuit on the first differing byte, leaking timing information that enables adversaries to incrementally guess digests through timing attacks.
- **How Implemented:** `ConstantTime.java` executes `MessageDigest.isEqual()`, providing constant-time byte and hex string equality checks for all verification decisions.

#### 6. NIST FIPS 180-4 Known-Answer Tests (KAT)
- **Why:** Cryptographic correctness cannot be assumed; it must be proven against official NIST test vectors.
- **How Implemented:** `HashServiceTest.java` validates:
  - Vector 1: `"abc"`
  - Vector 2: `"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"`
  - Vector 3: $1,000,000$ repetitions of character `'a'` streamed in chunks
  - Multi-buffer boundary streaming (150 KB over 64 KB buffer)
  - Custom buffer sizes (16 bytes)
  - Arbitrary binary byte arrays (PDF headers, null bytes)
  - Rejection of 0-byte streams and files

#### 7. Performance Measurement & Benchmarks
- **Why:** Section 18.5 requires benchmarking across representative file sizes (1 KB, 1 MB, 25 MB).
- **How Implemented:** `HashBenchmarkTest.java` and `docs/benchmark/hashing_benchmark.md` confirm throughput of **~350–420 MB/s** and sub-3ms latency for typical 1 MB documents, with constant memory footprint proven via virtual generator streams.

---

## 7. Conclusion

The initial project structure for **ACNS-DSIG** has been established, and **Member 2 (Devraj Sundrani)'s assigned work package (Document Processing & SHA-256 Hashing)** has been completely implemented, verified with NIST Known-Answer Tests, profiled with microbenchmarks, and documented in detail in `docs/HASHING.md` and `docs/benchmark/hashing_benchmark.md`.

