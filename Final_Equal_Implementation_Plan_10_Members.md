# Equal 10-Member Implementation Plan
## Digital Signature-Based Document Authentication and Verification System

This plan keeps the master implementation plan unchanged in scope, architecture, cryptographic approach, security controls, testing strategy, and deliverables. Only the ownership model is changed: there is **no project lead**. The project is divided into ten peer-level work packages with clear interfaces and roughly balanced implementation effort.

## 1. Team Work Allocation

| Member | Work Package | Primary Technical Ownership | Main Deliverables |
|---|---|---|---|
| Deven Thakkar | Verification Engine & Result Model | VerificationService, result states, verification flow | Verification core, result model, verification tests |
| Devraj Sundrani | Document Processing & Hashing | Streaming SHA-256, file handling utilities | HashService, hashing tests, performance data |
| Tanmay Vishwakarma | RSA-PSS Signature Engine | SignatureService, signature parameters | RSA-PSS sign/verify implementation, crypto tests |
| Atharv Vedant | Key Generation & Secure Key Storage | KeyService, encrypted PKCS#8 storage | Key lifecycle, PEM handling, key tests |
| Parth Zala | Manifest, Envelope & Format | Manifest, EnvelopeCodec, strict parsing | `.dsig.json`, FORMAT.md, format tests |
| Nityanand Upadhyay | Users, Database & Authentication | H2 schema, users, sessions, roles, persistence | Database, auth, history/trust persistence, backend tests |
| KVS Varshith | Signing Web Interface & Sign Flow | Thymeleaf sign/key screens and integration | Sign UI, key UI, frontend validation |
| Jay Pandya | Verification Web Interface & Trust UI | Verify/result/trust/history screens | Verification UI, trust UI, result visualization |
| Diyaan Rambhia | Network & Application Security | TLS, CSRF, secure uploads, rate limiting, headers | Security configuration, security tests |
| Simrit Kaur | QA, CI/CD, Documentation & Demo Infrastructure | Automated test pipeline, CI, shared documentation tooling | CI, integration test harness, test evidence, demo environment |

> **Important:** No one is the project lead. Architecture decisions, final integration, release approval, and demonstration are shared by all ten members.

---

# 2. Detailed Responsibilities

## Member 1 — Deven Thakkar
### Work Package: Verification Engine & Result Model

### Owns
- `VerificationService`
- Verification result model
- Verification decision flow
- Mapping cryptographic outcomes to user-facing states

### Tasks
1. Implement the complete verification sequence:
   - validate envelope
   - validate version/algorithms
   - decode required fields
   - load/resolve public key
   - check key fingerprint consistency
   - verify RSA-PSS signature
   - recompute document SHA-256
   - compare document size/hash
   - evaluate signer trust
2. Implement result states:
   - `VALID_TRUSTED`
   - `VALID_UNTRUSTED_SIGNER`
   - `DOCUMENT_TAMPERED`
   - `INVALID_SIGNATURE`
   - `INVALID_KEY`
   - `UNSUPPORTED_FORMAT`
   - `MISSING_METADATA`
   - `CORRUPTED_PACKAGE`
   - `REVOKED_OR_RETIRED_KEY`
3. Ensure verification never exposes parser/crypto internals to users.
4. Provide a stable result object/API for the backend and CLI.
5. Write unit tests for the decision tree.
6. Integrate the core verification components from Members 2–5.

### Deliverables
- `VerificationService`
- verification result classes/enums
- verification unit tests
- verification sequence documentation

---

## Member 2 — Devraj Sundrani
### Work Package: Document Processing & SHA-256 Hashing

### Owns
- `HashService`
- streaming file processing
- size calculation during hashing

### Tasks
1. Implement SHA-256 using streaming input.
2. Use a fixed buffer instead of loading full files into memory.
3. Calculate document size during processing.
4. Support arbitrary file types because the system signs file bytes rather than interpreting document contents.
5. Implement constant-time hash comparison support.
6. Handle empty files and read failures.
7. Prepare known-answer tests for SHA-256.
8. Measure hashing performance for representative file sizes.
9. Document why hashing is separate from RSA signing.

### Deliverables
- `HashService`
- hashing utilities
- JUnit tests
- hashing performance measurements

---

## Member 3 — Tanmay Vishwakarma
### Work Package: RSA-PSS Digital Signature Engine

### Owns
- `SignatureService`
- RSA-PSS configuration
- signature/verification primitives

### Tasks
1. Implement RSA-3072 key-compatible signing.
2. Configure RSASSA-PSS with:
   - SHA-256
   - MGF1-SHA256
   - 32-byte salt
3. Implement signature generation.
4. Implement signature verification.
5. Implement the fixed domain-separation label used by the project.
6. Reject unsupported signature configurations.
7. Create positive and negative signature tests.
8. Test wrong-key verification and modified signatures.
9. Keep all production cryptography inside standard Java cryptographic APIs; no custom RSA arithmetic.
10. Optionally prepare the benchmark code after the MVP is complete.

### Deliverables
- `SignatureService`
- RSA-PSS parameter configuration
- signature tests
- optional benchmark utility

---

## Member 4 — Atharv Vedant
### Work Package: Key Generation, Secure Storage & Fingerprints

### Owns
- `KeyService`
- `KeyStorage`
- fingerprint generation
- local key lifecycle logic

### Tasks
1. Generate RSA-3072 key pairs.
2. Generate/store public keys in PEM form.
3. Store private keys as encrypted PKCS#8 PEM.
4. Implement passphrase-based decryption/loading.
5. Enforce minimum RSA key size on load.
6. Generate SHA-256 SPKI fingerprints.
7. Implement key IDs from fingerprints.
8. Handle wrong passphrases with generic errors.
9. Implement key rotation/retirement state support.
10. Implement revoked-key state support required by verification.
11. Ensure private-key material is never logged or returned through APIs.
12. Write key-management tests.

### Deliverables
- `KeyService`
- `KeyStorage`
- fingerprint utilities
- key lifecycle tests

---

## Member 5 — Parth Zala
### Work Package: Manifest, Detached Envelope & Strict Format

### Owns
- `Manifest`
- `Envelope`
- `EnvelopeCodec`
- `FORMAT.md`

### Tasks
1. Implement the project manifest.
2. Include the required signed fields:
   - version
   - document name
   - document size
   - hash algorithm
   - document hash
   - signature algorithm
   - key ID
   - signing timestamp
   - nonce
   - signer information
3. Implement detached `.dsig.json` packaging.
4. Preserve the exact manifest bytes that are signed.
5. Implement Base64 encoding/decoding.
6. Enforce size and field limits.
7. Reject malformed JSON, missing fields, invalid Base64, duplicate keys and unsupported versions/algorithms.
8. Ensure attacker-controlled metadata is treated as untrusted until verified.
9. Define the final package format in `FORMAT.md`.
10. Create round-trip and malformed-input tests.

### Deliverables
- manifest classes
- envelope classes
- `EnvelopeCodec`
- `FORMAT.md`
- format tests

---

## Member 6 — Nityanand Upadhyay
### Work Package: Database, Users, Authentication & Persistence

### Owns
- H2 database
- persistence layer
- user/account management
- application roles

### Tasks
1. Create the H2 file-mode database.
2. Implement tables for:
   - users
   - key pairs
   - trusted signers
   - verification records
   - audit log
3. Implement registration/login persistence.
4. Implement BCrypt password hashing.
5. Implement roles:
   - SIGNER
   - VERIFIER
   - ADMIN
6. Implement verification-history persistence.
7. Implement trust-store persistence.
8. Implement key ownership checks at the persistence/service boundary.
9. Add migrations/schema initialization.
10. Ensure private-key bytes are never stored inside database columns.
11. Provide persistence APIs consumed by Members 7, 8 and 9.

### Deliverables
- H2 schema/migrations
- repositories/DAOs
- account/auth persistence
- role and ownership checks
- backend persistence tests

---

## Member 7 — KVS Varshith
### Work Package: Signing Web Interface

### Owns
- Thymeleaf signing pages
- key-generation UI
- sign workflow UI

### Tasks
1. Build key-generation screen.
2. Build signing screen.
3. Add file selection and client-side size checks.
4. Add key selection.
5. Add passphrase input handling.
6. Connect signing UI to backend services.
7. Display successful signature creation.
8. Provide download of the detached signature package.
9. Ensure private-key contents are never rendered to the browser.
10. Implement frontend validation and accessible error messages.
11. Write UI-level integration tests for the sign flow.

### Deliverables
- key-generation page
- sign page
- sign workflow integration
- frontend validation
- UI tests

---

## Member 8 — Jay Pandya
### Work Package: Verification Web Interface, Results & Trust UI

### Owns
- verify page
- verification-result page
- trust-store interface
- history interface

### Tasks
1. Build document verification screen.
2. Build signature-envelope upload UI.
3. Display every verification result state correctly.
4. Display:
   - signer
   - fingerprint
   - timestamp
   - trust status
   - signed hash
   - recomputed hash
5. Implement side-by-side hash visualization for document tampering.
6. Implement trust-store display/add/revoke UI.
7. Implement verification-history display and filters.
8. Ensure green is used only for trusted valid results and that color is not the sole status indicator.
9. Connect pages to verification and persistence services.
10. Test all verification states from the UI.

### Deliverables
- verify page
- result page
- trust store UI
- history UI
- tamper visualization
- UI tests

---

## Member 9 — Diyaan Rambhia
### Work Package: Network & Application Security

### Owns
- Spring Security hardening
- transport security
- upload protection
- security filters/configuration

### Tasks
1. Configure TLS 1.3 only.
2. Configure secure session cookies.
3. Implement CSRF protection.
4. Configure HSTS and security headers.
5. Implement login lockout/rate limiting.
6. Implement request rate limiting where required.
7. Implement upload size limits.
8. Ensure uploaded filenames cannot become filesystem paths.
9. Ensure temporary uploads are safely cleaned.
10. Apply authorization and object ownership checks.
11. Disable unnecessary CORS.
12. Ensure generic authentication errors.
13. Ensure exception responses reveal no internal stack traces.
14. Run security validation using the agreed project tests/tools.

### Deliverables
- Spring Security configuration
- TLS configuration
- upload guard
- rate-limiting controls
- security test evidence

---

## Member 10 — Simrit Kaur
### Work Package: QA Automation, CI/CD, Test Infrastructure & Shared Documentation

### Owns
- CI pipeline
- automated integration-test harness
- shared test data
- release/demo infrastructure

### Tasks
1. Configure the Maven multi-module build pipeline.
2. Configure GitHub Actions CI.
3. Add automated unit/integration test execution.
4. Prepare shared sample documents and test fixtures.
5. Build integration-test scripts connecting the independently developed modules.
6. Maintain the master test-results table.
7. Coordinate fuzz-test execution against the package parser.
8. Maintain performance-test scripts and collected measurements.
9. Maintain shared README/setup documentation.
10. Maintain the final demo setup and reproducible run instructions.
11. Collect screenshots/logs/test evidence for the final report.
12. Prepare the demonstration environment, but demonstration delivery remains a shared team responsibility.

### Deliverables
- CI workflow
- shared test harness
- test fixtures
- master test evidence
- README/setup documentation
- reproducible demo environment

---

# 3. Shared Responsibilities

These activities are deliberately **not assigned to a single person**.

## Architecture
All ten members review the architecture and agree on interfaces before implementation begins.

## Code Review
Every pull request must have at least one reviewer other than the author. Reviews should rotate so all members participate.

## Integration
Each member is responsible for integrating their module with its defined dependencies. No single person owns final integration.

## Documentation
Each member documents their own module. Simrit maintains the common README and test evidence structure, but technical documentation remains distributed among module owners.

## Testing
Every member writes tests for their own module. Diyaan owns security testing, while Simrit owns CI/test infrastructure. Final acceptance testing is performed collectively.

## Final Demo
All ten members must understand the complete workflow:

```text
Key Generation
      ↓
SHA-256 Hashing
      ↓
Manifest Creation
      ↓
RSA-PSS Signing
      ↓
Detached Signature Package
      ↓
Transmission
      ↓
Package Validation
      ↓
Signature Verification
      ↓
Document Hash Recalculation
      ↓
Hash Comparison
      ↓
Trust Evaluation
      ↓
Verification Result
      ↓
History / Audit
```

---

# 4. Dependency Structure

```text
Devraj ──────┐
             │
Tanmay ──────┼──────> Parth ──────> Deven
             │                         │
Atharv ──────┘                         ↓
                                  Nityanand
                                    /     \
                                   /       \
                                  ↓         ↓
                                KVS       Jay
                                           │
                                           ↓
                                         Diyaan
                                           │
                                           ↓
                                         Simrit
```

This diagram represents **technical dependency, not hierarchy**. Members may work in parallel whenever their interfaces are stable.

---

# 5. Parallel Development Plan

## Phase 1 — Common Setup
All 10 members

- Freeze implementation interfaces.
- Create repository.
- Create Maven modules.
- Agree on package names and data contracts.
- Set coding standards.
- Create initial CI pipeline.

## Phase 2 — Core Cryptography and Format
Parallel:

- Devraj → hashing
- Tanmay → RSA-PSS
- Atharv → keys/storage
- Parth → manifest/envelope
- Deven → verification interfaces/result states
- Simrit → test infrastructure

## Phase 3 — Backend
Parallel:

- Nityanand → database/auth/persistence
- KVS → sign UI skeleton
- Jay → verify/trust UI skeleton
- Diyaan → Spring Security/TLS skeleton
- Core members → integration tests/fixes

## Phase 4 — Full Application Integration
- KVS connects sign UI.
- Jay connects verification/trust/history UI.
- Nityanand connects persistence.
- Deven connects verification engine.
- Diyaan hardens complete application.
- Simrit runs CI/integration pipeline.

## Phase 5 — Security and Testing
All members participate.

- Unit tests
- Integration tests
- Tampering tests
- Public-key substitution test
- Wrong-key test
- Malformed package test
- Authorization tests
- TLS/security tests
- Performance tests

## Phase 6 — Finalization
All members:

- Fix outstanding defects.
- Complete module documentation.
- Complete diagrams.
- Record real test results.
- Prepare demonstration scenarios.
- Verify reproducible setup.
- Conduct final peer review.

---

# 6. Equal Contribution Rule

To keep the workload genuinely balanced, every member has four responsibilities:

1. **Primary implementation** of their assigned work package.
2. **Unit/integration tests** for that work package.
3. **Technical documentation** for that work package.
4. **Integration support/review** for another member's work.

No member is limited to only documentation, only testing, or only coordination.

---

# 7. Suggested Cross-Review Pairs

These are review partnerships, not leadership assignments.

| Developer | Primary Review Partner |
|---|---|
| Deven | Tanmay |
| Devraj | Atharv |
| Tanmay | Deven |
| Atharv | Devraj |
| Parth | Nityanand |
| Nityanand | Diyaan |
| KVS | Jay |
| Jay | KVS |
| Diyaan | Nityanand |
| Simrit | Parth |

---

# 8. Final Ownership Summary

```text
Deven      → Verification Engine
Devraj     → SHA-256 / Document Processing
Tanmay     → RSA-PSS Signing
Atharv     → Key Management / Fingerprints
Parth      → Manifest / Signature Package
Nityanand  → Database / Users / Authentication
KVS        → Signing UI
Jay        → Verification / Trust UI
Diyaan     → Network / Application Security
Simrit     → QA Infrastructure / CI / Shared Documentation
```

There is **no project lead** in this structure. The system is delivered collectively, with each member owning a technically meaningful part of the same implementation plan.
