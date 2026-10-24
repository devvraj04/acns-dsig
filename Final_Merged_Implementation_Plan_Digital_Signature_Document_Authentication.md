# Final Merged Implementation Plan
## Secure Digital Document Authentication and Integrity Verification Using Digital Signatures

### Purpose
This is the consolidated implementation plan created by combining the original proposal-aligned implementation plan with the more detailed ACNS-DC security blueprint.

The original project flow is retained: RSA key generation → document hashing → digital signing → transmission → receiver-side verification → hash comparison → result/reporting. The cryptographic and security details are strengthened where the original proposal used simplified textbook wording or left important design decisions unspecified.

---
# 1. Final Scope

## 1.1 Core problem
Digital documents can be copied or modified while being exchanged through channels such as email, cloud storage or USB. The system must allow a receiver to verify:

1. **Integrity** — whether the received document is unchanged from the signed document.
2. **Cryptographic origin authentication** — whether the signature was generated using the corresponding private key.
3. **Signer trust status** — whether the public key belongs to a signer that the receiver has explicitly trusted.
4. **Auditability** — what was verified, when it was verified, and what result was obtained.

## 1.2 Core functional scope

The system will implement:

- RSA public/private key generation.
- SHA-256 document hashing.
- RSA digital signatures using **RSASSA-PSS**.
- A detached signature package containing the signed manifest and signature.
- Public-key fingerprint generation.
- Explicit signer trust using fingerprint pinning.
- Document and signature verification.
- Clear verification result states.
- Hash/tamper visualization.
- Verification history.
- User authentication and role-based access for the server application.
- TLS-protected web communication.
- Tamper-evident audit logging.
- Automated functional, negative, security and performance testing.

## 1.3 Optional scope

Implement only after the complete core system is stable:

- RSA + SHA-256 vs RSA + SHA-512 experimental comparison.
- Ed25519 performance comparison.
- ZIP bundle containing document + signature envelope.
- QR-based fingerprint exchange.
- Key revocation UI.
- mTLS or stronger second-factor authentication.

## 1.4 Explicitly out of scope

Do not implement these in the core project:

- Blockchain-based verification.
- A real public CA / full PKI hierarchy.
- X.509 certificate chains and CRL/OCSP infrastructure.
- Document encryption.
- PDF-specific embedded signatures such as PAdES.
- Microservices.
- React/Next.js solely for this project.
- PostgreSQL unless a later requirement forces it.
- Custom RSA arithmetic in production code.
- AI/ML features.

---

# 2. Final Architecture Decision

## 2.1 Recommended architecture

Use a **shared Java cryptographic core + CLI + Spring Boot web application**.

```text
                         HTTPS / TLS 1.3
       +------------------------------------------------+
       |             Spring Boot Server                 |
       |                                                |
User <-| Web UI -> Controllers -> Application Services |
       |                     |                          |
       |               Verification / Trust / Audit     |
       |                     |                          |
       |                dsig-core library               |
       |                     |                          |
       |              H2 database + key files          |
       +------------------------------------------------+
                    ^                    ^
                    |                    |
             local CLI signing     browser verification
                    |
             Private key stays
             on signer machine
```

## 2.2 Signing modes

### Primary/reference mode: local signing

The CLI performs key generation and signing locally. The private key never leaves the signer's machine.

This is the strongest and easiest-to-defend cryptographic workflow.

### Web signing mode: optional server-assisted mode

A web Sign screen may be implemented using an encrypted private-key file stored on the server. The passphrase is supplied only over TLS for the signing operation, the key is decrypted in memory for that operation, and secret material is cleared afterwards.

This mode must be documented as a **trusted-server signing mode**. It is convenient for the UI but does not provide the same key-isolation property as local signing.

---

# 3. Technology Stack

| Area | Final choice | Reason |
|---|---|---|
| Language | Java 21 LTS | Matches project/course and JCA support |
| Crypto API | Java Cryptography Architecture (JCA) | Standard, tested cryptographic primitives |
| Core | Plain Java module | Keeps cryptographic logic isolated and testable |
| CLI | picocli or equivalent simple Java CLI | Local key/sign/verify workflow |
| Server | Spring Boot 3 | Authentication, CSRF, TLS and validation support |
| UI | Thymeleaf + CSS + small vanilla JS | Keeps frontend simple and integrated with Spring |
| Database | H2 file mode | Small embedded database for users, trust, history and audit |
| Testing | JUnit 5 | Unit/integration testing |
| Build | Maven multi-module | Clear separation of modules |
| Network | HTTPS / TLS 1.3 | Protects application communication |

---

# 4. Cryptographic Design

## 4.1 RSA configuration

Use one fixed production configuration:

- RSA modulus: **3072 bits**
- Public exponent: **65537**
- Signature scheme: **RSASSA-PSS**
- Hash: **SHA-256**
- MGF: **MGF1 with SHA-256**
- Salt length: **32 bytes**
- Secure randomness: Java `SecureRandom`

Do not dynamically choose cryptographic algorithms from attacker-controlled input.

## 4.2 Why RSA-PSS instead of textbook "encrypt the hash"

The proposal describes the digital signature as encrypting the hash with RSA. That is useful as a classroom intuition, but the production implementation must use a real signature scheme.

Implementation:

```java
Signature signature = Signature.getInstance("RSASSA-PSS");
signature.setParameter(
    new PSSParameterSpec(
        "SHA-256",
        "MGF1",
        MGF1ParameterSpec.SHA256,
        32,
        1
    )
);
```

Never implement raw textbook RSA signing in production.

## 4.3 SHA-256

Compute SHA-256 over the exact bytes of the input document.

The hash is a fingerprint of the document and is not itself a proof of signer identity. The signature supplies the private-key binding.

## 4.4 Domain separation

The system will sign:

```text
LABEL || manifestBytes
```

where:

```text
LABEL = "ACNS-DSIG-v1" || 0x00
```

This makes it explicit that the signature belongs to this protocol and prevents the same signed bytes from being interpreted as another protocol message.

---

# 5. Key Management

## 5.1 Key generation

1. Generate RSA-3072 key pair.
2. Calculate the public-key fingerprint.
3. Save the private key in encrypted PKCS#8 form.
4. Save/export the public key in PEM SubjectPublicKeyInfo form.
5. Display the fingerprint to the signer.

## 5.2 Private key storage

Use:

- PKCS#8 `ENCRYPTED PRIVATE KEY`
- PBES2
- PBKDF2-HMAC-SHA256
- AES-256 encryption
- random salt
- strong iteration count

The private key must never be stored in plaintext in the database or source repository.

## 5.3 Fingerprint

Compute:

```text
fingerprint = SHA-256(DER SubjectPublicKeyInfo)
```

Display it grouped for readability, e.g.:

```text
AB12 34CD 56EF ...
```

## 5.4 Trust establishment

Bundling a public key with the document is not sufficient to prove who the signer is because an attacker could replace both the document and the public key.

Therefore:

1. Signer communicates the public-key fingerprint through a separate channel.
2. Verifier receives the public key.
3. Verifier calculates the fingerprint.
4. Verifier compares it with the independently communicated fingerprint.
5. Verifier explicitly pins the fingerprint in the trust store.
6. Later verification checks the package's key against the pinned fingerprint.

This is the project's simplified alternative to a CA-based PKI trust chain.

## 5.5 Key lifecycle

Support at least:

- Active
- Retired
- Revoked (advanced but recommended)

Old signatures may remain mathematically verifiable even after a key is retired. Trust status is evaluated separately.

---

# 6. Document and Signature Package Format

## 6.1 Detached envelope

Do not modify the original document.

Create:

```text
<document-name>.<extension>.dsig.json
```

Example:

```text
invoice.pdf
invoice.pdf.dsig.json
```

Optional later enhancement:

```text
invoice.dsig.zip
```

containing the original document and envelope.

## 6.2 Envelope structure

```json
{
  "format": "ACNS-DSIG",
  "version": 1,
  "manifest": "<Base64 manifest bytes>",
  "signature": "<Base64 RSA-PSS signature>",
  "publicKey": "<Base64 DER SubjectPublicKeyInfo>"
}
```

`publicKey` is informational and must not automatically make a signer trusted.

## 6.3 Signed manifest

```json
{
  "v": 1,
  "docName": "invoice.pdf",
  "docSize": 482913,
  "hashAlg": "SHA-256",
  "docHash": "<Base64 32-byte SHA-256 hash>",
  "sigAlg": "RSASSA-PSS-SHA256-MGF1SHA256-S32",
  "keyId": "<SHA-256 SPKI fingerprint>",
  "signedAt": "2026-10-08T12:30:00Z",
  "nonce": "<Base64 random bytes>",
  "signer": "Signer Name"
}
```

The exact manifest bytes are signed. The verifier verifies the signature over those exact bytes rather than reconstructing a semantically equivalent JSON object.

## 6.4 Why sign the manifest instead of only the raw document hash

The manifest binds the following together:

- document hash
- document size
- algorithm identifiers
- signing key identity
- signing time
- protocol version
- signer label
- nonce

This prevents important metadata from being altered independently of the signature.

---

# 7. Core Software Modules

## 7.1 `dsig-core`

Framework-free module containing all cryptographic and format logic.

### Core classes

| Class | Responsibility |
|---|---|
| `HashService` | Streaming SHA-256 |
| `SignatureService` | RSA-PSS sign/verify |
| `KeyService` | RSA key generation and fingerprinting |
| `KeyStorage` | Encrypted private/public key read/write |
| `Manifest` | Manifest model |
| `Envelope` | Envelope model |
| `EnvelopeCodec` | Strict encoding/decoding |
| `SigningService` | Sign orchestration |
| `VerificationService` | Verify orchestration |
| `TrustPolicy` | Trusted/untrusted/revoked decision |
| `DsigException` hierarchy | Safe error categories |

## 7.2 `dsig-cli`

Commands:

```text
keygen
sign
verify
fingerprint
trust add
trust list
```

## 7.3 `dsig-server`

Contains:

- authentication
- users/roles
- web controllers
- trust store
- verification history
- optional remote signing
- audit logging
- database access
- network security configuration

---

# 8. Signing Implementation

## 8.1 Exact signing workflow

```text
Select document
      ↓
Validate input and size
      ↓
Stream document through SHA-256
      ↓
Calculate document size
      ↓
Load signer private key
      ↓
Calculate key fingerprint
      ↓
Build manifest
      ↓
Serialize exact manifest bytes
      ↓
LABEL || manifestBytes
      ↓
RSA-PSS sign with private key
      ↓
Create detached envelope
      ↓
Save envelope atomically
      ↓
Record audit event
      ↓
Return signature package + fingerprint + hash
```

## 8.2 Streaming requirement

Do not load an entire large document into memory.

Use a buffer such as:

```text
64 KB
```

and calculate hash and byte count during the same stream.

## 8.3 Input handling

- Reject empty files.
- Enforce a configurable size limit.
- Never treat the MIME type as proof of file type.
- Do not execute uploaded files.
- Sanitize filename for display.
- Never use an uploaded filename as a filesystem path.
- Write outputs to temporary files first and then atomically move them into place.

## 8.4 Signing pseudocode

```text
sign(document):
    validate(document)
    (docHash, docSize) = streamSha256(document)

    privateKey = loadEncryptedPrivateKey(passphrase)
    publicKey  = derivePublicKey(privateKey)
    keyId      = fingerprint(publicKey)

    manifest = {
        version,
        documentName,
        documentSize,
        hashAlgorithm,
        documentHash,
        signatureAlgorithm,
        keyId,
        signedAtUtc,
        nonce,
        signerName
    }

    manifestBytes = exactUtf8Json(manifest)
    signedBytes = LABEL || manifestBytes
    signature = rsaPssSign(privateKey, signedBytes)

    envelope = {
        format,
        version,
        base64(manifestBytes),
        base64(signature),
        base64(publicKey)
    }

    return envelope
```

---

# 9. Verification Implementation

## 9.1 Exact verification workflow

```text
Receive document + envelope
          ↓
Validate package size/encoding
          ↓
Strictly parse envelope
          ↓
Decode manifest/signature/public key
          ↓
Validate version + algorithm allow-list
          ↓
Validate public key
          ↓
Check fingerprint matches manifest keyId
          ↓
Verify RSA-PSS signature over LABEL || exact manifest bytes
          ↓
Recompute SHA-256 of received document
          ↓
Compare recomputed hash with authenticated manifest hash
          ↓
Evaluate trust-store status
          ↓
Generate result
          ↓
Save verification record
          ↓
Display result
```

## 9.2 Verification order

The system must first authenticate the manifest before using its document hash to report tampering.

This is important because otherwise an attacker could modify both the document hash and the document.

## 9.3 Verification result states

### `VALID_TRUSTED`

- RSA-PSS signature valid.
- Document hash matches.
- Key fingerprint is trusted.
- No revocation condition applies.

### `VALID_UNTRUSTED_SIGNER`

- RSA-PSS signature valid.
- Document hash matches.
- The signing key is not in the verifier's trust store.

This must not be presented as an unconditional green "authentic signer" result.

### `DOCUMENT_TAMPERED`

- Manifest signature is valid.
- Recomputed document hash does not match the signed manifest hash.

### `INVALID_SIGNATURE`

Signature verification fails because the signature, manifest, key or their relationship is invalid.

### `INVALID_KEY`

The key is malformed, does not satisfy the required RSA constraints, or its fingerprint does not match the manifest.

### `UNSUPPORTED_FORMAT`

Unknown package version or unsupported cryptographic algorithm identifier.

### `MISSING_METADATA`

Required package or manifest data is absent.

### `CORRUPTED_PACKAGE`

The signature package cannot be safely parsed or decoded.

### `REVOKED_OR_RETIRED_KEY`

The cryptographic verification may succeed, but trust policy rejects the key because it is no longer trusted for the applicable signing period.

---

# 10. Trust Store

## 10.1 Data stored

```text
fingerprint
label
status
addedAt
revokedAt
notes
```

## 10.2 Trust workflow

```text
Import public key
      ↓
Calculate fingerprint
      ↓
Compare to independently received fingerprint
      ↓
User confirms
      ↓
Store fingerprint as TRUSTED
```

## 10.3 Important security rule

A package-supplied public key is never accepted as proof of identity by itself.

---

# 11. Database Design

The cryptographic core does not need a database. The server application uses H2 for persistent user, trust, verification and audit data.

## 11.1 Tables

### `users`

```text
id
username
password_hash
role
created_at
failed_logins
locked_until
```

### `key_pairs`

```text
key_id
owner_id
label
public_pem
key_file_path
status
created_at
```

### `trusted_signers`

```text
id
owner_id
fingerprint
label
status
added_at
revoked_at
note
```

### `verification_records`

```text
id
user_id
doc_name
doc_sha256
key_id
result_code
trust_status
signed_at
verified_at
nonce
```

### `audit_log`

```text
seq
timestamp
user_id
action
detail
prev_hash
entry_hash
```

## 11.2 Data that must not be stored

- Plaintext passwords.
- Private key bytes in database columns.
- Passphrases.
- Uploaded documents after verification unless a separate requirement explicitly needs document storage.
- Document contents inside logs.

## 11.3 Audit-chain calculation

```text
entry_hash = SHA-256(
    prev_hash || seq || timestamp || user_id || action || detail
)
```

Provide an administrator action that verifies the chain and reports the first broken link.

---

# 12. User Roles

## Signer

- Generate keys.
- View own keys.
- Sign documents.
- Export public key.
- View own signing/verification activity.

## Verifier

- Verify documents.
- View verification result.
- Manage trusted signer fingerprints.
- View verification history.

## Administrator

- Manage users/roles.
- View audit log.
- Verify audit-chain integrity.
- Perform administrative trust/key actions where permitted.

A user may have more than one role.

---

# 13. Backend Implementation

## 13.1 REST/web functions

Required server functions:

```text
POST /api/auth/register
POST /login
POST /api/keys
GET  /api/keys
GET  /api/keys/{id}/public
POST /api/sign
POST /api/verify
GET  /api/verifications
GET  /api/trust
POST /api/trust
POST /api/trust/{id}/revoke
GET  /api/audit/verify-chain
GET  /api/health
```

Exact endpoint naming may be simplified while implementation is underway, but the capabilities must remain.

## 13.2 Authentication

Use:

- form login
- BCrypt password hashing
- secure session cookie
- session invalidation on logout
- idle timeout
- login lockout/rate limiting

Do not introduce JWT/OAuth merely for this project.

## 13.3 Error handling

Expected verification failures should return structured result states rather than stack traces.

For unexpected errors:

```text
User sees: safe message + reference ID
Server log: detailed internal error + reference ID
```

Never return private keys, passphrases, filesystem paths or stack traces to clients.

---

# 14. Frontend Implementation

## 14.1 Screens

### Login/Register

- username
- password
- authentication result

### Dashboard

Cards/links for:

- Keys
- Sign
- Verify
- Trust Store
- History
- Audit (admin)

### Key Generation

- key label
- passphrase
- confirmation
- generation result
- public key/fingerprint display

### Sign Document

- select document
- select key
- enter signing passphrase
- sign
- show resulting hash and fingerprint
- download signature envelope

### Verify Document

- select document
- select `.dsig.json`
- verify button

### Verification Result

Show:

- status
- signer name
- key fingerprint
- trust status
- signed timestamp
- document name
- signed document hash
- recomputed hash
- explanation

For tampering, display signed hash and recomputed hash side by side.

### Trust Store

- trusted keys
- fingerprint
- status
- label
- add/pin action
- revoke/retire action where implemented

### Verification History

- file name
- signer
- result
- timestamp
- hash

---

# 15. UI Security Rules

- Green only for a fully trusted valid result.
- Amber for cryptographically valid but untrusted signer.
- Red for failed verification.
- Text explanation must accompany colours; colour cannot be the only signal.
- Never reveal sensitive backend details.
- Never render or execute uploaded documents in the UI.

---

# 16. Network Security

This project is an ACNS-DC project, so network security must be demonstrated rather than treating the web layer as ordinary CRUD.

## 16.1 TLS

Configure HTTPS with TLS 1.3.

Demonstrate that application traffic is encrypted in transit.

## 16.2 HTTP hardening

Use:

- HSTS
- Content-Security-Policy
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- strict referrer policy

## 16.3 CSRF

Enable CSRF protection on all state-changing browser requests.

## 16.4 Session security

Use:

- HttpOnly
- Secure
- SameSite=Strict
- session ID rotation at login
- logout invalidation

## 16.5 Rate limiting

At minimum protect:

- login
- sign
- verify

## 16.6 Upload security

Enforce:

- file-size caps
- temporary storage
- randomized server-side filenames
- cleanup in `finally`
- no execution
- safe ZIP handling if the optional bundle is implemented

## 16.7 CORS

Do not enable CORS unless a genuine cross-origin requirement appears.

---

# 17. Threat Model

| Threat | Required response |
|---|---|
| Document modified | Signed digest detects it |
| Signature modified | RSA-PSS verification fails |
| Manifest modified | RSA-PSS verification fails |
| Public-key substitution | Trust-store fingerprint pinning prevents false identity claim |
| Private-key theft | Encrypted private key + passphrase + revocation process |
| MITM on web app | TLS 1.3 |
| Malicious upload | Limits + safe handling |
| Replay of old valid document | Signed timestamp/nonce + warning; cannot be fully prevented without an external freshness mechanism |
| Brute-force login | Rate limiting + lockout |
| IDOR / unauthorized key access | Authentication + role + ownership checks |
| Audit manipulation | Hash-chained audit log |
| Algorithm confusion | Fixed algorithm configuration + allow-list |

## 17.1 Honest limitations

The project does **not** provide:

- Real-world identity proofing by a CA.
- A trusted timestamp authority.
- Confidentiality of the document from everyone except the receiver.
- Absolute non-repudiation independent of key compromise.
- Complete replay prevention.

The trust model depends on correctly establishing the signer's public-key fingerprint through an independent channel.

---

# 18. Testing Strategy

Testing is a first-class implementation phase rather than a final-day activity.

## 18.1 Unit tests

Test:

- SHA-256 known-answer vectors.
- RSA key generation.
- RSA-3072 enforcement.
- RSA-PSS sign/verify.
- Fingerprint stability.
- Encrypted PKCS#8 save/load.
- Wrong passphrase failure.
- Envelope encode/decode.
- Strict parser behavior.
- Constant-time hash comparison.

## 18.2 Integration tests

Test:

1. Sign → copy package → verify.
2. CLI sign → web verify.
3. Web sign → CLI verify.
4. Document tampering.
5. Signature tampering.
6. Manifest tampering.
7. Wrong public key.
8. Public-key substitution.
9. Trust-store acceptance/rejection.

## 18.3 Negative/security tests

At minimum:

| ID | Scenario | Expected result |
|---|---|---|
| T01 | Original document + valid envelope + trusted key | VALID_TRUSTED |
| T02 | One byte changed in document | DOCUMENT_TAMPERED |
| T03 | Signature altered | INVALID_SIGNATURE |
| T04 | Manifest altered | INVALID_SIGNATURE |
| T05 | Attacker creates package with own key | VALID_UNTRUSTED_SIGNER |
| T06 | Key ID/key mismatch | INVALID_KEY |
| T07 | Wrong verification key | INVALID_SIGNATURE / INVALID_KEY |
| T08 | Weak RSA key | INVALID_KEY |
| T09 | Unsupported algorithm | UNSUPPORTED_FORMAT |
| T10 | Missing manifest | MISSING_METADATA |
| T11 | Malformed JSON | CORRUPTED_PACKAGE |
| T12 | Empty file | rejected by signing |
| T13 | Wrong private-key passphrase | generic key error |
| T14 | Revoked/retired key | trust failure state |
| T15 | Envelope used with another document | DOCUMENT_TAMPERED |
| T16 | Malicious ZIP path traversal | rejected |
| T17 | Repeated login failures | rate limited / locked |
| T18 | Missing CSRF token | rejected |
| T19 | User requests another user's key | 403/404 |
| T20 | Edited audit row | chain verification reports break |

## 18.4 Fuzz testing

Mutate malformed envelopes and ensure the verifier:

- never crashes
- never exposes stack traces
- never returns a VALID state for hostile input

## 18.5 Performance testing

Measure at least:

- 1 KB
- 1 MB
- 25 MB
- larger CLI test file

Measure:

- hash time
- sign time
- verification time
- memory behavior

The core implementation must use streaming and constant-memory processing with respect to document size.

---

# 19. Performance Design

The document is never passed directly to RSA.

```text
document
   ↓
SHA-256
   ↓
32-byte digest inside signed manifest
   ↓
RSA-PSS
```

This keeps RSA operations independent of document size.

Use separate `Signature` and `MessageDigest` instances for concurrent requests because these Java cryptographic objects should not be shared unsafely between threads.

Web upload size can be lower than CLI size for safety.

---

# 20. Development Order

## Phase A — Requirements and scope freeze

- Confirm problem statement.
- Confirm core features.
- Confirm exclusions.
- Confirm crypto parameters.
- Confirm trust model.

**Output:** frozen implementation specification.

## Phase B — Repository and project skeleton

- Create Maven parent project.
- Create `dsig-core`.
- Create `dsig-cli`.
- Create `dsig-server`.
- Configure JUnit and CI.

**Output:** clean build with tests running.

## Phase C — Cryptographic core

Implement:

1. `HashService`
2. `SignatureService`
3. `KeyService`
4. basic sign/verify flow

Build the first CLI prototype.

**Milestone:** working sign + verify without web UI.

## Phase D — Key management

Implement:

- encrypted PKCS#8
- public PEM
- fingerprints
- key loading
- trust store

**Milestone:** wrong-passphrase and trust tests pass.

## Phase E — Package format and verification states

Implement:

- manifest
- envelope
- codec
- strict parsing
- exact-byte signing
- verification result states

**Milestone:** all major positive and negative cryptographic cases pass.

## Phase F — Backend and persistence

Implement:

- Spring Boot server
- H2 database
- users
- key metadata
- trust store
- verification history
- audit chain

**Milestone:** server can authenticate and verify packages.

## Phase G — Frontend

Implement:

- Login/Register
- Dashboard
- Key generation
- Sign
- Verify
- Result
- Trust Store
- History
- Admin Audit

**Milestone:** complete usable workflow.

## Phase H — Network and application security

Implement:

- TLS 1.3
- secure headers
- sessions
- CSRF
- rate limiting
- upload hardening
- authorization/ownership checks

**Milestone:** hardened server.

## Phase I — Full testing

Execute:

- unit tests
- integration tests
- security tests
- negative tests
- fuzz tests
- performance tests

**Milestone:** no VALID state for any tampered test case.

## Phase J — Final documentation and demo

Produce:

- architecture diagrams
- data flow diagram
- sequence diagrams
- class diagram
- ER diagram
- threat model
- screenshots
- test results
- benchmark results

**Milestone:** reproducible, demo-ready build.

---

# 21. Recommended 8-Week Schedule

| Period | Main work | Required milestone |
|---|---|---|
| Days 1–3 | Requirements + architecture | Scope and design frozen |
| Days 4–7 | Repository + module skeleton | Build/CI works |
| Week 2 | Crypto core | CLI sign/verify works |
| Week 3 | Key management + package format | Trust and envelope work |
| Week 4 | Backend + database | Server verification works |
| Week 5 | Frontend | Full UI workflow works |
| Week 6 | TLS + security hardening | Security controls active |
| Week 7 | Full testing + performance | Test matrix completed |
| Week 8 | Report + diagrams + demo | Final submission and rehearsal |

The schedule is a planning template and can be compressed or stretched to match the semester.

---

# 22. Final Repository Structure

```text
acns-dsig/
├── pom.xml
├── dsig-core/
│   ├── src/main/java/.../crypto
│   ├── src/main/java/.../keys
│   ├── src/main/java/.../format
│   ├── src/main/java/.../sign
│   ├── src/main/java/.../verify
│   ├── src/main/java/.../trust
│   └── src/test/java/...
├── dsig-cli/
│   └── src/main/java/.../cli
├── dsig-server/
│   ├── src/main/java/.../web
│   ├── src/main/java/.../service
│   ├── src/main/java/.../security
│   ├── src/main/java/.../persistence
│   └── src/main/resources/
│       ├── templates/
│       ├── static/
│       └── application.yml
├── docs/
│   ├── FORMAT.md
│   ├── THREAT_MODEL.md
│   ├── diagrams/
│   ├── benchmark/
│   └── report/
├── scripts/
├── test-data/
├── .github/workflows/ci.yml
├── .gitignore
└── README.md
```

Runtime data must be outside source-controlled code and ignored by Git.

---

# 23. Required Diagrams

1. **Overall system architecture** — browser, CLI, server, core, DB, key files and TLS boundary.
2. **Level-1 DFD** — signer, verifier, sign, verify, trust store, database.
3. **Corrected sender flowchart** — hash → manifest → sign manifest → envelope.
4. **Corrected receiver flowchart** — parse → verify manifest signature → recompute hash → compare → trust decision.
5. **Combined end-to-end workflow** matching the original proposal diagram.
6. **Use-case diagram** — Signer, Verifier, Administrator.
7. **Sequence diagram: signing**.
8. **Sequence diagram: verification**.
9. **Class diagram** — core services and server services.
10. **ER diagram** — users, key pairs, trusted signers, verification records, audit log.
11. **Threat model / trust-boundary diagram**.

---

# 24. Final Demonstration Plan

Use two logical users:

- **Alice** — legitimate signer / trusted key.
- **Mallory** — attacker / untrusted signer.

## Demo 1 — Valid document

Alice signs a document and the verifier has Alice's fingerprint pinned.

Expected:

```text
VALID_TRUSTED
```

## Demo 2 — Document tampering

Change one byte/character after signing.

Expected:

```text
DOCUMENT_TAMPERED
```

Show both hashes.

## Demo 3 — Signature tampering

Alter the signature.

Expected:

```text
INVALID_SIGNATURE
```

## Demo 4 — Wrong public key

Attempt verification with another key.

Expected:

```text
INVALID_SIGNATURE / INVALID_KEY
```

## Demo 5 — Public-key substitution

Mallory replaces document + signature + bundled public key.

Cryptographic verification may succeed for Mallory's key, but the key is not trusted.

Expected:

```text
VALID_UNTRUSTED_SIGNER
```

This is the strongest demonstration of why public-key trust matters.

## Demo 6 — Network security

Show that the web session uses TLS 1.3.

Demonstrate that cryptographic document integrity and transport confidentiality are separate protections.

## Demo 7 — Audit tampering

Modify an audit record and verify the audit chain.

Expected:

```text
first broken audit-chain link identified
```

---

# 25. MVP Definition of Done

The project is considered complete only when all of these are true:

- RSA-3072 key pair generation works.
- Private keys are encrypted at rest.
- SHA-256 document hashing works.
- RSA-PSS signing and verification work.
- Signed manifest and detached envelope work.
- Key fingerprints work.
- Trust-store verification works.
- Valid and tampered documents are distinguished.
- Modified signatures are rejected.
- Wrong/unknown signers are distinguished.
- Verification history is recorded.
- Web authentication and authorization work.
- TLS 1.3 is enabled.
- Uploads are safely handled.
- Audit log is hash chained.
- All core negative tests pass.
- No test case allows tampered content to return a trusted valid state.
- Final demo works from a clean setup.

---

# 26. Optional Enhancement Order

Only after the MVP is complete:

1. RSA + SHA-512 comparison.
2. RSA-2048 vs RSA-3072 benchmark.
3. Ed25519 benchmark.
4. QR fingerprint exchange.
5. ZIP bundle.
6. Revocation UI.
7. mTLS.
8. TOTP/WebAuthn.
9. Trusted timestamping (RFC 3161) as future work.
10. X.509/CA/PKI as future work.

---

# 27. What Was Improved During the Merge

## Kept from the original implementation plan

- Simple sender → transmission → receiver workflow.
- RSA key generation.
- SHA-256 hashing.
- Document + signature + public key package.
- Verification and hash comparison.
- Valid/invalid result concept.
- Reporting and verification history.
- Tamper visualization.
- The proposal's basic development order.

## Added from the detailed security blueprint

- RSA-PSS instead of textbook RSA signing.
- RSA-3072 fixed configuration.
- Signed manifest rather than a bare hash.
- Domain separation.
- Key fingerprinting and explicit trust store.
- Distinction between cryptographic validity and signer trust.
- Encrypted private-key storage.
- Strict package parsing.
- Algorithm allow-list.
- Streaming hashing.
- Precise verification states.
- TLS 1.3.
- CSRF, secure sessions and rate limiting.
- Safe upload handling.
- Hash-chained audit log.
- Formal threat model.
- Negative/security/fuzz/performance testing.
- Structured development milestones.

## Deliberately not carried forward

- PostgreSQL.
- React/Next.js.
- Full X.509/CA infrastructure.
- Blockchain.
- Microservices.
- Custom RSA implementation.
- AI/ML.
- Large enterprise infrastructure.

These additions/removals keep the project technically defensible without turning it into an enterprise PKI product.

---

# 28. Final End-to-End Workflow

```text
                         SIGNER
                           │
                    Generate RSA key pair
                           │
                 Protect private key locally
                           │
                      Select document
                           │
                    SHA-256(document)
                           │
                     Build manifest
                           │
             LABEL || manifest bytes
                           │
                 RSA-PSS(private key)
                           │
                    Detached envelope
                           │
          Document + envelope + public key
                           │
                EMAIL / CLOUD / USB / HTTPS
                           │
                           ▼
                        RECEIVER
                           │
                 Parse/validate envelope
                           │
                 Verify key fingerprint
                           │
               Verify RSA-PSS signature
                           │
             Recompute SHA-256(document)
                           │
                  Compare document hash
                           │
                  Check trust-store state
                           │
          ┌───────────────┼────────────────┐
          │               │                │
       VALID          TAMPERED         UNTRUSTED
       TRUSTED        DOCUMENT         SIGNER
          │               │                │
          └───────────────┼────────────────┘
                           │
                  Reporting + History
                           │
                     Audit Logging
```

---

# 29. Final Project Principle

The system should remain simple at its visible level:

```text
SIGN → SEND → VERIFY
```

but the implementation underneath that simple workflow must correctly handle:

```text
HASHING
+ DIGITAL SIGNATURE
+ KEY MANAGEMENT
+ TRUST
+ NETWORK SECURITY
+ TAMPER DETECTION
+ AUDITABILITY
+ TESTING
```

That combination is the final recommended implementation scope.
