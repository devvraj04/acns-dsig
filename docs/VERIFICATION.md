# Verification Engine & Result Model Specification (`docs/VERIFICATION.md`)

**Author:** Deven Thakkar (Member 1)  
**Work Package:** Verification Engine & Result Model  
**Module:** `dsig-core` (Plain Java, zero framework dependencies)  
**Status:** Orchestration Core & Decision Tree Implemented and Testable  

---

## 1. Executive Summary & Design Objective

In the ACNS-DSIG architecture, the **Verification Engine** (`com.acns.dsig.core.verify.VerificationService`) serves as the central security orchestrator for digital document authentication.

Digital document verification is frequently implemented naively as a binary "Valid" or "Invalid" boolean flag. In real-world security engineering, a binary outcome is dangerously insufficient:
- A document may possess a cryptographically valid RSA signature, yet be signed by an unknown or compromised party (Public-Key Substitution Attack).
- A signature envelope may be mathematically authentic, but the received document payload may have been modified in transit (Document Tampering).
- An attacker may forge both document bytes and an unauthenticated manifest digest (Manifest Substitution).

The **Verification Engine** addresses these risks by enforcing:
1. **Strict 10-Step Verification Ordering:** Manifest digital signatures are authenticated **before** document hashes are inspected.
2. **Tripartite Separation of Concerns:** Rigidly separates **Cryptographic Signature Validity**, **Document Integrity**, and **Signer Trust**.
3. **Authoritative 9-State Result Model:** Maps every verification outcome to an explicit, unambiguous state with explanatory context rather than throwing raw cryptographic or parser exceptions.
4. **Decoupled Architecture:** Introduces minimal verification-owned contracts (`PackageDecoder`, `ManifestSignatureVerifier`, `PublicKeyValidator`) to allow independent testing while isolating unfinished team dependencies.

---

## 2. The Tripartite Verification Model

The verification engine establishes three distinct, independent security boundaries:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                      VERIFICATION ENGINE MODEL                         │
├──────────────────────────┬──────────────────────────┬──────────────────┤
│   1. Signature Validity  │   2. Document Integrity  │  3. Signer Trust │
│   (RSASSA-PSS / JCA)     │   (Streaming SHA-256)    │  (Trust Store)   │
├──────────────────────────┼──────────────────────────┼──────────────────┤
│ Proves knowledge of the  │ Proves document bytes    │ Evaluates who    │
│ private key matching the │ have not altered by even │ owns the key and │
│ public key in envelope.  │ a single bit in transit. │ whether pinned.  │
└──────────────────────────┴──────────────────────────┴──────────────────┘
```

A verification outcome of **`VALID_TRUSTED`** strictly requires all three pillars to succeed:
$$\text{VALID\_TRUSTED} \iff \text{Valid Signature} \land \text{Document Intact} \land \text{Signer Key Trusted}$$

If signature and document integrity succeed, but the signer is not pinned, the system returns **`VALID_UNTRUSTED_SIGNER`** (amber warning), preventing false trust in unknown keys.

---

## 3. Security-Critical Ordering: Manifest Authentication First

### The Threat
In detached signature packages, the manifest contains the expected document digest (`docHash`) and size (`docSize`). If a verification engine recalculates the document hash and compares it against `docHash` **before** verifying the manifest signature, an attacker who intercepts the transmission could:
1. Alter the document payload.
2. Alter `docHash` inside the manifest to match the tampered document.
3. Submit the unauthenticated manifest to the verifier.

If the engine relied on `docHash` prior to signature verification, it might conclude the document is intact, or misattribute errors.

### The Enforcement
`VerificationService` strictly validates the RSA-PSS signature over `ACNS-DSIG-v1\0 || exactManifestBytes` **before** streaming or reading the received document bytes.
- If the signature verification fails, the process terminates with **`INVALID_SIGNATURE`**.
- The received document stream is never trusted against an unauthenticated digest, and `recomputedDocHash` remains `null`.

---

## 4. Authoritative 10-Step Verification Workflow

```text
Receive document InputStream + envelope JSON
               │
               ▼
[Step 1] Strict Envelope Decoding & Format Bounds Check
         ├── Corrupted JSON / Bad Base64 / Oversized payload → CORRUPTED_PACKAGE
         └── Missing envelope fields → MISSING_METADATA
               │
               ▼
[Step 2] Protocol & Version Validation
         └── format != "ACNS-DSIG" or version != 1 → UNSUPPORTED_FORMAT
               │
               ▼
[Step 3] Manifest Metadata & Algorithm Allow-List Check
         ├── Null docHash, keyId, docName, signedAt, nonce, or size <= 0 → MISSING_METADATA
         └── hashAlg != SHA-256 or sigAlg != RSASSA-PSS... → UNSUPPORTED_FORMAT
               │
               ▼
[Step 4] Public Key Validation & Fingerprint Binding
         ├── Modulus < 3072 bits or invalid encoding → INVALID_KEY
         └── calculateFingerprint(pubKey) != manifest.keyId → INVALID_KEY
               │
               ▼
[Step 5] Manifest Authentication (RSASSA-PSS over LABEL || exactManifestBytes)
         └── Signature invalid → INVALID_SIGNATURE (Document stream NOT trusted)
               │
               ▼
[Step 6] Document Streaming SHA-256 Recalculation (via Devraj's HashService)
         ├── Empty document (0 bytes) while manifest docSize > 0 → DOCUMENT_TAMPERED
         └── Underlying I/O read failure → DocumentReadException (propagated)
               │
               ▼
[Step 7] Digest & Size Constant-Time Comparison
         └── ConstantTime.equals(recomputed, expected) == false OR size != docSize
             └── Mismatch → DOCUMENT_TAMPERED (Displays both digests)
               │
               ▼
[Step 8] Signer Trust Evaluation (via TrustPolicy)
         ├── Key status == TRUSTED → VALID_TRUSTED
         ├── Key status == REVOKED or RETIRED (strict) → REVOKED_OR_RETIRED_KEY
         └── Key status == UNTRUSTED or UNKNOWN → VALID_UNTRUSTED_SIGNER
               │
               ▼
[Step 9] Result Object Construction (VerificationResult)
               │
               ▼
[Step 10] Return Immutable Result to Caller (CLI / Server)
```

---

## 5. Result State Definitions & Decision Matrix

| Result Code | Trigger Condition | Trust Status | User-Facing Action |
|---|---|---|---|
| `VALID_TRUSTED` | Signature valid, document digest & size match, signer fingerprint pinned as `TRUSTED`. | `TRUSTED` | Green indicator: Full authenticity and integrity confirmed. |
| `VALID_UNTRUSTED_SIGNER` | Signature valid and document intact, but signer fingerprint is unpinned or marked `UNTRUSTED`. | `UNKNOWN` / `UNTRUSTED` | Amber warning: Document unaltered, but signer identity unverified. |
| `DOCUMENT_TAMPERED` | Manifest signature valid, but received document hash or byte count differs from manifest. | `UNKNOWN` / Lookup status | Red alert: Document was modified or corrupted in transit. |
| `INVALID_SIGNATURE` | Cryptographic RSASSA-PSS signature verification fails over manifest bytes. | `UNKNOWN` | Red alert: Signature forged, corrupted, or does not match key. |
| `INVALID_KEY` | Public key encoding invalid, modulus < 3072 bits, or fingerprint does not match manifest `keyId`. | `UNKNOWN` | Security rejection: Signer key violates security constraints. |
| `UNSUPPORTED_FORMAT` | Protocol format != `ACNS-DSIG`, version != 1, or unapproved signature/hash algorithms. | `UNKNOWN` | Operational failure: Incompatible version or algorithm. |
| `MISSING_METADATA` | Mandatory envelope or manifest fields are null, blank, or non-positive size. | `UNKNOWN` | Format error: Incomplete signature package. |
| `CORRUPTED_PACKAGE` | JSON parsing error, duplicate keys, invalid Base64, or payload exceeds security limits. | `UNKNOWN` | Format error: Envelope corrupted or unparseable. |
| `REVOKED_OR_RETIRED_KEY` | Signature and document valid, but key has been revoked or expired according to policy. | `REVOKED` / `RETIRED` | Security rejection: Key is no longer valid for verification. |

---

## 6. Consumption of Completed Work: Devraj Sundrani's `HashService`

`VerificationService` directly consumes Devraj Sundrani's completed work package:
- **`com.acns.dsig.core.crypto.HashService`**: Invokes `hashStream(InputStream)` to stream received document bytes with a constant 64 KB buffer footprint, calculating digest and size simultaneously.
- **`com.acns.dsig.core.crypto.ConstantTime`**: Used to perform side-channel resistant comparisons:
  - `ConstantTime.equals(recomputedRawDigest, expectedRawDigest)`
  - `ConstantTime.equals(derivedFingerprint, manifestKeyId)`
- **`com.acns.dsig.core.error.EmptyDocumentException`**: Caught when a received document is 0 bytes. If the authenticated manifest declares non-zero size, it is mapped to `DOCUMENT_TAMPERED` (truncation detection).
- **`com.acns.dsig.core.error.DocumentReadException`**: Operational stream read errors are propagated directly rather than mislabeled as envelope corruption or document tampering.

---

## 7. Verification-Owned Contracts for Pending Dependencies

To make `VerificationService` independently testable without waiting for or implementing other members' code, minimal verification-owned contracts were defined in package `com.acns.dsig.core.verify`:

### 7.1 `VerificationPackage` (Record)
An immutable value representation of the received package holding:
- Envelope metadata (`format`, `version`, `encodedPublicKey`)
- Exact signed manifest bytes (`exactManifestBytes` cloned defensively)
- Raw signature bytes (`signatureBytes` cloned defensively)
- Decoded manifest fields (`documentName`, `declaredDocumentSize`, `hashAlgorithm`, `declaredDocumentHash`, `signatureAlgorithm`, `keyId`, `signedAt`, `nonce`, `signerLabel`)

### 7.2 `PackageDecoder` (Interface)
```java
public interface PackageDecoder {
    VerificationPackage decode(String packagePayload) throws CorruptedPackageException;
}
```
Isolates Parth Zala's pending `EnvelopeCodec`. Guarantees that exact manifest bytes are retained.

### 7.3 `ManifestSignatureVerifier` (Functional Interface)
```java
@FunctionalInterface
public interface ManifestSignatureVerifier {
    boolean verifyManifestSignature(PublicKey publicKey, byte[] exactManifestBytes, byte[] signatureBytes);
}
```
Isolates Tanmay Vishwakarma's pending `SignatureService`. In unit tests, allows simulating valid and invalid cryptographic signatures without invoking JCA RSA key generation.

### 7.4 `PublicKeyValidator` (Interface)
```java
public interface PublicKeyValidator {
    PublicKey parsePublicKey(String encodedPublicKey) throws KeyValidationException;
    void validatePublicKey(PublicKey publicKey) throws KeyValidationException;
    String calculateFingerprint(PublicKey publicKey);
}
```
Isolates Atharv Vedant's pending `KeyService`, `KeyStorage`, and `Fingerprint` implementations.

### 7.5 Backward-Compatible Adapter Constructor
To ensure existing CLI (`VerifyCommand`), Server (`VerificationAppService`), and test harnesses continue working seamlessly, `VerificationService` provides a secondary adapter constructor that wraps existing draft classes (`EnvelopeCodec`, `SignatureService`) using `DefaultPackageDecoder`.

---

## 8. Unit Testing & Verification Evidence

The test suite in [`VerificationServiceTest.java`](file:///c:/Users/USER/acns-dsig/dsig-core/src/test/java/com/acns/dsig/core/verify/VerificationServiceTest.java) provides comprehensive coverage of the decision tree:

1. **Happy Path:** `VALID_TRUSTED` verified with mocked trust store pinning.
2. **Untrusted Signer:** `VALID_UNTRUSTED_SIGNER` verified with empty trust lookup.
3. **Revocation & Retirement:** Tested under default strict rejection policy as well as explicit administrative override.
4. **Tampering Detection:** Validates bit modification, declared-size mismatch, and empty received file truncation.
5. **Signature Failures:** Validates invalid signature bytes and altered manifest bytes.
6. **Verification Ordering:** Proves document stream is never read if manifest signature verification fails.
7. **Key Constraints:** Validates RSA modulus < 3072 rejection, malformed PEM, and fingerprint mismatch against `keyId`.
8. **Format & Algorithm Checks:** Rejects unauthorized protocol versions, hash algorithms (`SHA-512`), and signature algorithms.
9. **Corrupted Package:** Validates duplicate keys, bad Base64, and malformed JSON payloads.
10. **I/O Error Preservation:** Ensures `DocumentReadException` propagates without mislabeling.

---

## 9. Current Status & Integration Blockers

| Component | Responsible Member | Status | Verification Engine Dependency Status |
|---|---|---|---|
| **Verification Engine** | Deven Thakkar | **COMPLETE** | Ready for integration. |
| **Document Hashing** | Devraj Sundrani | **COMPLETE** | Integrated and consumed directly via `HashService`. |
| **RSA-PSS Signature Engine** | Tanmay Vishwakarma | Pending | Isolated via `ManifestSignatureVerifier`. |
| **Key Management & Storage** | Atharv Vedant | Pending | Isolated via `PublicKeyValidator`. |
| **Manifest & Envelope Codec**| Parth Zala | Pending | Isolated via `PackageDecoder`. |
| **Database & Persistence** | Nityanand Upadhyay | Pending | Decoupled via `TrustLookup` interface. |
| **Build & CI/CD** | Simrit Kaur | **CONFIGURED** | Parent and module POMs (`pom.xml`, `dsig-core`, `dsig-cli`, `dsig-server`) configured and verified with `mvn clean test`. |

The Verification Engine is fully isolated, modular, adheres strictly to ACNS security standards, and is ready for production integration upon completion of peer modules.
