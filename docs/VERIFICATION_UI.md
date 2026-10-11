# Technical Documentation: Verification Web Interface & Trust UI

**Member 8 — Jay Pandya**  
**Work Package:** Verification Web Interface & Trust UI  
**Module:** `dsig-server`  
**Dependencies:** `dsig-core` (Members 1, 2, 3, 5), Persistence & Auth (Member 6 — Nityanand Upadhyay), Network & App Security (Member 9 — Diyaan Rambhia)  
**Review Partner:** Member 7 — KVS Varshith (Signing Web Interface & Sign Flow)

---

## 1. Overview & Architecture

The **Verification Web Interface & Trust UI** is the primary receiver-side interface of the ACNS-DSIG system. It enables authenticated verifiers to independently substantiate:
1. **Document Integrity:** Guaranteeing via streaming SHA-256 recalculation that the received document has not been altered in transit.
2. **Cryptographic Origin Authentication:** Verifying the mathematical validity of the RSASSA-PSS digital signature over the canonical manifest bytes.
3. **Signer Trust Evaluation:** Evaluating the signer's SubjectPublicKeyInfo (SPKI) SHA-256 fingerprint against the verifier's locally pinned Trust Store.
4. **Tamper Visualization:** Providing an interactive side-by-side visual diff of authentic signed digests versus recomputed file digests whenever tampering is detected.
5. **Trust Store Management & Quick-Pin:** Enabling users to pin, inspect, search, and revoke trusted signer fingerprints.
6. **Immutable Audit History:** Maintaining an indexed chronological record of all verification events.

```
+-----------------------------------------------------------------------------------+
|                                 Verifier Browser                                  |
|                                                                                   |
|  [verify.html / verify.js]                   [result.html / result.js]            |
|  - Drag & drop doc (<50MB) + envelope (<512KB)- All 9 ResultCode state banners    |
|  - Instant client size & extension guards   - Side-by-side SHA-256 tamper diff    |
|  - Loading spinner to prevent double-post   - Quick-pin CTA for untrusted signers |
|                                             - 1-click clipboard copy helpers      |
|  [trust.html / trust.js]                     [history.html / history.js]          |
|  - Live 64-hex char cleaner & counter       - Summary metric badges (Total/Pass)  |
|  - Table search filter & revoke confirm     - Instant status filter pills & search|
+-----------------------------------------------------------------------------------+
                                   | HTTPS / TLS 1.3 (Diyaan Rambhia)
                                   v
+-----------------------------------------------------------------------------------+
|                        dsig-server Controllers & Services                         |
|                                                                                   |
|  [VerifyController]          [TrustController]          [HistoryController]       |
|  - Enforces CSRF token       - Validates 64-char hex FP - Enforces user isolation|
|  - UploadGuard size check    - Anti-IDOR ownership      - Aggregates stats        |
|  - Isolated temp doc cleanup - Handles prefill params   - Chronological sort      |
|         |                            |                         |                  |
|         v                            v                         v                  |
|  [VerificationAppService]    [TrustStoreService]        [HistoryService]          |
|  - Invokes VerificationService- Persists TrustedSigner  - Queries Verification-   |
|  - Evaluates TrustPolicy     - Implements TrustLookup     Record table (Nityanand)|
|  - Logs AuditChain event     - H2 DB persistence        - Zero document retention |
+-----------------------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------------------+
|                           dsig-core Verification Engine                           |
|                                                                                   |
|  [VerificationService] (Deven) -> [HashService] (Devraj) -> [SignatureService]   |
|  - Manifest validation & EnvelopeCodec (Parth)             (Tanmay RSA-PSS)       |
+-----------------------------------------------------------------------------------+
```

---

## 2. Core Functional Specifications

### 2.1 Verification Screen (`/verify`)
- **Routes:** `GET /verify`, `POST /verify`
- **Controller:** `com.acns.dsig.server.web.VerifyController`
- **Template:** `templates/verify.html`
- **Client Script:** `static/js/verify.js`
- **Key Capabilities:**
  - **Drag-and-Drop Zones:** Independent, accessible dropzones for the document file and `.dsig.json` signature envelope.
  - **Client-Side File Validation:** Rejects files exceeding size caps (<50 MB for documents, <512 KB for envelopes) and warns on improper envelope file extensions before transmission.
  - **Selected File Previews:** Shows live file name, formatted byte size, and an interactive "Change" button.
  - **Safe Temporary Storage:** Documents are streamed to an isolated temporary file using `UploadGuard.saveToIsolatedTempFile()` and cleaned up in a `finally` block via `UploadGuard.cleanupTempFile()`.
  - **Zero Leakage:** Server exceptions are caught, logged internally with reference IDs, and returned as safe user-facing error messages.

### 2.2 Verification Result Screen (`result.html`)
- **Controller:** `com.acns.dsig.server.web.VerifyController` (returns `result.html` upon successful processing)
- **Template:** `templates/result.html`
- **Client Script:** `static/js/result.js`
- **State Display Matrix:**

| Result Code | Badge Style | Primary Visual Signal | Semantic Explanation |
|---|---|---|---|
| `VALID_TRUSTED` | Green (`badge-success`) | Checkmark Shield | Signature valid, document intact, signer fingerprint pinned and trusted. |
| `VALID_UNTRUSTED_SIGNER` | Amber (`badge-warning`) | Warning Triangle | Signature valid and document intact, but signer fingerprint is NOT in local Trust Store. Displays quick-pin CTA. |
| `DOCUMENT_TAMPERED` | Red (`badge-danger`) | Danger Cross | Manifest signature valid, but document hash mismatch. Activates side-by-side tamper diff visualization. |
| `INVALID_SIGNATURE` | Red (`badge-danger`) | Danger Cross | Mathematical RSASSA-PSS verification failed against manifest payload. |
| `INVALID_KEY` | Red (`badge-danger`) | Key Warning | Malformed key, modulus below 3072 bits, or key ID mismatch. |
| `UNSUPPORTED_FORMAT` | Red (`badge-danger`) | Format Error | Unrecognized envelope version or cryptographic algorithm. |
| `MISSING_METADATA` | Red (`badge-danger`) | Metadata Warning | Essential envelope or manifest attributes missing. |
| `CORRUPTED_PACKAGE` | Red (`badge-danger`) | Package Warning | Malformed JSON, duplicate keys, or invalid Base64 encoding. |
| `REVOKED_OR_RETIRED_KEY`| Red (`badge-danger`) | Revocation Warning | Signature valid, but signing key is explicitly marked revoked or retired. |

### 2.3 Side-by-Side Tamper Diff Visualization
When `resultCode == DOCUMENT_TAMPERED`:
- The Authentic Signed Digest from the manifest and the Recomputed Document Digest from streaming SHA-256 are rendered side by side in monospace hex blocks.
- `result.js` analyzes both 64-character hex strings nibble-by-nibble:
  - Matching characters are rendered in muted text (`.hash-char-match`).
  - Mismatching characters are highlighted in bold red with wavy underline (`.hash-char-diff`).
- An interactive summary calculates the exact number of altered hexadecimal nibbles detected.

### 2.4 Signer Trust Store Screen (`/trust`)
- **Routes:** `GET /trust`, `POST /trust/pin`, `POST /trust/revoke/{id}`
- **Controller:** `com.acns.dsig.server.web.TrustController`
- **Template:** `templates/trust.html`
- **Client Script:** `static/js/trust.js`
- **Key Capabilities:**
  - **Quick-Pin Prefill:** Accepts optional query parameters `?fingerprint=...&label=...` (linked directly from `result.html` during untrusted verifications).
  - **Real-Time Input Cleaner & Counter:** Strips whitespace, colons, or dashes; dynamically displays `x/64 hex characters` counter.
  - **Table Directory & Instant Search:** Live client search filtering pinned signers by label, fingerprint, or notes.
  - **Revocation Protection:** Requires explicit user confirmation dialog before revoking trust.
  - **Anti-IDOR Security:** Enforces that users can only revoke signers belonging to their own `owner_id`.

### 2.5 Verification History Screen (`/history`)
- **Routes:** `GET /history`
- **Controller:** `com.acns.dsig.server.web.HistoryController`
- **Template:** `templates/history.html`
- **Client Script:** `static/js/history.js`
- **Key Capabilities:**
  - **Summary Metrics Grid:** Aggregates and displays Total Verifications, Valid & Trusted, Untrusted Signers, Tampered, and Other Failures.
  - **Interactive Filter Pills:** Quick one-click filtering by category (`ALL`, `VALID_TRUSTED`, `VALID_UNTRUSTED_SIGNER`, `DOCUMENT_TAMPERED`, `OTHER`).
  - **Keyword Search:** Instant live filtering by document name or key ID.
  - **Clipboard Integration:** Monospace fingerprint snippets with 1-click full copy buttons.

---

## 3. UI Security Rules & Compliance

1. **Color Restriction (Rule 8):**
   - **Green** is exclusively reserved for `VALID_TRUSTED` outcomes.
   - `VALID_UNTRUSTED_SIGNER` is strictly rendered in **Amber** with explicit warning copy.
   - Tampered and invalid states are strictly rendered in **Red**.
   - Accessible text descriptions and SVG icons accompany every status; color is never the sole indicator.
2. **Zero Internal Exposure:**
   - Stack traces, internal Java package names, filesystem paths, and private key bytes are never rendered.
3. **Anti-Tampering File Handling:**
   - Uploaded document contents are never rendered, executed, or persisted in the database.
   - Hashing is performed as raw byte streaming.

---

## 4. Test Suite & Verification Matrix

The Verification UI is verified through dedicated MockMvc integration test classes:

| Test Class | Focus Area | Covered Scenarios |
|---|---|---|
| `VerifyControllerTest` | Verification Flow | - GET `/verify` loads upload form for authenticated user<br>- Unauthenticated redirect to `/login`<br>- CSRF protection enforcement<br>- Empty document / envelope validation<br>- `VALID_TRUSTED` green rendering<br>- `DOCUMENT_TAMPERED` side-by-side hash rendering<br>- `VALID_UNTRUSTED_SIGNER` warning & quick-pin button<br>- Envelope size cap rejection via `UploadGuard`<br>- Temp file lifecycle cleanup |
| `TrustControllerTest` | Trust Store Operations | - GET `/trust` loads pinned signers directory<br>- Prefill parameter binding (`?fingerprint=...&label=...`)<br>- Unauthenticated redirect to `/login`<br>- CSRF protection on pin and revoke<br>- Successful pinning of 64-char SHA-256 fingerprint<br>- Rejection of short/malformed fingerprints<br>- Rejection of empty labels<br>- Revocation execution and redirect |
| `HistoryControllerTest` | History & Metrics | - GET `/history` loads chronological history<br>- Aggregates summary metric counts (`totalCount`, `tamperedCount`, etc.)<br>- Empty history state handling<br>- Unauthenticated redirect to `/login` |

---

## 5. Peer Integration

- **Member 1 (Deven Thakkar — Verification Engine):** Consumes `VerificationResult` model and `ResultCode` enum.
- **Member 6 (Nityanand Upadhyay — Persistence & Auth):** Integrates with `TrustStoreService`, `HistoryService`, and `VerificationRecordRepository`.
- **Member 7 (KVS Varshith — Signing UI):** Peer review partner; aligns design system, CSS tokens, and navigation flows.
- **Member 9 (Diyaan Rambhia — Network & App Security):** Enforces CSRF tokens, TLS 1.3 headers, and `UploadGuard` size limits.
