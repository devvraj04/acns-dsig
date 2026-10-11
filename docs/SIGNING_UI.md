# Technical Documentation: Signing Web Interface & Key Management Flow

**Member 7 — KVS Varshith**  
**Work Package:** Signing Web Interface & Sign Flow  
**Module:** `dsig-server`  
**Dependencies:** `dsig-core` (Members 2, 3, 4, 5), Persistence & Auth (Member 6 — Nityanand Upadhyay)  
**Review Partner:** Member 8 — Jay Pandya (Verification Web Interface & Trust UI)

---

## 1. Overview & Architecture

The Signing Web Interface is the primary user-facing component for signers in the ACNS-DSIG system. It allows authenticated users with the `ROLE_SIGNER` or `ROLE_ADMIN` role to:
1. Generate cryptographically strong RSA-3072 key pairs protected by passphrase encryption at rest.
2. Inspect, copy, and export SubjectPublicKeyInfo (SPKI) public keys in standard PEM format.
3. Securely retire signing keys so they can no longer be used for creating new signatures.
4. Upload documents up to 50 MB, select an active signing key, unlock the encrypted private key in memory, and produce detached `.dsig.json` signature envelopes.

```
+-----------------------------------------------------------------------------------+
|                                 Signer Browser                                    |
|                                                                                   |
|  [keys.html / keys.js]                     [sign.html / sign.js]                  |
|  - Passphrase strength indicator (0-4)      - Drag & drop / file size guard (<50MB) |
|  - Real-time password confirmation match   - Key selector with live FP preview     |
|  - SPKI Fingerprint 1-click clipboard       - Passphrase visibility toggles         |
|  - PEM export download                     - Detached .dsig.json auto-download     |
+-----------------------------------------------------------------------------------+
                                   | HTTPS / TLS 1.3 (Diyaan Rambhia)
                                   v
+-----------------------------------------------------------------------------------+
|                        dsig-server Controllers & Services                         |
|                                                                                   |
|  [KeyController]                           [SignController]                       |
|  - Enforces CSRF token                     - Enforces CSRF token                  |
|  - Validates passphrase constraints        - Streams upload via UploadGuard       |
|  - Verifies key ownership (Anti-IDOR)      - Validates key ownership & ACTIVE state|
|  - Never returns private key bytes         - Never returns private key bytes       |
|         |                                          |                              |
|         v                                          v                              |
|  [KeyManagementService]                    [SigningAppService]                    |
|  - Calls dsig-core KeyService              - Streams file hash (Devraj Sundrani)  |
|  - Encrypted PKCS#8 at rest (Atharv)       - Computes RSASSA-PSS (Tanmay)         |
|  - Saves KeyPairEntity to H2 (Nityanand)   - Serializes .dsig.json (Parth Zala)   |
+-----------------------------------------------------------------------------------+
```

---

## 2. Core Functional Specifications

### 2.1 Key Management Screen (`/keys`)
- **Route:** `GET /keys`, `POST /keys/generate`, `GET /keys/{keyId}/public`, `POST /keys/{keyId}/retire`
- **Controller:** `com.acns.dsig.server.web.KeyController`
- **Template:** `templates/keys.html`
- **Client Script:** `static/js/keys.js`
- **Key Generation:**
  - RSA key size: 3072 bits (meets NIST SP 800-57 guidelines for post-2030 security).
  - Private key encrypted at rest using PBES2 with PBKDF2 (HMAC-SHA256, 10,000 iterations) and AES-256-CBC.
  - Client-side strength meter checks length, lowercase, uppercase, digits, and special characters.
  - Server-side validation guarantees passphrase confirmation match and minimum length of 8 characters.
- **Key Status Lifecycle:**
  - `ACTIVE`: Key is available for signing and public export.
  - `RETIRED`: Key is blocked from new signing operations. Verifiers can still check older documents, but trust evaluation will flag the key as retired.
- **Export & Sharing:**
  - Verifiers require the public key or its SHA-256 fingerprint out-of-band to establish trust.
  - Public keys can be copied or downloaded as standard `.pem` files (`Content-Disposition: attachment; filename="public-<id>.pem"`).
  - IDOR protection: only the authenticated owner can download their public key.

### 2.2 Document Signing Screen (`/sign`)
- **Route:** `GET /sign`, `POST /sign/process`
- **Controller:** `com.acns.dsig.server.web.SignController`
- **Template:** `templates/sign.html`
- **Client Script:** `static/js/sign.js`
- **Upload & Signing Flow:**
  - Client-side validation blocks empty files and files exceeding the 50 MB threshold before submission.
  - Real-time preview displays selected document name and human-readable size (B, KB, MB).
  - Key selector dynamically updates to show the selected key's SHA-256 fingerprint.
  - Server-side processing uses `UploadGuard` to isolate uploads in temporary directories, preventing path traversal attacks.
  - If `download=true`, response returns the `.dsig.json` envelope directly as a file attachment.
  - Otherwise, the result panel renders the SHA-256 digest, key fingerprint, and document size with single-click copy buttons.

---

## 3. Strict Security Guarantees

1. **Zero Private-Key Leakage:**
   - Private key material is decrypted strictly in memory using `char[]` passphrase arrays and zeroized after use.
   - Private keys are never stored in database columns (only PKCS#8 file paths on disk).
   - Neither templates, response bodies, model attributes, nor API endpoints ever contain private key bytes.
2. **Access Control & Anti-IDOR:**
   - All key retrieval, export, and retirement operations strictly check `keyEntity.getOwnerId().equals(user.getId())`.
   - Unauthorized access attempts receive `403 Forbidden` or redirect with validation errors.
3. **State Guard:**
   - Retired or revoked keys are strictly blocked from signing in `SigningAppService`:
     ```java
     if (!"ACTIVE".equalsIgnoreCase(keyEntity.getStatus())) {
         throw new IllegalStateException("Key " + keyId + " is not active (status: " + keyEntity.getStatus() + ")");
     }
     ```
4. **Resilience & Safe Exceptions:**
   - Error messages presented to the user never leak internal cryptographic stack traces or file system paths.

---

## 4. Test Verification Suite

All 23 integration tests across `KeyControllerTest` and `SignControllerTest` pass cleanly:

| Test Class | Test Case | Purpose | Status |
|---|---|---|---|
| `KeyControllerTest` | `listKeys_authenticated_rendersPage` | Key management page loads for authenticated user | PASS |
| `KeyControllerTest` | `listKeys_unauthenticated_redirectsToLogin` | Unauthenticated requests redirected to `/login` | PASS |
| `KeyControllerTest` | `listKeys_neverRendersPrivateKeyMaterial` | Verification that private key strings are absent | PASS |
| `KeyControllerTest` | `generateKey_validInputs_showsSuccess` | Generates RSA-3072 key pair and reports fingerprint | PASS |
| `KeyControllerTest` | `generateKey_mismatchedPassphrases_showsError` | Server validation catches passphrase mismatch | PASS |
| `KeyControllerTest` | `generateKey_shortPassphrase_showsError` | Server validation catches < 8 char passphrases | PASS |
| `KeyControllerTest` | `generateKey_blankLabel_showsError` | Server validation catches empty key labels | PASS |
| `KeyControllerTest` | `downloadPublicKey_owner_downloadsPem` | Owner receives public key `.pem` attachment | PASS |
| `KeyControllerTest` | `downloadPublicKey_neverContainsPrivateKeyText` | Exported file contains only public key block | PASS |
| `KeyControllerTest` | `downloadPublicKey_nonOwner_returns403` | Non-owner export attempt is blocked with 403 | PASS |
| `KeyControllerTest` | `retireKey_owner_success` | Owner successfully retires active signing key | PASS |
| `KeyControllerTest` | `retireKey_nonOwner_showsError` | Non-owner cannot retire another user's key | PASS |
| `KeyControllerTest` | `generateKey_missingCsrfToken_returns403` | CSRF protection active on key generation | PASS |
| `SignControllerTest` | `showSignPage_authenticated_loadsKeys` | Sign page displays active keys belonging to user | PASS |
| `SignControllerTest` | `showSignPage_unauthenticated_redirectsToLogin` | Unauthenticated requests redirected to `/login` | PASS |
| `SignControllerTest` | `processSign_validDocument_showsSignResult` | Document successfully signed and hashes visualized | PASS |
| `SignControllerTest` | `processSign_withDownload_returnsAttachment` | Detached `.dsig.json` downloaded directly | PASS |
| `SignControllerTest` | `processSign_wrongPassphrase_showsErrorNoStackTrace` | Wrong passphrase returns clean error without leak | PASS |
| `SignControllerTest` | `processSign_emptyFile_showsValidationError` | Empty document file rejected with validation message | PASS |
| `SignControllerTest` | `processSign_keyOwnedByAnotherUser_showsError` | Signer cannot sign with another user's key | PASS |
| `SignControllerTest` | `processSign_retiredKey_cannotSign` | Signing with retired key is blocked | PASS |
| `SignControllerTest` | `processSign_missingCsrf_returns403` | CSRF protection active on document signing | PASS |
| `SignControllerTest` | `processSign_responseNeverContainsPrivateKeyMaterial`| Signature response never contains private key bytes | PASS |
