# ACNS-DSIG Specification: Format & Serialization Specification

**Owner:** Parth Zala  
**Status:** Frozen Contract (Version 1)

---

## 1. Detached Signature Package Structure (`<document>.<ext>.dsig.json`)

The signature package is stored detached from the original document so that the original binary content remains unmodified.

### 1.1 Envelope JSON Schema
```json
{
  "format": "ACNS-DSIG",
  "version": 1,
  "manifest": "<Base64 encoded UTF-8 bytes of canonical manifest JSON>",
  "signature": "<Base64 encoded RSA-PSS signature bytes>",
  "publicKey": "<Base64 encoded DER SubjectPublicKeyInfo>"
}
```

### 1.2 Field Definitions
| Field | Type | Description |
|---|---|---|
| `format` | String | Fixed protocol identifier: `"ACNS-DSIG"`. |
| `version` | Integer | Protocol format version integer (currently `1`). |
| `manifest` | String | Base64-encoded UTF-8 bytes of the signed manifest JSON object. |
| `signature` | String | Base64-encoded RSASSA-PSS digital signature computed over `LABEL \|\| manifestBytes`. |
| `publicKey` | String | Base64-encoded ASN.1 DER SubjectPublicKeyInfo bytes of the signer's public key. Informational; does NOT automatically establish trust. |

---

## 2. Signed Manifest Specification

The manifest binds all essential metadata attributes together into a single authenticated payload.

### 2.1 Manifest JSON Schema
```json
{
  "v": 1,
  "docName": "invoice.pdf",
  "docSize": 482913,
  "hashAlg": "SHA-256",
  "docHash": "<Base64 encoded 32-byte SHA-256 digest of document>",
  "sigAlg": "RSASSA-PSS-SHA256-MGF1SHA256-S32",
  "keyId": "<SHA-256 SPKI fingerprint in lowercase hex>",
  "signedAt": "2026-10-08T12:30:00Z",
  "nonce": "<Base64 encoded 16-byte random nonce>",
  "signer": "Signer Display Name"
}
```

### 2.2 Field Definitions
| Field | Type | Description |
|---|---|---|
| `v` | Integer | Manifest format version (`1`). |
| `docName` | String | Original document filename (display/informational only). |
| `docSize` | Long | Exact size of the document in bytes. |
| `hashAlg` | String | Fixed cryptographic digest algorithm: `"SHA-256"`. |
| `docHash` | String | Base64 encoding of the exact 32-byte SHA-256 digest of the document bytes. |
| `sigAlg` | String | Fixed signature algorithm: `"RSASSA-PSS-SHA256-MGF1SHA256-S32"`. |
| `keyId` | String | Normalized lowercase hex SHA-256 fingerprint of the signer's public key SPKI DER. |
| `signedAt` | String (ISO-8601) | UTC timestamp of signature creation (`YYYY-MM-DDTHH:MM:SSZ`). |
| `nonce` | String | Base64 encoding of 16 cryptographically secure random bytes (anti-replay freshness). |
| `signer` | String | Human-readable identity or label of signer. |

---

## 3. Strict Parser & Codec Rules
1. **Duplicate Keys:** Envelope and Manifest JSON parsers must strictly reject JSON documents containing duplicate keys.
2. **Unknown Properties:** Unknown or unexpected fields trigger rejection (`CORRUPTED_PACKAGE` or `UNSUPPORTED_FORMAT`).
3. **Canonical Signing:** The verifier verifies the digital signature directly over the exact raw bytes received in `base64Manifest` prefixed with the domain separation label `ACNS-DSIG-v1\0`.
4. **Limits:** Envelope JSON must not exceed 512 KB; Manifest JSON must not exceed 64 KB.
