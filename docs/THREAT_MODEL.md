# ACNS-DSIG Threat Model & Security Architecture

**Owner:** Diyaan Rambhia  
**Status:** Frozen Security Blueprint

---

## 1. System Assets & Security Objectives
1. **Document Integrity:** Guarantee that received document bytes match signed bytes exactly.
2. **Cryptographic Origin Authentication:** Prove knowledge of the corresponding private key via RSASSA-PSS.
3. **Signer Identity Binding:** Establish whether the public key is trusted via out-of-band fingerprint pinning.
4. **Non-Repudiation with Auditability:** Audit logging protected by forward hash-chaining.
5. **Secret Protection:** Never store or expose private keys or passphrases in plaintext.

---

## 2. Threat Matrix & Mitigations

| Threat | Attack Vector | Countermeasure in ACNS-DSIG |
|---|---|---|
| **Document Modification** | In-transit tampering of document bytes via USB/email/cloud. | SHA-256 streaming hash compared against authenticated manifest hash; returns `DOCUMENT_TAMPERED`. |
| **Signature Modification** | Attacker flips bits in the signature bytes. | RSASSA-PSS verification fails; returns `INVALID_SIGNATURE`. |
| **Manifest Tampering** | Attacker alters document size or timestamp inside manifest. | Digital signature covers `LABEL \|\| manifestBytes`; RSASSA-PSS verification fails. |
| **Public-Key Substitution** | Attacker replaces document, signature, AND public key with their own. | Verifier checks public key fingerprint against pinned trust store; returns `VALID_UNTRUSTED_SIGNER`. |
| **Private-Key Theft** | Attacker gains read access to server or disk files. | Private keys encrypted at rest via PBES2 AES-256 with PBKDF2 HMAC-SHA256 (600,000 iterations). |
| **Transport Interception** | Eavesdropping or active manipulation over network. | Web communication enforced over TLS 1.3 with strict HTTPS and secure cookies. |
| **Audit Log Tampering** | Rogue administrator attempts to modify or delete historical log entries. | Cryptographic hash chaining: `entry_hash = SHA-256(prev_hash \|\| seq \|\| timestamp \|\| user \|\| action \|\| detail)`. Admin verification identifies first broken link. |
| **Algorithm Confusion** | Attacker injects weak parameters (e.g. `none`, `MD5`, RSA-1024). | Rigid cryptographic configuration: strictly 3072-bit RSA, SHA-256, MGF1-SHA256, salt 32. Dynamic algorithm negotiation is prohibited. |
| **Resource Exhaustion / DoS** | Malicious multi-gigabyte JSON payloads or billion laughs. | Size caps enforced: 512KB envelope limit, 64KB manifest limit, streaming buffer for document hashing. |

---

## 3. Explicit Cryptographic Boundaries & Honest Limitations
- **No CA PKI:** The system does not implement an X.509 certificate hierarchy; trust relies on out-of-band fingerprint pinning.
- **No Confidentiality:** Digital signing provides authenticity and integrity; document payload itself is not encrypted.
- **Replay Considerations:** Nonces and ISO timestamps provide audit freshness; true replay mitigation requires external business process verification.
