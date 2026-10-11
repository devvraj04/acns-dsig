# Key Generation, Secure Storage & Fingerprints Technical Specification

**Author:** Atharv Vedant (Member 4)  
**Work Package:** Key Generation, Secure Storage & Fingerprints  
**Core Classes:**  
- `com.acns.dsig.core.keys.KeyService`  
- `com.acns.dsig.core.keys.KeyStorage`  
- `com.acns.dsig.core.keys.Fingerprint`  
- `com.acns.dsig.core.keys.KeyStatus`  
**Review Partner:** Devraj Sundrani (Member 2)  
**Status:** Complete & Production Ready  

---

## 1. Executive Summary & Design Objective

In the ACNS-DSIG architecture, the **Key Management Subsystem** provides cryptographic root identity, secret key security, and lifecycle guarantees. Asymmetric digital signatures depend completely on the confidentiality of the signer's private key and the authentic binding of the public key to the signer's identity.

The subsystem delivers four core guarantees:
1. **Compliant Key Generation:** Cryptographically sound generation of RSA-3072 key pairs using standard Fermat-4 public exponent ($e = 65537$) and Java CSPRNG (`SecureRandom`).
2. **Encrypted Key Storage at Rest:** Strict PBES2 password-based encryption conforming to NIST SP 800-132 and PKCS#5 v2.1 using PBKDF2 with HMAC-SHA256, 600,000 iterations, 16-byte random salt, and AES-256 in PKCS#8 format.
3. **Out-of-Band Key Pinning via SPKI Fingerprints:** Deterministic computation of SHA-256 fingerprints over standard ASN.1 `SubjectPublicKeyInfo` (SPKI) structures, preventing public-key substitution and rogue-signer attacks.
4. **Enforced Key Lifecycle & Capability Model:** Formal state transitions (`ACTIVE`, `RETIRED`, `REVOKED`) dictating whether a key is permitted to sign new documents or remain eligible for historical verification.

---

## 2. Cryptographic Architecture: Key Generation

### 2.1 Parameter Selection: RSA-3072 ($e = 65537$)
- **Key Algorithm:** RSA (`CryptoConfig.KEY_ALGORITHM`)
- **Modulus Bit Length:** 3072 bits (`CryptoConfig.RSA_KEY_BITS = 3072`)
- **Public Exponent:** $e = 65537$ ($F_4 = 2^{16} + 1$)
- **Entropy Source:** `java.security.SecureRandom`

#### Rationale for 3072-bit Modulus
NIST Special Publication 800-57 Part 1 Rev. 5 specifies cryptographic security strengths:
- RSA-2048 provides approximately 112 bits of security (acceptable only through legacy grace periods).
- **RSA-3072 provides 128 bits of security**, matching the cryptographic strength of AES-128 and SHA-256 for long-term data authenticity beyond 2030.
- RSA-4096 yields diminishing security returns while incurring a ~3x performance penalty on key generation and signing.

#### Rationale for Fermat Exponent $F_4 = 65537$
- Small public exponents such as $e = 3$ are vulnerable to Coppersmith's theorem attacks and low-exponent broadcast attacks.
- $e = 65537$ has a Hamming weight of only 2 ($2^{16} + 1$, binary `10000000000000001`), requiring only 17 modular multiplications during public-key verification while effectively neutralizing low-exponent attacks.

### 2.2 Strict Key Generation Verification (`KeyService`)
`KeyService.generateKeyPair()` enforces parameter compliance before returning the `GeneratedKeyPair` container:
- Validates that public key is an instance of `RSAPublicKey` and private key is an instance of `RSAPrivateKey`.
- Confirms that modulus bit length is $\ge 3072$ bits (`pub.getModulus().bitLength() >= 3072`).
- Confirms that public exponent is exactly $F_4$ (`pub.getPublicExponent().equals(65537)`).
- Atomically binds the generated key pair to its canonical 64-character lowercase SHA-256 fingerprint, grouped fingerprint block, and 16-character short Key ID.

---

## 3. Secure Private Key Storage at Rest (`KeyStorage`)

### 3.1 PBES2 Encrypted PKCS#8 Specification
Private keys are never stored in plaintext on disk or in the database. `KeyStorage` serializes private keys using standard PKCS#8 EncryptedPrivateKeyInfo:

| Parameter | Value | Security Rationale |
|---|---|---|
| **Cipher Suite** | `PBEWithHmacSHA256AndAES_256` | PBES2 with PBKDF2 and AES-256 |
| **KDF** | PBKDF2 with HMAC-SHA256 | Resists GPU/ASIC parallel dictionary attacks |
| **Salt Length** | 16 bytes (128 bits) CSPRNG | Prevents rainbow-table attacks across keys |
| **Iteration Count** | 600,000 iterations | Exceeds OWASP 2023 recommendations for PBKDF2-HMAC-SHA256 |
| **Container Format** | ASN.1 DER encapsulated in PEM | `-----BEGIN ENCRYPTED PRIVATE KEY-----` |

### 3.2 Standard PKCS#8 ASN.1 Encoding
To ensure universal interoperability with OpenSSL and Java cryptographic providers, `saveEncryptedPrivateKey` wraps PBES2 parameters using the standard ASN.1 OID `1.2.840.113549.1.5.13` (`PBES2`):
```java
AlgorithmParameters pbes2Params = AlgorithmParameters.getInstance("PBES2");
pbes2Params.init(cipher.getParameters().getEncoded());
EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(pbes2Params, encryptedKey);
```

### 3.3 Defensive Security & Error Sanitization
- **Generic Decryption Errors:** When a wrong passphrase is provided or ciphertext is tampered with, `loadEncryptedPrivateKey` catches all internal cryptographic errors (`BadPaddingException`, `AEADBadTagException`, `InvalidKeySpecException`) and emits a generic, uniform exception:
  ```java
  throw new CryptoException("Invalid passphrase or corrupted key file");
  ```
  This eliminates padding-oracle or format-oracle side-channels.
- **Minimum Key Size Enforcement on Load:**
  Even if an encrypted key is successfully decrypted, `loadEncryptedPrivateKey` verifies that the recovered `RSAPrivateKey` modulus is $\ge 3072$ bits. Any legacy or truncated keys are rejected with `KeyValidationException`.
- **Passphrase In-Memory Zeroization:**
  `KeyStorage.zeroize(char[] secret)` overwrites sensitive passphrase arrays with null characters (`'\0'`) immediately after use, preventing secrets from persisting in Java heap dumps.

---

## 4. Public Key Serialization & Fingerprinting (`Fingerprint`)

### 4.1 SubjectPublicKeyInfo (SPKI) Architecture
Public keys are exported in standard X.509 `SubjectPublicKeyInfo` (SPKI) format as PEM:
```text
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA...
-----END PUBLIC KEY-----
```
`KeyStorage.parsePublicKeyFromPem` verifies:
1. Valid PEM encapsulation headers (`BEGIN/END PUBLIC KEY`).
2. Valid Base64 encoding.
3. RSA algorithm consistency.
4. Strict minimum modulus size of $\ge 3072$ bits.

### 4.2 Out-of-Band Trust & SHA-256 Fingerprint
Because self-signed or uncertified public keys can be substituted by an active adversary (Public Key Substitution Attack), ACNS-DSIG relies on out-of-band fingerprint pinning.

#### Fingerprint Computation Formula
The fingerprint is defined as the SHA-256 digest calculated strictly over the DER-encoded ASN.1 `SubjectPublicKeyInfo` bytes:
$$\text{Fingerprint} = \text{Hex}(\text{SHA-256}(\text{SPKI}_{\text{DER}}))$$

```java
MessageDigest digest = MessageDigest.getInstance("SHA-256");
byte[] hash = digest.digest(publicKey.getEncoded());
return HexFormat.of().formatHex(hash).toLowerCase();
```

#### Formatting & Key IDs
- **Normalized Hex:** 64-character lowercase hexadecimal string.
- **Grouped Presentation:** Formatted into uppercase 4-character blocks separated by spaces (`Fingerprint.formatGrouped`):
  `A1B2 C3D4 E5F6 0123 ...`
- **Short Key ID:** First 16 hex characters (`Fingerprint.toKeyId`), providing a compact, collision-resistant identifier for UI tables and log files.

---

## 5. Key Lifecycle State Model (`KeyStatus`)

Keys transition through a deterministic lifecycle modeled by `KeyStatus`:

```mermaid
stateDiagram-v2
    [*] --> ACTIVE : Key Generated
    ACTIVE --> RETIRED : Voluntary Retirement
    ACTIVE --> REVOKED : Compromised / Invalidation
    RETIRED --> REVOKED : Discovered Post-Retirement Compromise
    REVOKED --> [*] : Terminal State
```

### 5.1 Capability & Permission Matrix

| Key Status | `canSign()` | `canVerify()` | Cryptographic Rationale |
|---|:---:|:---:|---|
| `ACTIVE` | **YES** | **YES** | Primary operational key; allowed to create new digital signatures and verify signatures. |
| `RETIRED` | **NO** | **YES** | Key lifecycle has expired; past documents remain legally valid and verifiable, but creating new signatures is prohibited. |
| `REVOKED` | **NO** | **NO** | Private key compromise or identity invalidation; all past and present signatures must be rejected as untrusted. |

### 5.2 Transition Validation Rules
`KeyStatus.validateTransition(KeyStatus next)` enforces strict invariant checks:
- Transitions from `ACTIVE` to `RETIRED` or `REVOKED` are valid.
- Transitions from `RETIRED` to `REVOKED` are valid.
- Re-activation of `RETIRED` or `REVOKED` keys back to `ACTIVE` is strictly prohibited (`IllegalStateException`).
- `REVOKED` is a terminal state; no transitions out of `REVOKED` are allowed.

---

## 6. Threat Mitigation Matrix

| Threat | Attack Vector | Countermeasure in Subsystem |
|---|---|---|
| **Weak Key Generation** | Factoring weak or small RSA moduli ($< 2048$ bits) | Minimum key size enforcement ($\ge 3072$ bits) and strict exponent validation ($F_4 = 65537$) in `KeyService` and `KeyStorage`. |
| **Passphrase Cracking** | Offline brute-force dictionary attack on exported `.pk8` files | PBES2 with PBKDF2-HMAC-SHA256, 600,000 iterations, and 16-byte random salt in `KeyStorage`. |
| **Key Substitution** | Adversary replaces public key in `.dsig.json` envelope | SHA-256 SPKI fingerprint calculation bound to signer trust store via `Fingerprint.calculate`. |
| **Timing Side-Channel** | Measuring decryption error response timing | Uniform generic error message `Invalid passphrase or corrupted key file` masking internal cipher states. |
| **Heap Scraping** | Extracting plaintext passwords from memory dumps | Memory zeroization utility `KeyStorage.zeroize(char[])` overwriting sensitive buffers. |
| **Compromised Key Re-use** | Signing with revoked credentials | `KeyStatus.canSign()` and `validateTransition()` prohibiting signing with non-`ACTIVE` keys. |

---

## 7. Verification & Test Evidence

The subsystem is validated by 25 dedicated unit tests across four test classes in `dsig-core/src/test/java/com/acns/dsig/core/keys/`:

```text
[INFO] Running com.acns.dsig.core.keys.KeyServiceTest
[INFO] Tests run: 3, Failures: 0, Errors: 0, Skipped: 0
[INFO] Running com.acns.dsig.core.keys.FingerprintTest
[INFO] Tests run: 7, Failures: 0, Errors: 0, Skipped: 0
[INFO] Running com.acns.dsig.core.keys.KeyStatusTest
[INFO] Tests run: 5, Failures: 0, Errors: 0, Skipped: 0
[INFO] Running com.acns.dsig.core.keys.KeyStorageTest
[INFO] Tests run: 10, Failures: 0, Errors: 0, Skipped: 0
```

### Test Coverage Highlights
- **`KeyServiceTest`:** Verified 3072-bit modulus, $F_4$ exponent, CSPRNG non-determinism, and fingerprint binding.
- **`FingerprintTest`:** Verified determinism, SPKI hashing KATs, 4-char grouped formatting, 16-char Key ID derivation, and null checks.
- **`KeyStatusTest`:** Verified capability matrix (`canSign`, `canVerify`), allowed transitions, and illegal transition rejections.
- **`KeyStorageTest`:** Verified encryption/decryption roundtrip on disk, wrong passphrase rejection, tampered ciphertext rejection, rejection of weak 2048-bit keys on export/import/save, and memory zeroization.
