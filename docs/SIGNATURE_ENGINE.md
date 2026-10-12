# RSA-PSS Digital Signature Engine Technical Specification

**Author:** Tanmay Vishwakarma (Member 3)  
**Work Package:** RSA-PSS Digital Signature Engine  
**Core Classes:** `com.acns.dsig.core.crypto.SignatureService`, `com.acns.dsig.core.crypto.CryptoConfig`  
**Status:** Complete & Production Ready

---

## 1. Executive Summary & Design Objective

The **RSA-PSS Digital Signature Engine** (`SignatureService`) forms the asymmetric cryptographic core of ACNS-DSIG. It is responsible for generating mathematical proofs of document authenticity, author identity, and non-repudiation, as well as strictly verifying those proofs against genuine public keys.

Key architecture properties:
1. **Standard Java Cryptographic Architecture (JCA):** Built purely on standard JCA primitives (`java.security.Signature` with `RSASSA-PSS` and `PSSParameterSpec`), strictly avoiding fragile custom big-integer arithmetic.
2. **Defensive Parameter Configuration:** Enforces RSA-3072, SHA-256 digest, MGF1-SHA256 mask generation, and a 32-byte randomized salt ($sLen = 32$).
3. **Cryptographic Domain Separation:** Prepends the authoritative 12-byte UTF-8 prefix `ACNS-DSIG-v1\0` to manifest payloads prior to signing and verification, preventing cross-protocol signature substitution attacks.
4. **Strict Key and Algorithm Validation:** Validates RSA key types, modulus bit lengths ($\ge 3072$ bits), public exponent ($e \ge 65537$), and rejects invalid, empty, or incompatible algorithm identifiers.
5. **Dynamic Engine Introspection:** Provides programmatic access to runtime engine specifications and live microbenchmarks for real-time web UI demonstration and auditing without hardcoded assumptions.

---

## 2. Cryptographic Architecture: RSASSA-PSS vs. PKCS#1 v1.5

### 2.1 Why RSASSA-PSS was Selected
Older signature standards, such as RSA PKCS#1 v1.5, rely on deterministic padding:
$$\text{EM} = \texttt{0x00} \parallel \texttt{0x01} \parallel \texttt{0xFF} \dots \texttt{0xFF} \parallel \texttt{0x00} \parallel T$$
where $T$ is the DER encoding of the DigestInfo structure. 

While widely deployed, PKCS#1 v1.5 has inherent theoretical and practical vulnerabilities:
- **Bleichenbacher's Low-Exponent Attack:** Flaws in unverified padding formatting can allow signature forgery if verification logic fails to check all padding bytes.
- **Deterministic Output:** For a fixed document and private key, PKCS#1 v1.5 always produces the exact same signature bytes, facilitating chosen-message analysis.
- **Lack of Tight Security Proofs:** Security relies on ad-hoc heuristic assumptions rather than proven reductions in the Random Oracle Model.

### 2.2 Probabilistic Signature Scheme (PSS / RFC 8017)
RSASSA-PSS introduces a provably secure padding scheme with tight reduction to the RSA problem:
- **Randomized Salt:** For each signing operation, a fresh 32-byte cryptographically secure random salt $s \stackrel{\$}{\leftarrow} \{0,1\}^{256}$ is generated.
- **Probabilistic Signatures:** Signing the exact same document twice produces completely different 384-byte signature outputs, yet both verify successfully against the signer's public key.
- **Mask Generation Function (MGF1):** Applies MGF1 with SHA-256 to hash the salt and message representation, producing randomized pseudorandom bit masks.
- **Provable Security:** In the Random Oracle Model, breaking RSASSA-PSS is provably equivalent to inverting the RSA permutation itself.

### 2.3 Parameter Selection & Formal Specification

| Parameter | Standard / RFC 8017 | ACNS-DSIG Setting | Cryptographic Rationale |
|---|---|---|---|
| **Asymmetric Algorithm** | PKCS #1 / JCA | `RSASSA-PSS` | Provable security in Random Oracle Model |
| **RSA Modulus Bit Length** | NIST SP 800-57 | **3072 bits** (384 bytes) | 128-bit post-2030 security strength; rejects 1024/2048-bit keys |
| **Public Exponent ($e$)** | Standard RSA | **65,537 ($F_4$)** | Protects against low-exponent attacks while enabling fast verification |
| **Message Digest** | FIPS 180-4 | **SHA-256** | Collision-resistant 256-bit cryptographic hash |
| **Mask Generation Function** | PKCS #1 v2.2 | **MGF1 (SHA-256)** | Matches hash function width to prevent degradation |
| **Salt Length ($sLen$)** | RFC 8017 Section 8.1 | **32 bytes** (256 bits) | Equal to hash output length for maximal tightness |
| **Trailer Field** | RFC 8017 / PKCS #1 | **1 (`0xBC`)** | Standard standard-compliant PSS trailer |
| **Domain Separation** | ACNS-DSIG Spec | `ACNS-DSIG-v1\0` | 12-byte UTF-8 prefix binding signature to application context |

---

## 3. Domain Separation Architecture

### 3.1 The Threat: Cross-Protocol Signature Replay
If a user signs a manifest byte stream in ACNS-DSIG, an adversary might attempt to replay that same signature in another protocol (e.g., a financial transaction, SSH authentication, or another envelope format) that also signs raw SHA-256 hashes with the user's RSA key.

### 3.2 Countermeasure Implementation
`SignatureService.signManifest` and `SignatureService.verifyManifest` prepend an explicit 12-byte domain separation label:
$$\text{DataToSign} = \texttt{"ACNS-DSIG-v1\textbackslash 0"} \parallel \text{ManifestBytes}$$

```java
public byte[] signManifest(PrivateKey privateKey, byte[] manifestBytes) {
    byte[] domainSeparated = prefixDomainLabel(manifestBytes);
    return signData(privateKey, domainSeparated);
}

private byte[] prefixDomainLabel(byte[] data) {
    byte[] label = CryptoConfig.DOMAIN_SEPARATION_LABEL.getBytes(StandardCharsets.UTF_8);
    byte[] combined = new byte[label.length + data.length];
    System.arraycopy(label, 0, combined, 0, label.length);
    System.arraycopy(data, 0, combined, label.length, data.length);
    return combined;
}
```

This guarantees:
1. Signatures generated for ACNS-DSIG manifests cannot verify as raw document signatures.
2. Signatures generated by outside systems cannot verify as ACNS-DSIG manifest signatures.
3. Tests in `SignatureServiceTest.DomainSeparationTests` explicitly prove that raw signatures fail when verified against manifest verifiers, and vice versa.

---

## 4. Key and Algorithm Validation

To guard against downgrade attacks and malformed keys, `SignatureService` enforces three validation gates:

### 4.1 Private Key Validation
```java
public void validatePrivateKey(PrivateKey privateKey) {
    if (privateKey == null) {
        throw new KeyValidationException("Private key must not be null");
    }
    if (!(privateKey instanceof RSAPrivateKey rsaKey)) {
        throw new KeyValidationException("Only RSA private keys are supported");
    }
    if (rsaKey.getModulus().bitLength() < CryptoConfig.RSA_KEY_SIZE_BITS) {
        throw new KeyValidationException("Private key modulus too small (< 3072 bits)");
    }
}
```

### 4.2 Public Key Validation
```java
public void validatePublicKey(PublicKey publicKey) {
    if (publicKey == null) {
        throw new KeyValidationException("Public key must not be null");
    }
    if (!(publicKey instanceof RSAPublicKey rsaKey)) {
        throw new KeyValidationException("Only RSA public keys are supported");
    }
    if (rsaKey.getModulus().bitLength() < CryptoConfig.RSA_KEY_SIZE_BITS) {
        throw new KeyValidationException("Public key modulus too small (< 3072 bits)");
    }
    if (rsaKey.getPublicExponent().compareTo(CryptoConfig.PUBLIC_EXPONENT) < 0) {
        throw new KeyValidationException("Public exponent too small (< 65537)");
    }
}
```

### 4.3 Algorithm Identifier Validation
Enforces that the manifest's requested signature algorithm strictly matches `RSASSA-PSS-SHA256-MGF1SHA256-S32`. Any mismatched string (e.g., `SHA256withRSA`, `NONEwithRSA`, empty, or null) throws a `CryptoException`.

---

## 5. Web Demonstration & REST Auditing

To provide transparency and allow live interactive inspection in the application, `SignatureService` provides:

### 5.1 Dynamic Engine Description (`SignatureEngineInfo`)
Returns an immutable record containing:
- Algorithm name (`RSASSA-PSS`)
- Canonical identifier (`RSASSA-PSS-SHA256-MGF1SHA256-S32`)
- Modulus bit length (3072)
- Signature byte length (384 bytes)
- Hash algorithm (`SHA-256`)
- MGF algorithm (`MGF1 (SHA-256)`)
- Salt length (32 bytes)
- Domain label (`ACNS-DSIG-v1\0`)
- Minimum public exponent (65537)

### 5.2 Interactive Endpoints & UI
- **REST API:**
  - `GET /api/signature-engine`: Exposes live specification details in JSON format.
  - `GET /api/signature-engine/benchmark`: Runs 25 live in-memory signing and verification operations on the server and returns average latency (ms) and throughput (ops/sec).
- **Dashboard (`/dashboard`):**
  - Features the **RSA-PSS Digital Signature Engine** card with live cryptographic specification badges and a one-click **Run Live Engine Benchmark** widget.
- **Document Signing (`/sign`):**
  - Displays engine parameters and renders the full 384-byte raw Base64 signature with one-click clipboard copying.

---

## 6. Verification & Test Suite Summary

The engine is covered by 23 comprehensive tests in `SignatureServiceTest.java`:
1. **Happy Path:**
   - Manifest signing and verification.
   - Raw data signing and verification.
   - 384-byte exact signature size validation.
   - Probabilistic signature verification (asserts distinct signatures for identical inputs).
2. **Negative Integrity & Tampering:**
   - Public key mismatch detection.
   - 1-bit manifest tamper detection.
   - Single-bit signature corruption detection.
   - Truncated signature rejection.
   - Random garbage bytes rejection.
   - Missing domain separation label rejection.
   - Null and empty argument validation.
3. **Key Enforcement:**
   - Rejection of 1024-bit and 2048-bit RSA keys.
   - Rejection of non-RSA (EC secp256r1) keys.
   - Acceptance of 3072-bit keys.
4. **Domain Separation:**
   - Cross-domain signature rejection.
   - Raw vs. manifest prefix isolation.
5. **Algorithm Validation:**
   - Rejection of non-canonical algorithm identifiers.
