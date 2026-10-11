# ACNS-DSIG: Secure Digital Document Authentication & Integrity Verification

> **Course / Subject:** Applied Cryptography and Network Security (CNS / ACNS-DC)  
> **Architecture:** Pure Java Cryptographic Core + Picocli Offline CLI + Spring Boot 3 Web Application  
> **Cryptographic Suite:** RSA-3072, RSASSA-PSS, SHA-256, PBES2 AES-256 Key Storage, Hash-Chained Audit  
> **Web Theme:** Aura Gradient — Ice Sheet (Tailwind CSS, Inter & JetBrains Mono, Frosted Glass)

---

## 1. Project Overview

Digital documents (PDFs, contracts, invoices, code artifacts) exchanged across insecure communication channels such as email, messaging apps, or cloud storage can be intercepted, forged, or altered in transit. 

**ACNS-DSIG** implements a modular, production-grade cryptographic authentication system providing:
1. **Cryptographic Integrity:** Streaming SHA-256 digest calculation detects single-bit file alterations without loading entire large files into memory.
2. **Cryptographic Origin Authentication:** RSA-3072 with RSASSA-PSS (SHA-256 / MGF1-SHA256, 32-byte salt) and domain separation (`ACNS-DSIG-v1`) mathematically proves private-key possession.
3. **Explicit Signer Trust (Zero-Trust Pinning):** Out-of-band SHA-256 SubjectPublicKeyInfo (SPKI) fingerprint pinning prevents public-key substitution and rogue certificate attacks.
4. **Auditability & Non-Repudiation:** Tamper-evident forward hash chain (`entry_hash = SHA-256(prev_hash || seq || timestamp || user || action || detail)`) guarantees immutability of system events.
5. **Defense-in-Depth Transport & Web Security:** Strict CSP, TLS 1.3, anti-CSRF tokens, token-bucket IP rate limiting, brute-force lockout, and PBES2 AES-256 private key encryption at rest.

---

## 2. Repository Architecture

```text
acns-dsig/
├── pom.xml                                   (Parent POM, dependency management)
├── mvnw, mvnw.cmd, .mvn/                     (Maven Wrapper — Java 21+ required)
├── .github/workflows/ci.yml                  (Automated GitHub Actions CI matrix)
│
├── dsig-core/                                (Pure Java Cryptographic Core — zero external web dependencies)
│   ├── api/                                  (Frozen API contracts: VerificationResult, ResultCode, TrustStatus)
│   ├── crypto/                               (HashService, SignatureService, ConstantTime, CryptoConfig)
│   ├── keys/                                 (KeyService, KeyStorage PBES2 AES-256, Fingerprint, KeyStatus)
│   ├── format/                               (Manifest, Envelope, EnvelopeCodec strict parser, FormatLimits)
│   ├── sign/                                 (SigningService detached envelope generator)
│   ├── verify/                               (VerificationService multi-stage verifier)
│   ├── trust/                                (TrustPolicy evaluation logic)
│   └── error/                                (DsigException hierarchy)
│
├── dsig-cli/                                 (Offline Command-Line Interface using Picocli)
│   ├── DsigCli.java                          (CLI entry point)
│   ├── KeygenCommand.java                    (RSA-3072 keygen with PBES2 AES-256 storage)
│   ├── FingerprintCommand.java               (SHA-256 SPKI fingerprint extraction)
│   ├── SignCommand.java                      (Detached document signing to .dsig.json)
│   ├── VerifyCommand.java                    (Multi-stage integrity and trust verification)
│   ├── TrustAddCommand / TrustListCommand    (Local JSON trust store management)
│   └── FileTrustStore.java                   (Thread-safe file-backed TrustLookup)
│
├── dsig-server/                              (Production Spring Boot 3 Web Application)
│   ├── persistence/                          (JPA entities, repositories, and AuditChainService)
│   ├── service/                              (SigningAppService, VerificationAppService, KeyManagementService)
│   ├── security/                             (SecurityConfig, RateLimitFilter, UploadGuard, CSP policy)
│   ├── web/                                  (MVC controllers: Auth, Keys, Sign, Verify, Trust, History, Audit)
│   └── resources/
│       ├── application.yml                   (Production config with H2 file DB & optional TLS)
│       ├── application-demo.yml              (In-memory H2 demo profile for rapid testing)
│       ├── templates/                        (Thymeleaf views styled with Ice Sheet Aura Gradient)
│       └── static/css/app.css                (Aura 4-layer blend modes & frosted glass styling)
│
├── docs/                                     (Specifications, Threat Model, Changes, and Architecture)
│   ├── changes.md                            (Exhaustive log of codebase modifications)
│   ├── KEY_MANAGEMENT.md                     (Key lifecycle, PBES2 derivation, and zeroization)
│   ├── FORMAT.md                             (Detached envelope and canonical manifest schema)
│   ├── THREAT_MODEL.md                       (STRIDE threat matrix and countermeasure analysis)
│   └── report.md                             (Detailed project implementation report)
│
├── scripts/                                  (Cross-platform runner and benchmark scripts)
│   ├── run-demo.sh / run-demo.ps1            (Automated end-to-end cryptographic demonstration)
│   ├── bench.sh / bench.ps1                  (Microbenchmark suite for throughput and latency)
│   ├── fuzz.sh / fuzz.ps1                    (Parser fuzzing suite for malformed envelopes)
│   └── gen-cert.sh / gen-cert.ps1            (Self-signed TLS 1.3 PKCS#12 keystore generator)
│
├── test-data/                                (Sample documents for signing, verification, and tampering)
└── runtime/                                  (Local runtime state: H2 database, keys, and uploads)
```

---

## 3. Team Work Package Allocation (10 Members)

| Member | Work Package | Primary Technical Modules |
|---|---|---|
| **Deven Thakkar** | Verification Engine & Result Model | `VerificationService`, `VerificationResult`, `ResultCode`, `TrustPolicy`, `DsigException` |
| **Devraj Sundrani** | Document Processing & SHA-256 Hashing | `HashService`, `ConstantTime`, `DsigCli`, CLI commands |
| **Tanmay Vishwakarma** | RSA-PSS Signature Engine | `SignatureService`, `CryptoConfig`, `SigningService` |
| **Atharv Vedant** | Key Generation & Secure Key Storage | `KeyService`, `KeyStorage` (PBES2 AES-256), `Fingerprint`, `KeyStatus` |
| **Parth Zala** | Manifest, Envelope & Strict Codec | `Manifest`, `Envelope`, `EnvelopeCodec`, `FormatLimits`, `FORMAT.md` |
| **Nityanand Upadhyay** | Database, Users & Audit Chain | JPA Entities, Repositories, `AuditChainService`, `UserService`, `HistoryService` |
| **KVS Varshith** | Signing Web Interface & Key UI | `KeyController`, `SignController`, `keys.html`, `sign.html`, `sign.js` |
| **Jay Pandya** | Verification Web Interface & Trust UI | `VerifyController`, `TrustController`, `AuditController`, `verify.html`, `result.html`, `trust.html` |
| **Diyaan Rambhia** | Network & Application Security | `SecurityConfig`, `RateLimitFilter`, `UploadGuard`, `THREAT_MODEL.md`, `application.yml` |
| **Simrit Kaur** | QA, CI/CD, Documentation & Demo | GitHub Actions CI, Maven Wrapper, test fixtures, benchmark scripts |

---

## 4. Prerequisites

- **Java Development Kit (JDK):** **Java 21 LTS** or **Java 23** installed.
  - Check your version:
    ```bash
    java -version
    ```
  - Ensure `JAVA_HOME` points to your JDK directory:
    - **Windows (PowerShell):** `$env:JAVA_HOME = "C:\Program Files\Java\jdk-23"`
    - **Linux / macOS:** `export JAVA_HOME=/path/to/jdk-21`
- **Build Tool:** Maven Wrapper (`./mvnw` or `.\mvnw.cmd`) is included in the project. No separate Maven installation is required.

---

## 5. Building the Project

Always build from the repository root directory (`acns-dsig`).

### 5.1 Clean and Build All Modules
```bash
# On Linux / macOS:
./mvnw clean package

# On Windows (PowerShell or Command Prompt):
.\mvnw.cmd clean package
```

### 5.2 Build Without Running Tests (Quick Build)
```bash
# Linux / macOS:
./mvnw clean package -DskipTests

# Windows:
.\mvnw.cmd clean package -DskipTests
```

This compiles all modules and produces the following standalone artifacts:
- `dsig-core/target/dsig-core-1.0.0-SNAPSHOT.jar`
- `dsig-cli/target/dsig-cli-1.0.0-SNAPSHOT.jar` (Executable offline CLI)
- `dsig-server/target/dsig-server-1.0.0-SNAPSHOT.jar` (Executable Spring Boot Web App)

---

## 6. Ways to Run the Project

### Method 1: Automated End-to-End Demonstration Script

The fastest way to witness the full cryptographic flow (key generation, fingerprint calculation, trust store pinning, signing, valid verification, and tamper detection) is through the demo scripts:

#### On Windows (PowerShell):
```powershell
powershell -ExecutionPolicy Bypass -File scripts/run-demo.ps1
```

#### On Linux / macOS (Bash):
```bash
bash scripts/run-demo.sh
```

**What the demo demonstrates:**
1. Generates an RSA-3072 key pair encrypted with PBES2 AES-256.
2. Calculates the SHA-256 SPKI fingerprint of the public key.
3. Pins the fingerprint into the trust store (`trusted.json`).
4. Signs a sample document (`test-data/contract.txt`) into a detached envelope (`.dsig.json`).
5. Verifies the authentic document &rarr; outputs **`VALID_TRUSTED`** (exit code 0).
6. Injects an unauthorized clause into the document &rarr; outputs **`DOCUMENT_TAMPERED`** (exit code 1).
7. Automatically cleans up temporary demo artifacts.

---

### Method 2: Offline Command-Line Interface (CLI)

The CLI works completely offline without network or database dependencies.

Ensure the CLI jar has been packaged:
```bash
.\mvnw.cmd package -DskipTests -pl dsig-core,dsig-cli
```

#### 1. Generate an RSA-3072 Key Pair
```bash
java -jar dsig-cli/target/dsig-cli-1.0.0-SNAPSHOT.jar keygen -o mykey -p MySecretPass123
```
- Outputs:
  - `mykey.pk8`: Private key encrypted with PBES2 AES-256.
  - `mykey.pub.pem`: Public key in standard SubjectPublicKeyInfo (SPKI) PEM format.

#### 2. Display the Public Key Fingerprint
```bash
java -jar dsig-cli/target/dsig-cli-1.0.0-SNAPSHOT.jar fingerprint mykey.pub.pem
```

#### 3. Pin the Fingerprint in Your Local Trust Store
```bash
java -jar dsig-cli/target/dsig-cli-1.0.0-SNAPSHOT.jar trust-add <FINGERPRINT_HEX> -l "Alice Finance" --trust-store my-trust.json
```

#### 4. List Pinned Signers in Trust Store
```bash
java -jar dsig-cli/target/dsig-cli-1.0.0-SNAPSHOT.jar trust-list --trust-store my-trust.json
```

#### 5. Sign a Document (Generate Detached Envelope)
```bash
java -jar dsig-cli/target/dsig-cli-1.0.0-SNAPSHOT.jar sign test-data/contract.txt -k mykey.pk8 --pub mykey.pub.pem -p MySecretPass123 -s "Alice Finance" -o contract.txt.dsig.json
```

#### 6. Verify Document Authenticity & Integrity
```bash
# Verifying with local trust store:
java -jar dsig-cli/target/dsig-cli-1.0.0-SNAPSHOT.jar verify test-data/contract.txt -e contract.txt.dsig.json --trust-store my-trust.json
```

Possible outcomes:
- `VALID_TRUSTED`: Signature valid and signer fingerprint pinned in trust store.
- `VALID_UNTRUSTED_SIGNER`: Signature valid, but signer fingerprint not pinned.
- `DOCUMENT_TAMPERED`: Document bytes altered after signing (exit code 1).
- `SIGNATURE_INVALID`: Signature could not be cryptographically validated.

---

### Method 3: Spring Boot Web Application (Browser Interface)

The web application provides an intuitive graphical interface featuring the **Ice Sheet Aura Gradient** theme, frosted glass cards, and side-by-side cryptographic tamper diffs.

#### Option A: Running with Maven (Development / Demo Mode)
```bash
# Windows (PowerShell):
.\mvnw.cmd -pl dsig-server spring-boot:run

# Linux / macOS:
./mvnw -pl dsig-server spring-boot:run
```

To run with an isolated in-memory H2 database (resets on restart):
```bash
.\mvnw.cmd -pl dsig-server spring-boot:run -Dspring-boot.run.profiles=demo
```

#### Option B: Running the Packaged JAR Directly
```bash
# First build all modules:
.\mvnw.cmd clean package -DskipTests

# Run the server jar:
java -jar dsig-server/target/dsig-server-1.0.0-SNAPSHOT.jar
```

#### Accessing the Web Interface
1. Open your web browser to **`http://localhost:8080`** (or `https://localhost:8443` if TLS is enabled).
2. Click **Register** to create an account:
   - Select role **Signer** to generate keys and sign documents.
   - Select role **Verifier** to inspect incoming documents and pin signers.
3. Log in to access the multi-step navigation tabs:
   - **Dashboard:** Workspace metrics, quick stats, and workflow guides.
   - **Keys (`/keys`):** Generate RSA-3072 key pairs, test passphrase strength, export public PEM, copy fingerprints, and retire keys.
   - **Sign (`/sign`):** Upload any document (&le; 50 MB), enter your passphrase, sign detached envelope, and download `.dsig.json`.
   - **Verify (`/verify`):** Drag-and-drop document and `.dsig.json` envelope to execute multi-stage verification.
   - **Outcome (`/verify` result):** View color-coded outcome badges, signer identity, side-by-side SHA-256 digest comparison, and quick-pin CTA.
   - **Trust Store (`/trust`):** Pin 64-hex SHA-256 SPKI fingerprints with notes, search pinned signers, or revoke trust.
   - **History (`/history`):** Filter and search chronological verification audit history.
   - **Audit (`/admin/audit`):** Admin view to verify the mathematical integrity of the forward hash chain.

---

### Method 4: Production HTTPS / TLS 1.3 Mode

To run the web interface over strict TLS 1.3 with AES-GCM and ChaCha20-Poly1305:

#### 1. Generate a PKCS#12 Keystore
```bash
# On Windows (PowerShell):
powershell -ExecutionPolicy Bypass -File scripts/gen-cert.ps1

# On Linux / macOS:
bash scripts/gen-cert.sh
```
This generates `runtime/tls/keystore.p12` with RSA-3072 self-signed certificate.

#### 2. Start Server with TLS Enabled
```bash
# Windows:
$env:SSL_ENABLED = "true"; $env:SERVER_PORT = "8443"; .\mvnw.cmd -pl dsig-server spring-boot:run

# Linux / macOS:
SSL_ENABLED=true SERVER_PORT=8443 ./mvnw -pl dsig-server spring-boot:run
```
Navigate to **`https://localhost:8443`** (accept the self-signed certificate warning in your browser for local testing).

---

## 7. Testing, Fuzzing & Microbenchmarking

### 7.1 Running All Unit & Integration Tests (140+ Tests)
```bash
# Run tests across all 3 modules (dsig-core, dsig-cli, dsig-server):
.\mvnw.cmd test

# Run tests only for a specific module:
.\mvnw.cmd test -pl dsig-core
.\mvnw.cmd test -pl dsig-cli
.\mvnw.cmd test -pl dsig-server
```

### 7.2 Microbenchmark Suite (Performance Profiling)
Measures SHA-256 streaming hashing throughput, RSA-3072 key generation time, and RSASSA-PSS signing/verifying latency:

```bash
# On Windows:
powershell -ExecutionPolicy Bypass -File scripts/bench.ps1

# On Linux / macOS:
bash scripts/bench.sh
```

### 7.3 Envelope & Parser Fuzz Testing
Evaluates parser resilience against randomized bitflips, truncated payloads, corrupt Base64, and boundary violations:

```bash
# On Windows:
powershell -ExecutionPolicy Bypass -File scripts/fuzz.ps1

# On Linux / macOS:
bash scripts/fuzz.sh
```

---

## 8. Common Troubleshooting & Notes

- **Maven Multi-Module Build Order:**  
  If building `dsig-cli` or `dsig-server` individually results in a `Could not resolve dependencies for com.acns.dsig:dsig-core` error, run `.\mvnw.cmd install -DskipTests` or `.\mvnw.cmd package -DskipTests` from the root directory first to install `dsig-core` into your local `.m2` repository.
- **H2 Database Lock (`runtime/acns-dsig.mv.db`):**  
  If the server fails to start with `Database may be already in use: Locked by another process`, ensure no orphaned `java.exe` process is running:
  ```powershell
  Get-Process -Name java | Stop-Process -Force
  ```
- **File Upload Limits:**  
  Document upload size is capped at **50 MB**; signature envelopes (`.dsig.json`) are strictly capped at **512 KB** via `UploadGuard` to prevent denial-of-service memory exhaustion.
