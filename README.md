# ACNS-DSIG: Secure Digital Document Authentication & Integrity Verification

> **Course / Subject:** Applied Cryptography and Network Security (CNS / ACNS-DC)  
> **Architecture:** Pure Java Cryptographic Core + Picocli CLI + Spring Boot 3 Web Application  
> **Cryptographic Suite:** RSA-3072, RSASSA-PSS, SHA-256, PBES2 AES-256 Key Storage, Hash-Chained Audit

---

## 1. Project Overview
Digital documents (PDFs, contracts, invoices, code artifacts) exchanged across insecure communication channels such as email, USB, or cloud storage can be altered or forged. This project implements a comprehensive, production-grade cryptographic system providing:
1. **Integrity:** Streaming SHA-256 verification detects single-byte modifications.
2. **Cryptographic Origin Authentication:** RSA-3072 with RSASSA-PSS and domain separation proves private-key ownership.
3. **Explicit Signer Trust:** Out-of-band SHA-256 public-key fingerprint pinning stops public-key substitution attacks.
4. **Auditability & Non-Repudiation:** Tamper-evident, forward hash-chained audit logging (`entry_hash = SHA-256(...)`).
5. **Transport Security:** Web communication protected with TLS 1.3, CSRF tokens, strict security headers, and rate limiting.

---

## 2. Repository Structure

```text
acns-dsig/
├── pom.xml                                   (parent, dependencyManagement)      [Simrit]
├── mvnw, mvnw.cmd, .mvn/                     (Maven wrapper)                     [Simrit]
├── .github/workflows/ci.yml                                                      [Simrit]
├── .gitignore, README.md                                                         [Simrit]
│
├── dsig-core/                                (plain Java, NO Spring)
│   └── src/main/java/com/acns/dsig/core/
│       ├── api/                              ← FROZEN CONTRACTS (all 10 members)
│       │   ├── HashResult.java  TrustStatus.java  TrustLookup.java
│       │   ├── VerificationResult.java  ResultCode.java                          [Deven]
│       ├── crypto/
│       │   ├── HashService.java                                                  [Devraj]
│       │   ├── ConstantTime.java                                                 [Devraj]
│       │   ├── SignatureService.java                                             [Tanmay]
│       │   └── CryptoConfig.java             (RSA-3072, PSS params, LABEL)       [Tanmay]
│       ├── keys/
│       │   ├── KeyService.java                                                   [Atharv]
│       │   ├── KeyStorage.java               (encrypted PKCS#8 + PEM)            [Atharv]
│       │   ├── Fingerprint.java                                                  [Atharv]
│       │   └── KeyStatus.java                (ACTIVE/RETIRED/REVOKED)            [Atharv]
│       ├── format/
│       │   ├── Manifest.java  Envelope.java                                      [Parth]
│       │   ├── EnvelopeCodec.java            (strict parse, dup-key reject)      [Parth]
│       │   └── FormatLimits.java                                                 [Parth]
│       ├── sign/SigningService.java                                              [Tanmay]
│       ├── verify/VerificationService.java                                       [Deven]
│       ├── trust/TrustPolicy.java                                                [Deven]
│       └── error/DsigException.java (+ subclasses)                               [Deven]
│   └── src/test/java/...                     (unit tests per module)
│
├── dsig-cli/
│   └── src/main/java/com/acns/dsig/cli/
│       ├── DsigCli.java                      (picocli root)                      [Devraj]
│       ├── KeygenCommand.java  SignCommand.java  VerifyCommand.java
│       ├── FingerprintCommand.java  TrustAddCommand.java  TrustListCommand.java
│       └── FileTrustStore.java               (implements TrustLookup)            [Devraj + Atharv]
│
├── dsig-server/
│   └── src/main/java/com/acns/dsig/server/
│       ├── DsigServerApplication.java                                            [Nityanand]
│       ├── persistence/                                                          [Nityanand]
│       │   ├── UserRepository  KeyPairRepository  TrustedSignerRepository
│       │   ├── VerificationRecordRepository  AuditLogRepository
│       │   └── AuditChainService.java        (hash chain + verify-chain)
│       ├── service/                                                              [Nityanand]
│       │   ├── UserService  KeyManagementService  TrustStoreService (impl TrustLookup)
│       │   ├── SigningAppService  VerificationAppService  HistoryService
│       ├── security/                                                             [Diyaan]
│       │   ├── SecurityConfig  RateLimitFilter  UploadGuard
│       │   ├── LoginAttemptService  SecurityHeadersConfig  GlobalExceptionHandler
│       └── web/
│           ├── AuthController  DashboardController                               [Nityanand]
│           ├── KeyController  SignController                                     [KVS]
│           ├── VerifyController  TrustController  HistoryController              [Jay]
│           ├── AuditController (admin)                                           [Jay]
│           └── ApiController (/api/health etc.)                                  [Nityanand]
│   └── src/main/resources/
│       ├── application.yml  (+ application-demo.yml)                             [Diyaan]
│       ├── db/migration/V1__init.sql  V2__audit.sql                              [Nityanand]
│       ├── templates/ login register dashboard keys sign verify result trust history audit   [KVS / Jay]
│       ├── templates/fragments/ layout, header, flash                            [KVS + Jay]
│       └── static/css/app.css  static/js/{sign.js, verify.js}                    [KVS / Jay]
│
├── docs/
│   ├── changes.md                            (detailed log of all repository modifications)
│   ├── report.md                             (engineering rationale and implementation report)
│   ├── FORMAT.md                             (detached envelope & manifest specification)
│   ├── THREAT_MODEL.md                       (threat matrix & security countermeasures)
│   ├── diagrams/                             (architecture & sequence Mermaid diagrams)
│   ├── benchmark/                            (performance benchmarks & charts)
│   └── report/                               (final documentation archive)
├── scripts/                                  (gen-cert, run-demo, fuzz, bench)   [Simrit / Diyaan]
├── test-data/                                (sample files & test fixtures)      [Simrit]
└── runtime/                                  (git-ignored H2, keys/, tls/, tmp uploads)
```

---

## 3. Team Work Package Allocation (10 Members)

| Member | Work Package | Primary Technical Ownership |
|---|---|---|
| **Deven Thakkar** | Verification Engine & Result Model | `VerificationService`, `VerificationResult`, `ResultCode`, `TrustPolicy`, `DsigException` |
| **Devraj Sundrani** | Document Processing & SHA-256 Hashing | `HashService`, `ConstantTime`, `DsigCli`, CLI commands |
| **Tanmay Vishwakarma** | RSA-PSS Signature Engine | `SignatureService`, `CryptoConfig`, `SigningService` |
| **Atharv Vedant** | Key Generation & Secure Key Storage | `KeyService`, `KeyStorage` (PBES2 AES-256), `Fingerprint`, `KeyStatus` |
| **Parth Zala** | Manifest, Envelope & Strict Codec | `Manifest`, `Envelope`, `EnvelopeCodec`, `FormatLimits`, `FORMAT.md` |
| **Nityanand Upadhyay**| Users, Database & Audit Chain | JPA Entities, Repositories, `AuditChainService`, `UserService`, `HistoryService` |
| **KVS Varshith** | Signing Web Interface & Key UI | `KeyController`, `SignController`, `keys.html`, `sign.html`, `sign.js` |
| **Jay Pandya** | Verification Web Interface & Trust UI | `VerifyController`, `TrustController`, `AuditController`, `verify.html`, `result.html`, `trust.html` |
| **Diyaan Rambhia** | Network & Application Security | `SecurityConfig`, `RateLimitFilter`, `UploadGuard`, `THREAT_MODEL.md`, `application.yml` |
| **Simrit Kaur** | QA, CI/CD, Documentation & Demo | GitHub Actions CI, Maven Wrapper, scripts, test fixtures, report coordination |

---

## 4. Quickstart & Build Instructions

### Prerequisites
- **Java 21 LTS** or newer (installed and on PATH).
- **Maven Wrapper** (`mvnw` / `mvnw.cmd`) is included in the project; no manual Maven install required.

### 4.1 Build Entire System
```bash
# On Linux / macOS:
./mvnw clean package

# On Windows (Command Prompt / PowerShell):
.\mvnw.cmd clean package
```

### 4.2 Run Local Offline CLI
```bash
# 1. Generate key pair
java -jar dsig-cli/target/dsig-cli-1.0.0-SNAPSHOT.jar keygen -o mykey -p secret123

# 2. Pin fingerprint
java -jar dsig-cli/target/dsig-cli-1.0.0-SNAPSHOT.jar trust-add <FINGERPRINT> -l "Alice"

# 3. Sign document
java -jar dsig-cli/target/dsig-cli-1.0.0-SNAPSHOT.jar sign document.pdf -k mykey.pk8 --pub mykey.pub.pem -p secret123

# 4. Verify document
java -jar dsig-cli/target/dsig-cli-1.0.0-SNAPSHOT.jar verify document.pdf
```

### 4.3 Run Spring Boot Web Server
```bash
# Run server (default port 8443 or demo profile on 8080):
./mvnw -pl dsig-server spring-boot:run -Dspring-boot.run.profiles=demo
```
Navigate to `http://localhost:8080` in your web browser.

---

## 5. Automated Testing, Benchmarking & Demo Scripts

### 5.1 Run Full Test Suite
```bash
# Execute all unit, integration, and fuzz tests across all modules:
./mvnw test
# Windows:
.\mvnw.cmd test
```

### 5.2 Microbenchmark Suite (`scripts/bench.sh`)
Profiles streaming SHA-256 hashing throughput, RSA-3072 key generation latency, and RSASSA-PSS signing and verification throughput:
```bash
bash scripts/bench.sh
# Or via Maven directly:
./mvnw test "-Dtest=HashBenchmarkTest,CryptoBenchmarkTest" "-Dsurefire.failIfNoSpecifiedTests=false"
```

### 5.3 Parser & Envelope Fuzz Suite (`scripts/fuzz.sh`)
Tests envelope and manifest deserialization resilience against random bitflips, truncated payloads, corrupt Base64, and boundary conditions:
```bash
bash scripts/fuzz.sh
# Or via Maven directly:
./mvnw test "-Dtest=EnvelopeFuzzTest" "-Dsurefire.failIfNoSpecifiedTests=false"
```

### 5.4 End-to-End Demo Script (`scripts/run-demo.*`)
Executes the full automated workflow (RSA-3072 keygen, fingerprint calculation, trust store pinning, signing, legitimate verification, and tampered document detection):
```bash
# On Linux / macOS:
bash scripts/run-demo.sh

# On Windows (PowerShell):
powershell -ExecutionPolicy Bypass -File scripts/run-demo.ps1
```
