package com.acns.dsig.core.verify;

import com.acns.dsig.core.api.HashResult;
import com.acns.dsig.core.api.ResultCode;
import com.acns.dsig.core.api.TrustLookup;
import com.acns.dsig.core.api.TrustStatus;
import com.acns.dsig.core.api.VerificationResult;
import com.acns.dsig.core.crypto.HashService;
import com.acns.dsig.core.error.CorruptedPackageException;
import com.acns.dsig.core.error.DocumentReadException;
import com.acns.dsig.core.error.KeyValidationException;
import com.acns.dsig.core.trust.TrustPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Exhaustive unit test suite for VerificationService and the 9-state decision tree.
 *
 * Owned by: Deven Thakkar (Member 1)
 * Work Package: Verification Engine & Result Model
 *
 * Uses real HashService from Devraj Sundrani and targeted test doubles for pending dependencies.
 */
public class VerificationServiceTest {

    private static final String VALID_FINGERPRINT = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";
    private static final String DEFAULT_DOC_CONTENT = "Confidential Contract Payload for Verification";

    private HashService hashService;
    private PublicKey mockPublicKey;

    @BeforeEach
    void setUp() {
        hashService = new HashService();
        mockPublicKey = new PublicKey() {
            @Override
            public String getAlgorithm() {
                return "RSA";
            }
            @Override
            public String getFormat() {
                return "X.509";
            }
            @Override
            public byte[] getEncoded() {
                return new byte[]{1, 2, 3, 4};
            }
        };
    }

    private VerificationPackage createStandardPackage(byte[] docBytes) {
        HashResult hash = hashService.hashBytes(docBytes);
        return new VerificationPackage(
                "ACNS-DSIG",
                1,
                "{\"v\":1,\"mock\":\"manifest\"}".getBytes(StandardCharsets.UTF_8),
                new byte[]{0x10, 0x20, 0x30, 0x40},
                "MOCK_PUBLIC_KEY_BASE64",
                1,
                "contract.pdf",
                docBytes.length,
                "SHA-256",
                hash.base64Digest(),
                "RSASSA-PSS-SHA256-MGF1SHA256-S32",
                VALID_FINGERPRINT,
                Instant.parse("2026-10-10T12:00:00Z"),
                "bm9uY2VfdmFsdWVfMTIz",
                "Alice Legal Signer"
        );
    }

    private PublicKeyValidator createDefaultKeyValidator() {
        return new PublicKeyValidator() {
            @Override
            public PublicKey parsePublicKey(String encodedPublicKey) {
                return mockPublicKey;
            }
            @Override
            public void validatePublicKey(PublicKey publicKey) {
                // Accepts valid 3072-bit mock key
            }
            @Override
            public String calculateFingerprint(PublicKey publicKey) {
                return VALID_FINGERPRINT;
            }
        };
    }

    private PackageDecoder createPassthroughDecoder(VerificationPackage pkg) {
        return payload -> pkg;
    }

    @Nested
    @DisplayName("1. Happy Path & Trust State Transitions")
    class HappyPathAndTrustTests {

        @Test
        @DisplayName("Returns VALID_TRUSTED when signature valid, document intact, and signer trusted")
        void testValidTrusted() {
            byte[] docBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationPackage pkg = createStandardPackage(docBytes);

            ManifestSignatureVerifier sigVerifier = (key, manifest, sig) -> true;
            PublicKeyValidator keyValidator = createDefaultKeyValidator();
            PackageDecoder decoder = createPassthroughDecoder(pkg);

            VerificationService service = new VerificationService(hashService, sigVerifier, keyValidator, decoder);

            TrustLookup trustLookup = new TrustLookup() {
                @Override
                public TrustStatus getTrustStatus(String fingerprint) {
                    return VALID_FINGERPRINT.equalsIgnoreCase(fingerprint) ? TrustStatus.TRUSTED : TrustStatus.UNKNOWN;
                }
                @Override
                public Optional<String> getSignerLabel(String fingerprint) {
                    return Optional.of("Alice Legal Signer");
                }
            };

            VerificationResult result = service.verify(new ByteArrayInputStream(docBytes), pkg, new TrustPolicy(trustLookup));

            assertEquals(ResultCode.VALID_TRUSTED, result.resultCode());
            assertTrue(result.isValidTrusted());
            assertFalse(result.isTampered());
            assertEquals(TrustStatus.TRUSTED, result.trustStatus());
            assertEquals("contract.pdf", result.documentName());
            assertEquals(docBytes.length, result.documentSize());
            assertEquals(VALID_FINGERPRINT, result.keyFingerprint());
            assertEquals("Alice Legal Signer", result.signerName());
            assertNotNull(result.recomputedDocHash());
            assertEquals(result.signedDocHash(), result.recomputedDocHash());
        }

        @Test
        @DisplayName("Returns VALID_UNTRUSTED_SIGNER when signature valid and document intact but key not in trust store")
        void testValidUntrustedSigner() {
            byte[] docBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationPackage pkg = createStandardPackage(docBytes);

            ManifestSignatureVerifier sigVerifier = (key, manifest, sig) -> true;
            PublicKeyValidator keyValidator = createDefaultKeyValidator();
            PackageDecoder decoder = createPassthroughDecoder(pkg);

            VerificationService service = new VerificationService(hashService, sigVerifier, keyValidator, decoder);

            TrustLookup emptyLookup = new TrustLookup() {
                @Override
                public TrustStatus getTrustStatus(String fingerprint) {
                    return TrustStatus.UNKNOWN;
                }
                @Override
                public Optional<String> getSignerLabel(String fingerprint) {
                    return Optional.empty();
                }
            };

            VerificationResult result = service.verify(new ByteArrayInputStream(docBytes), pkg, new TrustPolicy(emptyLookup));

            assertEquals(ResultCode.VALID_UNTRUSTED_SIGNER, result.resultCode());
            assertFalse(result.isValidTrusted());
            assertFalse(result.isTampered());
            assertEquals(TrustStatus.UNKNOWN, result.trustStatus());
        }

        @Test
        @DisplayName("Returns VALID_UNTRUSTED_SIGNER when TrustPolicy is null")
        void testValidNullTrustPolicy() {
            byte[] docBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationPackage pkg = createStandardPackage(docBytes);

            VerificationService service = new VerificationService(
                    hashService,
                    (k, m, s) -> true,
                    createDefaultKeyValidator(),
                    createPassthroughDecoder(pkg)
            );

            VerificationResult result = service.verify(new ByteArrayInputStream(docBytes), pkg, null);

            assertEquals(ResultCode.VALID_UNTRUSTED_SIGNER, result.resultCode());
            assertFalse(result.isValidTrusted());
        }

        @Test
        @DisplayName("Returns REVOKED_OR_RETIRED_KEY when key status is REVOKED")
        void testRevokedKey() {
            byte[] docBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationPackage pkg = createStandardPackage(docBytes);

            VerificationService service = new VerificationService(
                    hashService,
                    (k, m, s) -> true,
                    createDefaultKeyValidator(),
                    createPassthroughDecoder(pkg)
            );

            TrustLookup lookup = new TrustLookup() {
                @Override
                public TrustStatus getTrustStatus(String fingerprint) {
                    return TrustStatus.REVOKED;
                }
                @Override
                public Optional<String> getSignerLabel(String fingerprint) {
                    return Optional.of("Compromised Key");
                }
            };

            VerificationResult result = service.verify(new ByteArrayInputStream(docBytes), pkg, new TrustPolicy(lookup));

            assertEquals(ResultCode.REVOKED_OR_RETIRED_KEY, result.resultCode());
            assertEquals(TrustStatus.REVOKED, result.trustStatus());
            assertFalse(result.isValidTrusted());
        }

        @Test
        @DisplayName("Returns REVOKED_OR_RETIRED_KEY when key is RETIRED under default strict policy")
        void testRetiredKeyStrictPolicy() {
            byte[] docBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationPackage pkg = createStandardPackage(docBytes);

            VerificationService service = new VerificationService(
                    hashService,
                    (k, m, s) -> true,
                    createDefaultKeyValidator(),
                    createPassthroughDecoder(pkg)
            );

            TrustLookup lookup = new TrustLookup() {
                @Override
                public TrustStatus getTrustStatus(String fingerprint) {
                    return TrustStatus.RETIRED;
                }
                @Override
                public Optional<String> getSignerLabel(String fingerprint) {
                    return Optional.of("Old Retired Key");
                }
            };

            VerificationResult result = service.verify(new ByteArrayInputStream(docBytes), pkg, new TrustPolicy(lookup, false));

            assertEquals(ResultCode.REVOKED_OR_RETIRED_KEY, result.resultCode());
            assertEquals(TrustStatus.RETIRED, result.trustStatus());
            assertFalse(result.isValidTrusted());
        }

        @Test
        @DisplayName("Returns VALID_TRUSTED when key is RETIRED and policy has administrative allowRetiredKeys override enabled")
        void testRetiredKeyAdministrativeOverride() {
            byte[] docBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationPackage pkg = createStandardPackage(docBytes);

            VerificationService service = new VerificationService(
                    hashService,
                    (k, m, s) -> true,
                    createDefaultKeyValidator(),
                    createPassthroughDecoder(pkg)
            );

            TrustLookup lookup = new TrustLookup() {
                @Override
                public TrustStatus getTrustStatus(String fingerprint) {
                    return TrustStatus.RETIRED;
                }
                @Override
                public Optional<String> getSignerLabel(String fingerprint) {
                    return Optional.of("Old Retired Key");
                }
            };

            VerificationResult result = service.verify(new ByteArrayInputStream(docBytes), pkg, new TrustPolicy(lookup, true));

            assertEquals(ResultCode.VALID_TRUSTED, result.resultCode());
            assertTrue(result.isValidTrusted());
            assertEquals(TrustStatus.RETIRED, result.trustStatus());
        }
    }

    @Nested
    @DisplayName("2. Document Tampering Detection")
    class DocumentTamperingTests {

        @Test
        @DisplayName("Returns DOCUMENT_TAMPERED when document bytes are modified")
        void testDocumentContentModified() {
            byte[] originalBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationPackage pkg = createStandardPackage(originalBytes);

            VerificationService service = new VerificationService(
                    hashService,
                    (k, m, s) -> true,
                    createDefaultKeyValidator(),
                    createPassthroughDecoder(pkg)
            );

            byte[] tamperedBytes = "Altered/Modified Document Content".getBytes(StandardCharsets.UTF_8);
            VerificationResult result = service.verify(new ByteArrayInputStream(tamperedBytes), pkg, null);

            assertEquals(ResultCode.DOCUMENT_TAMPERED, result.resultCode());
            assertTrue(result.isTampered());
            assertNotNull(result.signedDocHash());
            assertNotNull(result.recomputedDocHash());
            assertNotEquals(result.signedDocHash(), result.recomputedDocHash());
            assertEquals(tamperedBytes.length, result.documentSize());
        }

        @Test
        @DisplayName("Returns DOCUMENT_TAMPERED when received document size differs from declared manifest size")
        void testDocumentSizeMismatch() {
            byte[] originalBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            HashResult hash = hashService.hashBytes(originalBytes);

            // Package declaring size 99999 instead of actual content length
            VerificationPackage pkg = new VerificationPackage(
                    "ACNS-DSIG", 1,
                    new byte[]{1, 2}, new byte[]{3, 4}, "PUB", 1,
                    "doc.txt", 99999L, "SHA-256", hash.base64Digest(),
                    "RSASSA-PSS-SHA256-MGF1SHA256-S32", VALID_FINGERPRINT,
                    Instant.now(), "nonce", "Signer"
            );

            VerificationService service = new VerificationService(
                    hashService,
                    (k, m, s) -> true,
                    createDefaultKeyValidator(),
                    createPassthroughDecoder(pkg)
            );

            VerificationResult result = service.verify(new ByteArrayInputStream(originalBytes), pkg, null);

            assertEquals(ResultCode.DOCUMENT_TAMPERED, result.resultCode());
            assertTrue(result.isTampered());
        }

        @Test
        @DisplayName("Returns DOCUMENT_TAMPERED when received document is empty (0 bytes) but manifest expects data")
        void testEmptyReceivedDocument() {
            byte[] originalBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationPackage pkg = createStandardPackage(originalBytes);

            VerificationService service = new VerificationService(
                    hashService,
                    (k, m, s) -> true,
                    createDefaultKeyValidator(),
                    createPassthroughDecoder(pkg)
            );

            VerificationResult result = service.verify(new ByteArrayInputStream(new byte[0]), pkg, null);

            assertEquals(ResultCode.DOCUMENT_TAMPERED, result.resultCode());
            assertTrue(result.isTampered());
            assertEquals(0L, result.documentSize());
            assertTrue(result.message().contains("empty"));
        }
    }

    @Nested
    @DisplayName("3. Cryptographic Signature & Verification Order")
    class SignatureAndOrderingTests {

        @Test
        @DisplayName("Returns INVALID_SIGNATURE when RSASSA-PSS signature verification fails")
        void testInvalidSignature() {
            byte[] docBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationPackage pkg = createStandardPackage(docBytes);

            // Signature verifier explicitly returns false
            ManifestSignatureVerifier failingVerifier = (k, m, s) -> false;

            VerificationService service = new VerificationService(
                    hashService,
                    failingVerifier,
                    createDefaultKeyValidator(),
                    createPassthroughDecoder(pkg)
            );

            VerificationResult result = service.verify(new ByteArrayInputStream(docBytes), pkg, null);

            assertEquals(ResultCode.INVALID_SIGNATURE, result.resultCode());
            assertFalse(result.isValidTrusted());
            assertNull(result.recomputedDocHash(), "Must not compute or expose recomputed hash when manifest signature fails");
            assertEquals(TrustStatus.UNKNOWN, result.trustStatus());
            assertEquals(VALID_FINGERPRINT, result.keyFingerprint());
            assertEquals("contract.pdf", result.documentName());
        }

        @Test
        @DisplayName("Verifies manifest signature FIRST before streaming or trusting document hash")
        void testVerificationOrdering() {
            byte[] docBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationPackage pkg = createStandardPackage(docBytes);

            AtomicBoolean streamWasRead = new AtomicBoolean(false);
            InputStream trackingStream = new InputStream() {
                private final InputStream delegate = new ByteArrayInputStream(docBytes);
                @Override
                public int read() throws IOException {
                    streamWasRead.set(true);
                    return delegate.read();
                }
            };

            // Failing signature verifier
            ManifestSignatureVerifier failingVerifier = (k, m, s) -> false;

            VerificationService service = new VerificationService(
                    hashService,
                    failingVerifier,
                    createDefaultKeyValidator(),
                    createPassthroughDecoder(pkg)
            );

            VerificationResult result = service.verify(trackingStream, pkg, null);

            assertEquals(ResultCode.INVALID_SIGNATURE, result.resultCode());
            assertFalse(streamWasRead.get(), "Security violation: Document stream must not be read if manifest signature is invalid!");
        }
    }

    @Nested
    @DisplayName("4. Public Key & KeyId Validation")
    class KeyValidationTests {

        @Test
        @DisplayName("Returns INVALID_KEY when key violates RSA constraints without leaking internal exception message")
        void testKeyConstraintFailure() {
            byte[] docBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationPackage pkg = createStandardPackage(docBytes);

            String distinctiveDiagnostic = "INTERNAL_DIAGNOSTIC_TRACE_KEY_MODULUS_2048";
            PublicKeyValidator constraintFailingValidator = new PublicKeyValidator() {
                @Override
                public PublicKey parsePublicKey(String encodedPublicKey) {
                    return mockPublicKey;
                }
                @Override
                public void validatePublicKey(PublicKey publicKey) {
                    throw new KeyValidationException(distinctiveDiagnostic);
                }
                @Override
                public String calculateFingerprint(PublicKey publicKey) {
                    return VALID_FINGERPRINT;
                }
            };

            VerificationService service = new VerificationService(
                    hashService,
                    (k, m, s) -> true,
                    constraintFailingValidator,
                    createPassthroughDecoder(pkg)
            );

            VerificationResult result = service.verify(new ByteArrayInputStream(docBytes), pkg, null);

            assertEquals(ResultCode.INVALID_KEY, result.resultCode());
            assertEquals("Public key validation failed.", result.message());
            assertFalse(result.message().contains(distinctiveDiagnostic));
        }

        @Test
        @DisplayName("Returns INVALID_KEY when public key parsing fails without leaking internal exception message")
        void testKeyParsingFailure() {
            byte[] docBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationPackage pkg = createStandardPackage(docBytes);

            String distinctiveInternalDetail = "INTERNAL_ASN1_PARSER_OFFSET_0x7F_CORRUPTED";
            PublicKeyValidator parseFailingValidator = new PublicKeyValidator() {
                @Override
                public PublicKey parsePublicKey(String encodedPublicKey) {
                    throw new KeyValidationException(distinctiveInternalDetail);
                }
                @Override
                public void validatePublicKey(PublicKey publicKey) {}
                @Override
                public String calculateFingerprint(PublicKey publicKey) {
                    return VALID_FINGERPRINT;
                }
            };

            VerificationService service = new VerificationService(
                    hashService,
                    (k, m, s) -> true,
                    parseFailingValidator,
                    createPassthroughDecoder(pkg)
            );

            VerificationResult result = service.verify(new ByteArrayInputStream(docBytes), pkg, null);

            assertEquals(ResultCode.INVALID_KEY, result.resultCode());
            assertEquals("Public key parsing failed.", result.message());
            assertFalse(result.message().contains(distinctiveInternalDetail));
        }

        @Test
        @DisplayName("Returns INVALID_KEY when public key fingerprint does not match manifest keyId")
        void testKeyFingerprintMismatch() {
            byte[] docBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationPackage pkg = createStandardPackage(docBytes);

            PublicKeyValidator mismatchValidator = new PublicKeyValidator() {
                @Override
                public PublicKey parsePublicKey(String encodedPublicKey) {
                    return mockPublicKey;
                }
                @Override
                public void validatePublicKey(PublicKey publicKey) {}
                @Override
                public String calculateFingerprint(PublicKey publicKey) {
                    return "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
                }
            };

            VerificationService service = new VerificationService(
                    hashService,
                    (k, m, s) -> true,
                    mismatchValidator,
                    createPassthroughDecoder(pkg)
            );

            VerificationResult result = service.verify(new ByteArrayInputStream(docBytes), pkg, null);

            assertEquals(ResultCode.INVALID_KEY, result.resultCode());
            assertTrue(result.message().contains("does not match manifest keyId"));
        }
    }

    @Nested
    @DisplayName("5. Format & Algorithm Allow-List Validation")
    class FormatAndAlgorithmTests {

        @Test
        @DisplayName("Returns UNSUPPORTED_FORMAT for invalid envelope format protocol identifier")
        void testUnsupportedEnvelopeFormat() {
            byte[] docBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationPackage pkg = new VerificationPackage(
                    "UNKNOWN-PROTOCOL", 1,
                    new byte[]{1}, new byte[]{2}, "PUB", 1,
                    "doc.txt", 100L, "SHA-256", "AAAA",
                    "RSASSA-PSS-SHA256-MGF1SHA256-S32", VALID_FINGERPRINT,
                    Instant.now(), "nonce", "Signer"
            );

            VerificationService service = new VerificationService(
                    hashService,
                    (k, m, s) -> true,
                    createDefaultKeyValidator(),
                    createPassthroughDecoder(pkg)
            );

            VerificationResult result = service.verify(new ByteArrayInputStream(docBytes), pkg, null);
            assertEquals(ResultCode.UNSUPPORTED_FORMAT, result.resultCode());
        }

        @Test
        @DisplayName("Returns UNSUPPORTED_FORMAT for unsupported envelope version")
        void testUnsupportedEnvelopeVersion() {
            byte[] docBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationPackage pkg = new VerificationPackage(
                    "ACNS-DSIG", 99,
                    new byte[]{1}, new byte[]{2}, "PUB", 1,
                    "doc.txt", 100L, "SHA-256", "AAAA",
                    "RSASSA-PSS-SHA256-MGF1SHA256-S32", VALID_FINGERPRINT,
                    Instant.now(), "nonce", "Signer"
            );

            VerificationService service = new VerificationService(
                    hashService,
                    (k, m, s) -> true,
                    createDefaultKeyValidator(),
                    createPassthroughDecoder(pkg)
            );

            VerificationResult result = service.verify(new ByteArrayInputStream(docBytes), pkg, null);
            assertEquals(ResultCode.UNSUPPORTED_FORMAT, result.resultCode());
        }

        @Test
        @DisplayName("Returns UNSUPPORTED_FORMAT for unsupported hash algorithm")
        void testUnsupportedHashAlgorithm() {
            byte[] docBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationPackage pkg = new VerificationPackage(
                    "ACNS-DSIG", 1,
                    new byte[]{1}, new byte[]{2}, "PUB", 1,
                    "doc.txt", 100L, "SHA-512", "AAAA",
                    "RSASSA-PSS-SHA256-MGF1SHA256-S32", VALID_FINGERPRINT,
                    Instant.now(), "nonce", "Signer"
            );

            VerificationService service = new VerificationService(
                    hashService,
                    (k, m, s) -> true,
                    createDefaultKeyValidator(),
                    createPassthroughDecoder(pkg)
            );

            VerificationResult result = service.verify(new ByteArrayInputStream(docBytes), pkg, null);
            assertEquals(ResultCode.UNSUPPORTED_FORMAT, result.resultCode());
        }

        @Test
        @DisplayName("Returns UNSUPPORTED_FORMAT for unsupported signature algorithm")
        void testUnsupportedSignatureAlgorithm() {
            byte[] docBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationPackage pkg = new VerificationPackage(
                    "ACNS-DSIG", 1,
                    new byte[]{1}, new byte[]{2}, "PUB", 1,
                    "doc.txt", 100L, "SHA-256", "AAAA",
                    "SHA256withRSA", VALID_FINGERPRINT,
                    Instant.now(), "nonce", "Signer"
            );

            VerificationService service = new VerificationService(
                    hashService,
                    (k, m, s) -> true,
                    createDefaultKeyValidator(),
                    createPassthroughDecoder(pkg)
            );

            VerificationResult result = service.verify(new ByteArrayInputStream(docBytes), pkg, null);
            assertEquals(ResultCode.UNSUPPORTED_FORMAT, result.resultCode());
        }
    }

    @Nested
    @DisplayName("6. Missing Metadata & Corrupted Package")
    class MetadataAndCorruptionTests {

        @Test
        @DisplayName("Returns MISSING_METADATA when envelope components are null")
        void testMissingEnvelopeComponents() {
            byte[] docBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationPackage pkg = new VerificationPackage(
                    "ACNS-DSIG", 1,
                    null, null, null, 1,
                    "doc.txt", 100L, "SHA-256", "AAAA",
                    "RSASSA-PSS-SHA256-MGF1SHA256-S32", VALID_FINGERPRINT,
                    Instant.now(), "nonce", "Signer"
            );

            VerificationService service = new VerificationService(
                    hashService,
                    (k, m, s) -> true,
                    createDefaultKeyValidator(),
                    createPassthroughDecoder(pkg)
            );

            VerificationResult result = service.verify(new ByteArrayInputStream(docBytes), pkg, null);
            assertEquals(ResultCode.MISSING_METADATA, result.resultCode());
        }

        @Test
        @DisplayName("Returns MISSING_METADATA when manifest fields are missing or docSize <= 0")
        void testMissingManifestFields() {
            byte[] docBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationPackage pkg = new VerificationPackage(
                    "ACNS-DSIG", 1,
                    new byte[]{1}, new byte[]{2}, "PUB", 1,
                    "", 0L, "SHA-256", null,
                    "RSASSA-PSS-SHA256-MGF1SHA256-S32", VALID_FINGERPRINT,
                    Instant.now(), "nonce", "Signer"
            );

            VerificationService service = new VerificationService(
                    hashService,
                    (k, m, s) -> true,
                    createDefaultKeyValidator(),
                    createPassthroughDecoder(pkg)
            );

            VerificationResult result = service.verify(new ByteArrayInputStream(docBytes), pkg, null);
            assertEquals(ResultCode.MISSING_METADATA, result.resultCode());
        }

        @Test
        @DisplayName("Returns CORRUPTED_PACKAGE when PackageDecoder throws CorruptedPackageException")
        void testCorruptedPackageFromDecoder() {
            PackageDecoder decoder = payload -> {
                throw new CorruptedPackageException("Duplicate JSON keys detected in manifest");
            };

            VerificationService service = new VerificationService(
                    hashService,
                    (k, m, s) -> true,
                    createDefaultKeyValidator(),
                    decoder
            );

            byte[] docBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationResult result = service.verify(new ByteArrayInputStream(docBytes), "{\"bad\":\"json\"}", null);

            assertEquals(ResultCode.CORRUPTED_PACKAGE, result.resultCode());
            assertTrue(result.message().contains("Duplicate JSON keys"));
        }

        @Test
        @DisplayName("Returns CORRUPTED_PACKAGE when manifest docHash is invalid Base64")
        void testCorruptedManifestHashBase64() {
            byte[] docBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationPackage pkg = new VerificationPackage(
                    "ACNS-DSIG", 1,
                    new byte[]{1}, new byte[]{2}, "PUB", 1,
                    "doc.txt", 100L, "SHA-256", "!@#$%^&*(NOT_BASE_64)",
                    "RSASSA-PSS-SHA256-MGF1SHA256-S32", VALID_FINGERPRINT,
                    Instant.now(), "nonce", "Signer"
            );

            VerificationService service = new VerificationService(
                    hashService,
                    (k, m, s) -> true,
                    createDefaultKeyValidator(),
                    createPassthroughDecoder(pkg)
            );

            VerificationResult result = service.verify(new ByteArrayInputStream(docBytes), pkg, null);
            assertEquals(ResultCode.CORRUPTED_PACKAGE, result.resultCode());
            assertTrue(result.message().contains("Malformed Base64 document hash"));
        }
    }

    @Nested
    @DisplayName("7. I/O Failures & Defensive Error Handling")
    class IoAndDefensiveTests {

        @Test
        @DisplayName("Propagates DocumentReadException on underlying stream I/O failure without mislabeling")
        void testDocumentReadFailurePropagated() {
            byte[] docBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationPackage pkg = createStandardPackage(docBytes);

            VerificationService service = new VerificationService(
                    hashService,
                    (k, m, s) -> true,
                    createDefaultKeyValidator(),
                    createPassthroughDecoder(pkg)
            );

            InputStream faultyStream = new InputStream() {
                @Override
                public int read() throws IOException {
                    throw new IOException("Simulated disk read error");
                }
            };

            assertThrows(DocumentReadException.class, () -> service.verify(faultyStream, pkg, null));
        }

        @Test
        @DisplayName("Rejects null document stream with NullPointerException")
        void testNullDocumentStream() {
            VerificationService service = new VerificationService(
                    hashService,
                    (k, m, s) -> true,
                    createDefaultKeyValidator(),
                    createPassthroughDecoder(null)
            );

            assertThrows(NullPointerException.class, () -> service.verify((InputStream) null, "{}", null));
        }

        @Test
        @DisplayName("Path-based overload successfully verifies local document file")
        void testPathBasedOverloadSuccess(@TempDir Path tempDir) throws IOException {
            byte[] docBytes = DEFAULT_DOC_CONTENT.getBytes(StandardCharsets.UTF_8);
            VerificationPackage pkg = createStandardPackage(docBytes);

            Path docFile = tempDir.resolve("test_doc.txt");
            Files.write(docFile, docBytes);

            VerificationService service = new VerificationService(
                    hashService,
                    (k, m, s) -> true,
                    createDefaultKeyValidator(),
                    createPassthroughDecoder(pkg)
            );

            VerificationResult result = service.verify(docFile, pkg, null);
            assertEquals(ResultCode.VALID_UNTRUSTED_SIGNER, result.resultCode());
        }
    }
}
