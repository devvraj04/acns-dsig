package com.acns.dsig.core.benchmark;

import com.acns.dsig.core.api.HashResult;
import com.acns.dsig.core.api.ResultCode;
import com.acns.dsig.core.api.TrustLookup;
import com.acns.dsig.core.api.TrustStatus;
import com.acns.dsig.core.api.VerificationResult;
import com.acns.dsig.core.crypto.HashService;
import com.acns.dsig.core.crypto.SignatureService;
import com.acns.dsig.core.format.EnvelopeCodec;
import com.acns.dsig.core.keys.KeyService;
import com.acns.dsig.core.sign.SigningService;
import com.acns.dsig.core.trust.TrustPolicy;
import com.acns.dsig.core.verify.VerificationService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Performance benchmarking suite for RSA-3072 PSS Key Generation, Signing, and Verification.
 *
 * Complementary to Devraj's HashBenchmarkTest (which profiles streaming SHA-256).
 *
 * Owned by: Simrit Kaur (Member 10) - QA, CI/CD & Performance Infrastructure.
 */
public class CryptoBenchmarkTest {

    private static KeyService keyService;
    private static SigningService signingService;
    private static VerificationService verificationService;
    private static KeyService.GeneratedKeyPair keyPair;
    private static byte[] payloadBytes;
    private static String signedEnvelopeJson;
    private static TrustPolicy trustPolicy;

    @BeforeAll
    static void setUp() throws Exception {
        keyService = new KeyService();
        HashService hashService = new HashService();
        SignatureService signatureService = new SignatureService();
        EnvelopeCodec envelopeCodec = new EnvelopeCodec();

        signingService = new SigningService(hashService, signatureService, envelopeCodec);
        verificationService = new VerificationService(hashService, signatureService, envelopeCodec);

        keyPair = keyService.generateKeyPair();
        payloadBytes = "Official legal document for RSA-PSS performance profiling.".getBytes(StandardCharsets.UTF_8);

        SigningService.SignResult signResult = signingService.sign(
                new ByteArrayInputStream(payloadBytes),
                "benchmark-doc.txt",
                keyPair.keyPair().getPrivate(),
                keyPair.keyPair().getPublic(),
                "Benchmarker"
        );
        signedEnvelopeJson = signResult.envelopeJson();

        TrustLookup trustLookup = new TrustLookup() {
            @Override
            public TrustStatus getTrustStatus(String fingerprint) {
                return TrustStatus.TRUSTED;
            }

            @Override
            public Optional<String> getSignerLabel(String fingerprint) {
                return Optional.of("Benchmarker");
            }
        };
        trustPolicy = new TrustPolicy(trustLookup);
    }

    @Test
    @DisplayName("Benchmark RSA-3072 Key Pair Generation Latency")
    void benchmarkKeyGeneration() {
        // Warmup
        for (int i = 0; i < 3; i++) {
            keyService.generateKeyPair();
        }

        int iterations = 10;
        long start = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            KeyService.GeneratedKeyPair kp = keyService.generateKeyPair();
            assertNotNull(kp);
        }
        long durationNs = System.nanoTime() - start;

        double totalMs = durationNs / 1_000_000.0;
        double avgMs = totalMs / iterations;

        System.out.printf("[BENCHMARK - RSA-3072 KeyGen] %d keypairs in %.2f ms | Avg: %.2f ms/keypair%n",
                iterations, totalMs, avgMs);
    }

    @Test
    @DisplayName("Benchmark RSASSA-PSS Signing Latency & Throughput")
    void benchmarkSigning() throws Exception {
        // Warmup
        for (int i = 0; i < 5; i++) {
            signingService.sign(
                    new ByteArrayInputStream(payloadBytes),
                    "benchmark-doc.txt",
                    keyPair.keyPair().getPrivate(),
                    keyPair.keyPair().getPublic(),
                    "Benchmarker"
            );
        }

        int iterations = 50;
        long start = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            SigningService.SignResult res = signingService.sign(
                    new ByteArrayInputStream(payloadBytes),
                    "benchmark-doc.txt",
                    keyPair.keyPair().getPrivate(),
                    keyPair.keyPair().getPublic(),
                    "Benchmarker"
            );
            assertNotNull(res);
        }
        long durationNs = System.nanoTime() - start;

        double totalMs = durationNs / 1_000_000.0;
        double avgMs = totalMs / iterations;
        double opsPerSec = (iterations / (durationNs / 1_000_000_000.0));

        System.out.printf("[BENCHMARK - RSA-PSS Sign] %d operations in %.2f ms | Avg: %.2f ms/sign | Throughput: %.2f ops/sec%n",
                iterations, totalMs, avgMs, opsPerSec);
    }

    @Test
    @DisplayName("Benchmark Full Verification Pipeline Latency & Throughput")
    void benchmarkVerification() throws Exception {
        // Warmup
        for (int i = 0; i < 10; i++) {
            verificationService.verify(new ByteArrayInputStream(payloadBytes), signedEnvelopeJson, trustPolicy);
        }

        int iterations = 100;
        long start = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            VerificationResult res = verificationService.verify(
                    new ByteArrayInputStream(payloadBytes),
                    signedEnvelopeJson,
                    trustPolicy
            );
            assertEquals(ResultCode.VALID_TRUSTED, res.resultCode());
        }
        long durationNs = System.nanoTime() - start;

        double totalMs = durationNs / 1_000_000.0;
        double avgMs = totalMs / iterations;
        double opsPerSec = (iterations / (durationNs / 1_000_000_000.0));

        System.out.printf("[BENCHMARK - RSA-PSS Verify] %d operations in %.2f ms | Avg: %.2f ms/verify | Throughput: %.2f ops/sec%n",
                iterations, totalMs, avgMs, opsPerSec);
    }
}
