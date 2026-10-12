package com.acns.dsig.server.web;

import com.acns.dsig.core.crypto.SignatureService;
import com.acns.dsig.core.keys.KeyService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {

    private final SignatureService signatureService = new SignatureService();
    private final KeyService keyService = new KeyService();

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        return ResponseEntity.ok(Map.of(
                "status", "UP",
                "system", "ACNS-DSIG Server",
                "timestamp", Instant.now().toString(),
                "algorithms", Map.of(
                        "hash", "SHA-256",
                        "signature", "RSASSA-PSS-SHA256-MGF1SHA256-S32",
                        "rsaModulusBits", 3072
                )
        ));
    }

    /**
     * Diagnostic endpoint exposing the active RSA-PSS Digital Signature Engine configuration.
     * Work Package: Cryptographic Signature Subsystem.
     */
    @GetMapping("/signature-engine")
    public ResponseEntity<SignatureService.SignatureEngineInfo> getSignatureEngineInfo() {
        return ResponseEntity.ok(signatureService.describeEngine());
    }

    /**
     * Executes an on-demand in-memory cryptographic benchmark measuring live RSASSA-PSS
     * signing and verification latency and throughput without mock or hardcoded numbers.
     */
    @GetMapping("/signature-engine/benchmark")
    public ResponseEntity<Map<String, Object>> benchmarkSignatureEngine() {
        KeyPair kp = keyService.generateKeyPair().keyPair();
        byte[] samplePayload = "{\"benchmark\":\"acns-dsig-live-engine-test\"}".getBytes(StandardCharsets.UTF_8);

        // Warmup JIT compiler
        for (int i = 0; i < 5; i++) {
            byte[] s = signatureService.signManifest(kp.getPrivate(), samplePayload);
            signatureService.verifyManifest(kp.getPublic(), samplePayload, s);
        }

        int iterations = 25;
        long startSign = System.nanoTime();
        byte[][] sigs = new byte[iterations][];
        for (int i = 0; i < iterations; i++) {
            sigs[i] = signatureService.signManifest(kp.getPrivate(), samplePayload);
        }
        long signDurationNs = System.nanoTime() - startSign;

        long startVerify = System.nanoTime();
        boolean allValid = true;
        for (int i = 0; i < iterations; i++) {
            if (!signatureService.verifyManifest(kp.getPublic(), samplePayload, sigs[i])) {
                allValid = false;
            }
        }
        long verifyDurationNs = System.nanoTime() - startVerify;

        double signAvgMs = (signDurationNs / 1_000_000.0) / iterations;
        double signOpsSec = iterations / (signDurationNs / 1_000_000_000.0);
        double verifyAvgMs = (verifyDurationNs / 1_000_000.0) / iterations;
        double verifyOpsSec = iterations / (verifyDurationNs / 1_000_000_000.0);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("iterations", iterations);
        response.put("allSignaturesValid", allValid);
        response.put("signLatencyMs", Math.round(signAvgMs * 100.0) / 100.0);
        response.put("signThroughputOpsSec", Math.round(signOpsSec * 10.0) / 10.0);
        response.put("verifyLatencyMs", Math.round(verifyAvgMs * 100.0) / 100.0);
        response.put("verifyThroughputOpsSec", Math.round(verifyOpsSec * 10.0) / 10.0);
        response.put("keyBits", 3072);
        response.put("saltLengthBytes", 32);
        response.put("signatureSizeBytes", sigs[0].length);
        response.put("scheme", "RSASSA-PSS");
        response.put("timestamp", Instant.now().toString());

        return ResponseEntity.ok(response);
    }
}
