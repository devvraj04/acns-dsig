package com.acns.dsig.cli;

import com.acns.dsig.core.api.VerificationResult;
import com.acns.dsig.core.crypto.HashService;
import com.acns.dsig.core.crypto.SignatureService;
import com.acns.dsig.core.format.EnvelopeCodec;
import com.acns.dsig.core.keys.Fingerprint;
import com.acns.dsig.core.trust.TrustPolicy;
import com.acns.dsig.core.verify.VerificationService;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(name = "verify", description = "Verify document authenticity, integrity, and signer trust")
public class VerifyCommand implements Callable<Integer> {

    @Parameters(index = "0", description = "Target document file to verify")
    private Path documentPath;

    @Option(names = {"-e", "--envelope"}, description = "Path to signature envelope (.dsig.json)")
    private Path envelopePath;

    @Option(names = {"--trust-store"}, description = "Path to trust store JSON file", defaultValue = "trusted_signers.json")
    private Path trustStorePath;

    @Override
    public Integer call() throws Exception {
        if (!Files.exists(documentPath)) {
            System.err.println("Error: Document file not found: " + documentPath);
            return 1;
        }

        Path finalEnvelopePath = envelopePath != null ?
                envelopePath : Path.of(documentPath.toString() + ".dsig.json");

        if (!Files.exists(finalEnvelopePath)) {
            System.err.println("Error: Signature envelope not found: " + finalEnvelopePath);
            return 1;
        }

        String envelopeJson = Files.readString(finalEnvelopePath, StandardCharsets.UTF_8);
        FileTrustStore trustStore = new FileTrustStore(trustStorePath);
        TrustPolicy trustPolicy = new TrustPolicy(trustStore);

        VerificationService verificationService = new VerificationService(
                new HashService(),
                new SignatureService(),
                new EnvelopeCodec()
        );

        try (InputStream docIn = new FileInputStream(documentPath.toFile())) {
            VerificationResult result = verificationService.verify(docIn, envelopeJson, trustPolicy);

            System.out.println("==================================================");
            System.out.println("           VERIFICATION REPORT                    ");
            System.out.println("==================================================");
            System.out.println("Result Code     : " + result.resultCode());
            System.out.println("Trust Status    : " + result.trustStatus());
            System.out.println("Document        : " + (result.documentName() != null ? result.documentName() : documentPath.getFileName()));
            System.out.println("Document Size   : " + result.documentSize() + " bytes");
            System.out.println("Signer Name     : " + result.signerName());
            System.out.println("Key Fingerprint : " + Fingerprint.formatGrouped(result.keyFingerprint()));
            System.out.println("Signed Digest   : " + result.signedDocHash());
            System.out.println("Computed Digest : " + result.recomputedDocHash());
            System.out.println("Signed At (UTC) : " + result.signedAt());
            System.out.println("Explanation     : " + result.message());
            System.out.println("==================================================");

            return switch (result.resultCode()) {
                case VALID_TRUSTED -> 0;
                case VALID_UNTRUSTED_SIGNER -> 2;
                default -> 1;
            };
        }
    }
}
