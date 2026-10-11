package com.acns.dsig.cli;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end integration test suite exercising the DsigCli Picocli commands.
 * Tests keygen, fingerprinting, trust pinning, signing, valid verification,
 * tampered document detection, untrusted signer, and malformed inputs.
 *
 * Owned by: Simrit Kaur (Member 10) - QA, CI/CD & Integration-Test Infrastructure.
 */
public class DsigCliIntegrationTest {

    @TempDir
    Path tempDir;

    private ByteArrayOutputStream outStream;
    private ByteArrayOutputStream errStream;
    private PrintStream originalOut;
    private PrintStream originalErr;

    @BeforeEach
    void setUp() {
        originalOut = System.out;
        originalErr = System.err;
        outStream = new ByteArrayOutputStream();
        errStream = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outStream));
        System.setErr(new PrintStream(errStream));
    }

    @AfterEach
    void tearDown() {
        System.setOut(originalOut);
        System.setErr(originalErr);
    }

    private int runCli(String... args) {
        return new CommandLine(new DsigCli()).execute(args);
    }

    private String getOutput() {
        return outStream.toString(StandardCharsets.UTF_8);
    }

    private String getError() {
        return errStream.toString(StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("CLI Full Workflow: Keygen -> Fingerprint -> TrustPin -> Sign -> Verify (VALID_TRUSTED)")
    void testFullCliWorkflowSuccess() throws Exception {
        Path keyOut = tempDir.resolve("alice_key");
        Path trustStore = tempDir.resolve("trust_store.json");
        Path docPath = tempDir.resolve("contract.txt");
        Files.writeString(docPath, "Acme Corp Master Services Agreement 2026.");

        // 1. Keygen
        int keygenExit = runCli("keygen", "-o", keyOut.toString(), "-p", "passphrase123");
        assertEquals(0, keygenExit, "Keygen should succeed");
        assertTrue(Files.exists(tempDir.resolve("alice_key.pk8")));
        assertTrue(Files.exists(tempDir.resolve("alice_key.pub.pem")));

        // 2. Fingerprint
        outStream.reset();
        int fpExit = runCli("fingerprint", tempDir.resolve("alice_key.pub.pem").toString());
        assertEquals(0, fpExit);
        String fpOutput = getOutput();
        assertTrue(fpOutput.contains("Hex Fingerprint : "));
        String hexFp = null;
        for (String line : fpOutput.split("\\R")) {
            if (line.contains("Hex Fingerprint : ")) {
                hexFp = line.split("Hex Fingerprint : ")[1].trim();
                break;
            }
        }
        assertNotNull(hexFp);
        assertEquals(64, hexFp.length());

        // 3. Trust-Add
        outStream.reset();
        int trustExit = runCli("trust-add", hexFp, "-l", "Alice Corporate", "--trust-store", trustStore.toString());
        assertEquals(0, trustExit);
        assertTrue(Files.exists(trustStore));

        // 4. Sign
        outStream.reset();
        Path envPath = tempDir.resolve("contract.txt.dsig.json");
        int signExit = runCli("sign", docPath.toString(),
                "-k", tempDir.resolve("alice_key.pk8").toString(),
                "--pub", tempDir.resolve("alice_key.pub.pem").toString(),
                "-s", "Alice",
                "-o", envPath.toString(),
                "-p", "passphrase123");
        assertEquals(0, signExit);
        assertTrue(Files.exists(envPath));

        // 5. Verify (Expect VALID_TRUSTED => exit code 0)
        outStream.reset();
        int verifyExit = runCli("verify", docPath.toString(),
                "-e", envPath.toString(),
                "--trust-store", trustStore.toString());
        assertEquals(0, verifyExit, "Legitimate signed document should exit with 0 (VALID_TRUSTED)");
        String verifyOutput = getOutput();
        assertTrue(verifyOutput.contains("Result Code     : VALID_TRUSTED"));
        assertTrue(verifyOutput.contains("Trust Status    : TRUSTED"));
        assertTrue(verifyOutput.contains("Signer Name     : Alice"));
    }

    @Test
    @DisplayName("CLI Workflow: Untrusted signer exits with code 2 (VALID_UNTRUSTED_SIGNER)")
    void testCliUntrustedSigner() throws Exception {
        Path keyOut = tempDir.resolve("mallory_key");
        Path emptyTrustStore = tempDir.resolve("empty_trust.json");
        Path docPath = tempDir.resolve("proposal.txt");
        Files.writeString(docPath, "Business proposal from unpinned third party.");

        // Keygen & Sign
        runCli("keygen", "-o", keyOut.toString(), "-p", "passphrase123");
        Path envPath = tempDir.resolve("proposal.txt.dsig.json");
        runCli("sign", docPath.toString(),
                "-k", tempDir.resolve("mallory_key.pk8").toString(),
                "--pub", tempDir.resolve("mallory_key.pub.pem").toString(),
                "-s", "Mallory",
                "-o", envPath.toString(),
                "-p", "passphrase123");

        // Verify against empty trust store
        outStream.reset();
        int verifyExit = runCli("verify", docPath.toString(),
                "-e", envPath.toString(),
                "--trust-store", emptyTrustStore.toString());
        assertEquals(2, verifyExit, "Untrusted signer should return exit code 2");
        String verifyOutput = getOutput();
        assertTrue(verifyOutput.contains("Result Code     : VALID_UNTRUSTED_SIGNER"));
    }

    @Test
    @DisplayName("CLI Workflow: Tampered document content exits with code 1 (DOCUMENT_TAMPERED)")
    void testCliTamperedDocument() throws Exception {
        Path keyOut = tempDir.resolve("signer_key");
        Path docPath = tempDir.resolve("statement.txt");
        Files.writeString(docPath, "Original statement before unauthorized modification.");

        runCli("keygen", "-o", keyOut.toString(), "-p", "passphrase123");
        Path envPath = tempDir.resolve("statement.txt.dsig.json");
        runCli("sign", docPath.toString(),
                "-k", tempDir.resolve("signer_key.pk8").toString(),
                "--pub", tempDir.resolve("signer_key.pub.pem").toString(),
                "-s", "Signer",
                "-o", envPath.toString(),
                "-p", "passphrase123");

        // Alter document after signing
        Files.writeString(docPath, "Tampered statement with modified numbers!");

        outStream.reset();
        int verifyExit = runCli("verify", docPath.toString(), "-e", envPath.toString());
        assertEquals(1, verifyExit, "Tampered document must fail verification with exit code 1");
        String verifyOutput = getOutput();
        assertTrue(verifyOutput.contains("Result Code     : DOCUMENT_TAMPERED"));
    }

    @Test
    @DisplayName("CLI Workflow: Malformed envelope JSON exits with code 1 (CORRUPTED_PACKAGE)")
    void testCliMalformedEnvelope() throws Exception {
        Path docPath = tempDir.resolve("file.txt");
        Path badEnv = tempDir.resolve("bad.dsig.json");
        Files.writeString(docPath, "Normal document payload.");
        Files.writeString(badEnv, """
                {
                  "format": "ACNS-DSIG",
                  "version": 1,
                  "manifest": "NOT_VALID_BASE64_!!!",
                  "signature": "dGFtcGVyZWQ=",
                  "publicKey": "dGFtcGVyZWQ="
                }
                """);

        outStream.reset();
        int verifyExit = runCli("verify", docPath.toString(), "-e", badEnv.toString());
        assertEquals(1, verifyExit, "Malformed envelope should fail verification with code 1");
        String verifyOutput = getOutput();
        assertTrue(verifyOutput.contains("Result Code     : CORRUPTED_PACKAGE"));
    }
}
