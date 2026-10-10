package com.acns.dsig.cli;

import com.acns.dsig.core.crypto.HashService;
import com.acns.dsig.core.crypto.SignatureService;
import com.acns.dsig.core.format.EnvelopeCodec;
import com.acns.dsig.core.keys.KeyStorage;
import com.acns.dsig.core.sign.SigningService;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.Console;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.concurrent.Callable;

@Command(name = "sign", description = "Sign a document and create a detached signature envelope")
public class SignCommand implements Callable<Integer> {

    @Parameters(index = "0", description = "Target document file to sign")
    private Path documentPath;

    @Option(names = {"-k", "--key"}, required = true, description = "Path to encrypted private key (.pk8)")
    private Path keyPath;

    @Option(names = {"--pub"}, required = true, description = "Path to public key (.pub.pem)")
    private Path pubKeyPath;

    @Option(names = {"-s", "--signer"}, description = "Signer identity or label", defaultValue = "Local Signer")
    private String signerName;

    @Option(names = {"-o", "--out"}, description = "Output signature envelope path (defaults to <doc>.dsig.json)")
    private Path outEnvelopePath;

    @Option(names = {"-p", "--passphrase"}, description = "Private key decryption passphrase", interactive = true)
    private char[] passphrase;

    @Override
    public Integer call() throws Exception {
        if (!Files.exists(documentPath)) {
            System.err.println("Error: Document file not found: " + documentPath);
            return 1;
        }

        if (passphrase == null || passphrase.length == 0) {
            Console console = System.console();
            if (console != null) {
                passphrase = console.readPassword("Enter passphrase to decrypt private key: ");
            } else {
                System.err.println("Error: Private key passphrase required.");
                return 1;
            }
        }

        KeyStorage keyStorage = new KeyStorage();
        PrivateKey privateKey = keyStorage.loadEncryptedPrivateKey(keyPath, passphrase);
        PublicKey publicKey = KeyStorage.parsePublicKeyFromPem(Files.readString(pubKeyPath, StandardCharsets.UTF_8));

        SigningService signingService = new SigningService(new HashService(), new SignatureService(), new EnvelopeCodec());

        Path finalOutPath = outEnvelopePath != null ?
                outEnvelopePath : Path.of(documentPath.toString() + ".dsig.json");

        try (InputStream docIn = new FileInputStream(documentPath.toFile())) {
            SigningService.SignResult result = signingService.sign(
                    docIn,
                    documentPath.getFileName().toString(),
                    privateKey,
                    publicKey,
                    signerName
            );

            Files.writeString(finalOutPath, result.envelopeJson(), StandardCharsets.UTF_8);

            System.out.println("Document successfully signed!");
            System.out.println("Document        : " + documentPath.getFileName());
            System.out.println("Document Size   : " + result.documentSize() + " bytes");
            System.out.println("Document SHA256 : " + result.documentHash());
            System.out.println("Key Fingerprint : " + result.keyFingerprint());
            System.out.println("Saved Envelope  : " + finalOutPath.toAbsolutePath());
        }

        return 0;
    }
}
