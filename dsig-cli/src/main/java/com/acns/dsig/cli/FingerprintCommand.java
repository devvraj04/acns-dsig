package com.acns.dsig.cli;

import com.acns.dsig.core.keys.Fingerprint;
import com.acns.dsig.core.keys.KeyStorage;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.concurrent.Callable;

@Command(name = "fingerprint", description = "Calculate and display the SHA-256 SPKI fingerprint of a public key PEM")
public class FingerprintCommand implements Callable<Integer> {

    @Parameters(index = "0", description = "Path to public key PEM file")
    private Path publicKeyPath;

    @Override
    public Integer call() throws Exception {
        if (!Files.exists(publicKeyPath)) {
            System.err.println("Error: File not found: " + publicKeyPath);
            return 1;
        }

        String pem = Files.readString(publicKeyPath, StandardCharsets.UTF_8);
        PublicKey pubKey = KeyStorage.parsePublicKeyFromPem(pem);
        String rawFp = Fingerprint.calculate(pubKey);
        String formattedFp = Fingerprint.formatGrouped(rawFp);

        System.out.println("Public Key File : " + publicKeyPath.toAbsolutePath());
        System.out.println("Hex Fingerprint : " + rawFp);
        System.out.println("Formatted       : " + formattedFp);

        return 0;
    }
}
