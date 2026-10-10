package com.acns.dsig.cli;

import com.acns.dsig.core.keys.KeyService;
import com.acns.dsig.core.keys.KeyStorage;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.Console;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(name = "keygen", description = "Generate an RSA-3072 key pair with encrypted private key storage")
public class KeygenCommand implements Callable<Integer> {

    @Option(names = {"-o", "--out"}, description = "Base path for output key files", defaultValue = "signer_key")
    private String outPath;

    @Option(names = {"-p", "--passphrase"}, description = "Passphrase to encrypt private key (prompted if omitted)", interactive = true)
    private char[] passphrase;

    @Override
    public Integer call() throws Exception {
        System.out.println("Generating RSA-3072 key pair with secure randomness...");
        KeyService keyService = new KeyService();
        KeyService.GeneratedKeyPair result = keyService.generateKeyPair();

        if (passphrase == null || passphrase.length == 0) {
            Console console = System.console();
            if (console != null) {
                passphrase = console.readPassword("Enter passphrase to encrypt private key: ");
            } else {
                System.err.println("Error: Passphrase required to encrypt private key.");
                return 1;
            }
        }

        KeyStorage storage = new KeyStorage();
        Path privKeyPath = Path.of(outPath + ".pk8");
        Path pubKeyPath = Path.of(outPath + ".pub.pem");

        storage.saveEncryptedPrivateKey(result.keyPair().getPrivate(), passphrase, privKeyPath);
        Files.writeString(pubKeyPath, KeyStorage.exportPublicKeyToPem(result.keyPair().getPublic()));

        System.out.println("Key pair successfully generated!");
        System.out.println("Encrypted Private Key : " + privKeyPath.toAbsolutePath());
        System.out.println("Public Key (PEM)       : " + pubKeyPath.toAbsolutePath());
        System.out.println("Fingerprint (SHA-256) : " + result.formattedFingerprint());

        return 0;
    }
}
