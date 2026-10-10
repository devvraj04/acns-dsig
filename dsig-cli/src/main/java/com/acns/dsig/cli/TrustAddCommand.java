package com.acns.dsig.cli;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(name = "trust-add", description = "Pin a signer's public key fingerprint in the local trust store")
public class TrustAddCommand implements Callable<Integer> {

    @Parameters(index = "0", description = "SHA-256 fingerprint of the signer key")
    private String fingerprint;

    @Option(names = {"-l", "--label"}, required = true, description = "Signer label or name")
    private String label;

    @Option(names = {"-n", "--notes"}, description = "Verification notes or channel verification details", defaultValue = "Manually pinned")
    private String notes;

    @Option(names = {"--trust-store"}, description = "Path to trust store JSON file", defaultValue = "trusted_signers.json")
    private Path trustStorePath;

    @Override
    public Integer call() throws Exception {
        FileTrustStore trustStore = new FileTrustStore(trustStorePath);
        trustStore.addTrust(fingerprint, label, notes);

        System.out.println("Signer fingerprint successfully pinned as TRUSTED!");
        System.out.println("Fingerprint : " + fingerprint);
        System.out.println("Label       : " + label);
        System.out.println("Trust Store : " + trustStorePath.toAbsolutePath());

        return 0;
    }
}
