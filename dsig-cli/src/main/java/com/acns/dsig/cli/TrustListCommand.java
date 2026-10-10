package com.acns.dsig.cli;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.Callable;

@Command(name = "trust-list", description = "List all pinned signer fingerprints in the local trust store")
public class TrustListCommand implements Callable<Integer> {

    @Option(names = {"--trust-store"}, description = "Path to trust store JSON file", defaultValue = "trusted_signers.json")
    private Path trustStorePath;

    @Override
    public Integer call() throws Exception {
        FileTrustStore trustStore = new FileTrustStore(trustStorePath);
        Map<String, FileTrustStore.TrustEntry> entries = trustStore.listEntries();

        if (entries.isEmpty()) {
            System.out.println("Trust store is currently empty.");
            return 0;
        }

        System.out.println("===============================================================================");
        System.out.printf("%-18s | %-10s | %s%n", "LABEL", "STATUS", "FINGERPRINT");
        System.out.println("-------------------------------------------------------------------------------");
        for (FileTrustStore.TrustEntry entry : entries.values()) {
            System.out.printf("%-18s | %-10s | %s%n",
                    entry.label(),
                    entry.status(),
                    entry.fingerprint());
        }
        System.out.println("===============================================================================");

        return 0;
    }
}
