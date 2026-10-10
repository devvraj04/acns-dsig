package com.acns.dsig.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;

/**
 * Root Picocli entry point for the ACNS-DSIG local offline CLI tool.
 */
@Command(
        name = "dsig",
        mixinStandardHelpOptions = true,
        version = "ACNS-DSIG CLI 1.0.0",
        description = "Digital Signature Document Authentication and Integrity Verification CLI",
        subcommands = {
                KeygenCommand.class,
                SignCommand.class,
                VerifyCommand.class,
                FingerprintCommand.class,
                TrustAddCommand.class,
                TrustListCommand.class
        }
)
public class DsigCli implements Runnable {

    @Override
    public void run() {
        CommandLine.usage(this, System.out);
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new DsigCli()).execute(args);
        System.exit(exitCode);
    }
}
