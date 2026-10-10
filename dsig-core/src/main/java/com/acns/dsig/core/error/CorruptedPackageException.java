package com.acns.dsig.core.error;

/**
 * Thrown when an envelope or manifest JSON cannot be parsed, contains invalid base64, or duplicate keys.
 */
public class CorruptedPackageException extends DsigException {
    public CorruptedPackageException(String message) {
        super(message);
    }

    public CorruptedPackageException(String message, Throwable cause) {
        super(message, cause);
    }
}
