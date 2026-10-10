package com.acns.dsig.core.error;

/**
 * Base unchecked exception for all ACNS-DSIG operations.
 */
public class DsigException extends RuntimeException {
    public DsigException(String message) {
        super(message);
    }

    public DsigException(String message, Throwable cause) {
        super(message, cause);
    }
}
