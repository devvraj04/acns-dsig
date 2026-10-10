package com.acns.dsig.core.error;

/**
 * Thrown when an I/O failure, permission error, or stream interruption occurs during document reading.
 */
public class DocumentReadException extends DsigException {
    public DocumentReadException(String message, Throwable cause) {
        super(message, cause);
    }

    public DocumentReadException(String message) {
        super(message);
    }
}
