package com.acns.dsig.core.error;

/**
 * Thrown when manifest or envelope structure fails format allow-list checks or metadata requirements.
 */
public class FormatValidationException extends DsigException {
    public FormatValidationException(String message) {
        super(message);
    }

    public FormatValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
