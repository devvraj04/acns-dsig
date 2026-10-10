package com.acns.dsig.core.error;

/**
 * Thrown when an RSA key fails validation constraints (e.g., bit length < 3072, invalid format, wrong exponent).
 */
public class KeyValidationException extends DsigException {
    public KeyValidationException(String message) {
        super(message);
    }

    public KeyValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
