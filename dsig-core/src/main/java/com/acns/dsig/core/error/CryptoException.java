package com.acns.dsig.core.error;

/**
 * Thrown when cryptographic algorithm, key derivation, or signature execution fails.
 */
public class CryptoException extends DsigException {
    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
