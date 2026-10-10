package com.acns.dsig.core.error;

/**
 * Thrown when an input document has 0 bytes (empty file).
 * Section 8.3 of Master Plan mandates rejecting empty files.
 */
public class EmptyDocumentException extends DsigException {
    public EmptyDocumentException(String message) {
        super(message);
    }
}
