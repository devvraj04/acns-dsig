package com.acns.dsig.core.verify;

import com.acns.dsig.core.error.CorruptedPackageException;

/**
 * Minimal verification-owned contract for decoding raw envelope payloads into a structured VerificationPackage.
 *
 * Owned by: Deven Thakkar (Member 1)
 * Isolates pending envelope/manifest decoding implementation (Parth Zala) while guaranteeing
 * that exact manifest bytes are provided for signature verification.
 */
public interface PackageDecoder {

    /**
     * Decodes the raw package payload (e.g. JSON string) into an immutable VerificationPackage.
     *
     * @param packagePayload raw string payload of the detached signature envelope
     * @return populated VerificationPackage containing exact manifest bytes and envelope attributes
     * @throws CorruptedPackageException if the package payload is malformed, has invalid Base64, or fails strict parsing
     */
    VerificationPackage decode(String packagePayload) throws CorruptedPackageException;
}
