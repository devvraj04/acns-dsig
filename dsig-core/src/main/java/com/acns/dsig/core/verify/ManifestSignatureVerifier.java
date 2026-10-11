package com.acns.dsig.core.verify;

import java.security.PublicKey;

/**
 * Minimal verification-owned contract for verifying RSASSA-PSS signatures over domain-separated manifest bytes.
 *
 * Owned by: Deven Thakkar (Member 1)
 * Isolates pending signature engine implementation (Tanmay Vishwakarma).
 */
@FunctionalInterface
public interface ManifestSignatureVerifier {

    /**
     * Cryptographically verifies the digital signature over the exact manifest bytes.
     * The implementation must prepend the protocol domain separation label "ACNS-DSIG-v1\0" before verifying.
     *
     * @param publicKey the signer's RSA public key
     * @param exactManifestBytes exact received UTF-8 bytes of the manifest JSON
     * @param signatureBytes decoded raw RSASSA-PSS signature bytes
     * @return true if the signature is mathematically valid, false otherwise
     */
    boolean verifyManifestSignature(PublicKey publicKey, byte[] exactManifestBytes, byte[] signatureBytes);
}
