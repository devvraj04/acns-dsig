package com.acns.dsig.core.api;

/**
 * Trust lifecycle status of a signer's public key fingerprint.
 */
public enum TrustStatus {
    /**
     * Key fingerprint has been explicitly verified and pinned by the user/verifier.
     */
    TRUSTED,

    /**
     * Key fingerprint is recognized but marked untrusted, or has not been pinned.
     */
    UNTRUSTED,

    /**
     * Key fingerprint has been revoked due to compromise or invalidation.
     */
    REVOKED,

    /**
     * Key has reached end-of-life / expiration and is no longer valid for new signatures.
     */
    RETIRED,

    /**
     * Key fingerprint is unknown to the local trust store.
     */
    UNKNOWN
}
