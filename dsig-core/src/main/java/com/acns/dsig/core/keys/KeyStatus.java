package com.acns.dsig.core.keys;

/**
 * Key lifecycle status for local and server-side key management.
 */
public enum KeyStatus {
    /**
     * Currently active for generating new signatures.
     */
    ACTIVE,

    /**
     * Past regular lifecycle; existing signatures remain verifiable, but new signings are disallowed.
     */
    RETIRED,

    /**
     * Compromised or invalidated; signatures must not be trusted.
     */
    REVOKED
}
