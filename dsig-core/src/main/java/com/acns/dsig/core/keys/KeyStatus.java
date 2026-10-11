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
    REVOKED;

    /**
     * Checks if a key in this status is allowed to produce new signatures.
     * Only ACTIVE keys are permitted to sign.
     *
     * @return true if permitted to sign, false otherwise
     */
    public boolean canSign() {
        return this == ACTIVE;
    }

    /**
     * Checks if signatures made with a key in this status remain verifiable.
     * ACTIVE and RETIRED keys are valid for verification; REVOKED keys are untrusted.
     *
     * @return true if permitted to verify, false if revoked
     */
    public boolean canVerify() {
        return this == ACTIVE || this == RETIRED;
    }

    /**
     * Validates whether a state transition from this status to nextStatus is allowed.
     * Rules:
     * - ACTIVE -> RETIRED, REVOKED (or same status)
     * - RETIRED -> REVOKED (or same status)
     * - REVOKED is terminal (cannot transition to any other state)
     *
     * @param nextStatus the desired next status
     * @throws IllegalArgumentException if nextStatus is null
     * @throws IllegalStateException if the requested transition is disallowed
     */
    public void validateTransition(KeyStatus nextStatus) {
        if (nextStatus == null) {
            throw new IllegalArgumentException("Target key status cannot be null");
        }
        if (this == nextStatus) {
            return;
        }

        switch (this) {
            case ACTIVE -> {
                // ACTIVE may transition to RETIRED or REVOKED
                if (nextStatus != RETIRED && nextStatus != REVOKED) {
                    throw new IllegalStateException("Invalid transition from " + this + " to " + nextStatus);
                }
            }
            case RETIRED -> {
                // RETIRED may only transition to REVOKED
                if (nextStatus != REVOKED) {
                    throw new IllegalStateException("Cannot reactivate RETIRED key to " + nextStatus);
                }
            }
            case REVOKED -> throw new IllegalStateException("REVOKED is a terminal status and cannot be changed");
        }
    }

    /**
     * Performs validated transition to nextStatus.
     *
     * @param nextStatus the target status
     * @return the target status
     */
    public KeyStatus transitionTo(KeyStatus nextStatus) {
        validateTransition(nextStatus);
        return nextStatus;
    }
}
