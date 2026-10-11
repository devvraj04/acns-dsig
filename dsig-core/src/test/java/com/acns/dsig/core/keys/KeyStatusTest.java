package com.acns.dsig.core.keys;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("KeyStatus Lifecycle Unit Tests")
class KeyStatusTest {

    @Test
    @DisplayName("Signing permissions: Only ACTIVE keys are permitted to sign")
    void testSigningPermissions() {
        assertTrue(KeyStatus.ACTIVE.canSign(), "ACTIVE keys must be permitted to sign");
        assertFalse(KeyStatus.RETIRED.canSign(), "RETIRED keys must NOT be permitted to sign");
        assertFalse(KeyStatus.REVOKED.canSign(), "REVOKED keys must NOT be permitted to sign");
    }

    @Test
    @DisplayName("Verification permissions: ACTIVE and RETIRED keys are verifiable; REVOKED is untrusted")
    void testVerificationPermissions() {
        assertTrue(KeyStatus.ACTIVE.canVerify(), "ACTIVE keys must be verifiable");
        assertTrue(KeyStatus.RETIRED.canVerify(), "RETIRED keys must remain verifiable for past documents");
        assertFalse(KeyStatus.REVOKED.canVerify(), "REVOKED keys must NEVER be verified as trusted");
    }

    @Test
    @DisplayName("Valid status transitions proceed without exception")
    void testValidTransitions() {
        // ACTIVE -> RETIRED
        assertDoesNotThrow(() -> KeyStatus.ACTIVE.validateTransition(KeyStatus.RETIRED));
        assertEquals(KeyStatus.RETIRED, KeyStatus.ACTIVE.transitionTo(KeyStatus.RETIRED));

        // ACTIVE -> REVOKED
        assertDoesNotThrow(() -> KeyStatus.ACTIVE.validateTransition(KeyStatus.REVOKED));
        assertEquals(KeyStatus.REVOKED, KeyStatus.ACTIVE.transitionTo(KeyStatus.REVOKED));

        // RETIRED -> REVOKED
        assertDoesNotThrow(() -> KeyStatus.RETIRED.validateTransition(KeyStatus.REVOKED));
        assertEquals(KeyStatus.REVOKED, KeyStatus.RETIRED.transitionTo(KeyStatus.REVOKED));

        // Idempotent transitions to same status
        assertDoesNotThrow(() -> KeyStatus.ACTIVE.validateTransition(KeyStatus.ACTIVE));
        assertDoesNotThrow(() -> KeyStatus.RETIRED.validateTransition(KeyStatus.RETIRED));
        assertDoesNotThrow(() -> KeyStatus.REVOKED.validateTransition(KeyStatus.REVOKED));
    }

    @Test
    @DisplayName("Invalid status transitions throw IllegalStateException")
    void testInvalidTransitions() {
        // Cannot reactivate RETIRED key
        IllegalStateException ex1 = assertThrows(IllegalStateException.class,
                () -> KeyStatus.RETIRED.validateTransition(KeyStatus.ACTIVE));
        assertTrue(ex1.getMessage().contains("Cannot reactivate"));

        // REVOKED is terminal and cannot transition to ACTIVE
        IllegalStateException ex2 = assertThrows(IllegalStateException.class,
                () -> KeyStatus.REVOKED.validateTransition(KeyStatus.ACTIVE));
        assertTrue(ex2.getMessage().contains("terminal"));

        // REVOKED is terminal and cannot transition to RETIRED
        IllegalStateException ex3 = assertThrows(IllegalStateException.class,
                () -> KeyStatus.REVOKED.validateTransition(KeyStatus.RETIRED));
        assertTrue(ex3.getMessage().contains("terminal"));
    }

    @Test
    @DisplayName("Transition validation rejects null target status")
    void testNullTargetStatus() {
        assertThrows(IllegalArgumentException.class, () -> KeyStatus.ACTIVE.validateTransition(null));
        assertThrows(IllegalArgumentException.class, () -> KeyStatus.RETIRED.validateTransition(null));
        assertThrows(IllegalArgumentException.class, () -> KeyStatus.REVOKED.validateTransition(null));
    }
}
