package com.acns.dsig.server.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("LoginAttemptService — Brute Force Prevention & Account Lockout Tests")
class LoginAttemptServiceTest {

    private LoginAttemptService loginAttemptService;

    @BeforeEach
    void setUp() {
        loginAttemptService = new LoginAttemptService();
        loginAttemptService.resetCache();
    }

    @Test
    @DisplayName("Initial state: unknown user is not blocked and has 0 failed attempts")
    void initialState_notBlocked() {
        assertFalse(loginAttemptService.isBlocked("alice"));
        assertEquals(0, loginAttemptService.getAttempts("alice"));
    }

    @Test
    @DisplayName("Under threshold: 4 failed attempts does not lock the account")
    void fourFailedAttempts_notBlocked() {
        for (int i = 0; i < 4; i++) {
            loginAttemptService.loginFailed("alice");
        }
        assertEquals(4, loginAttemptService.getAttempts("alice"));
        assertFalse(loginAttemptService.isBlocked("alice"));
    }

    @Test
    @DisplayName("Threshold reached: 5 failed attempts locks the account")
    void fiveFailedAttempts_blocksAccount() {
        for (int i = 0; i < 5; i++) {
            loginAttemptService.loginFailed("alice");
        }
        assertEquals(5, loginAttemptService.getAttempts("alice"));
        assertTrue(loginAttemptService.isBlocked("alice"));

        // Subsequent failure while locked does not increment counter or extend lockout
        loginAttemptService.loginFailed("alice");
        assertEquals(5, loginAttemptService.getAttempts("alice"));
        assertTrue(loginAttemptService.isBlocked("alice"));
    }

    @Test
    @DisplayName("Login succeeded resets the counter and unblocks account")
    void loginSucceeded_resetsLockout() {
        for (int i = 0; i < 5; i++) {
            loginAttemptService.loginFailed("alice");
        }
        assertTrue(loginAttemptService.isBlocked("alice"));

        loginAttemptService.loginSucceeded("alice");
        assertFalse(loginAttemptService.isBlocked("alice"));
        assertEquals(0, loginAttemptService.getAttempts("alice"));
    }

    @Test
    @DisplayName("Key normalization: case insensitive matching for usernames")
    void caseInsensitive_locking() {
        loginAttemptService.loginFailed("Alice");
        loginAttemptService.loginFailed("ALICE");
        loginAttemptService.loginFailed("alice");
        loginAttemptService.loginFailed("  alice  ");
        loginAttemptService.loginFailed("AliCe");

        assertTrue(loginAttemptService.isBlocked("alice"));
        assertTrue(loginAttemptService.isBlocked("ALICE"));
    }

    @Test
    @DisplayName("Different users have independent attempt counters")
    void independentUsers() {
        for (int i = 0; i < 5; i++) {
            loginAttemptService.loginFailed("attacker_target");
        }
        assertTrue(loginAttemptService.isBlocked("attacker_target"));
        assertFalse(loginAttemptService.isBlocked("legitimate_user"));
    }

    @Test
    @DisplayName("Null or blank keys are handled gracefully")
    void nullOrBlank_handledSafely() {
        assertDoesNotThrow(() -> {
            loginAttemptService.loginFailed(null);
            loginAttemptService.loginFailed("");
            loginAttemptService.loginFailed("   ");
            loginAttemptService.loginSucceeded(null);
            loginAttemptService.loginSucceeded("");
        });
        assertFalse(loginAttemptService.isBlocked(null));
        assertFalse(loginAttemptService.isBlocked(""));
        assertEquals(0, loginAttemptService.getAttempts(null));
    }
}
