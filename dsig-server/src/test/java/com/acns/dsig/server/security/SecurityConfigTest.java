package com.acns.dsig.server.security;

import com.acns.dsig.server.persistence.User;
import com.acns.dsig.server.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("SecurityConfig — Spring Security Hardening & Filter Chain Integration Tests")
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserService userService;

    @Autowired
    private LoginAttemptService loginAttemptService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        loginAttemptService.resetCache();

        User signerUser = new User();
        signerUser.setId(10L);
        signerUser.setUsername("signer_bob");
        signerUser.setPasswordHash(passwordEncoder.encode("SecretPass123!"));
        signerUser.setRole("ROLE_SIGNER");

        User adminUser = new User();
        adminUser.setId(20L);
        adminUser.setUsername("admin_carol");
        adminUser.setPasswordHash(passwordEncoder.encode("AdminPass123!"));
        adminUser.setRole("ROLE_ADMIN");

        when(userService.findByUsername("signer_bob")).thenReturn(Optional.of(signerUser));
        when(userService.findByUsername("admin_carol")).thenReturn(Optional.of(adminUser));
    }

    // ── Public Endpoints ──────────────────────────────────────────────────────

    @Test
    @DisplayName("Public endpoints (/login, /register, /api/health) are accessible without authentication")
    void publicEndpoints_accessibleAnonymously() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/register"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }

    @Test
    @DisplayName("Public registration rejects self-assignment of ROLE_ADMIN")
    void register_rejectsRoleAdmin() throws Exception {
        mockMvc.perform(post("/register")
                        .with(csrf())
                        .param("username", "evil_admin")
                        .param("password", "Pass123!")
                        .param("role", "ROLE_ADMIN"))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("error"))
                .andExpect(view().name("register"));
    }

    @Test
    @DisplayName("Public registration accepts legitimate ROLE_SIGNER")
    void register_acceptsRoleSigner() throws Exception {
        mockMvc.perform(post("/register")
                        .with(csrf())
                        .param("username", "new_signer")
                        .param("password", "Pass123!")
                        .param("role", "ROLE_SIGNER"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?registered"));
    }

    // ── Protected Endpoints ───────────────────────────────────────────────────

    @Test
    @DisplayName("Protected endpoint (/dashboard) redirects unauthenticated user to /login")
    void protectedEndpoint_redirectsToLogin() throws Exception {
        mockMvc.perform(get("/dashboard"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/login")));
    }

    // ── Role-Based Access Control ─────────────────────────────────────────────

    @Test
    @DisplayName("ROLE_SIGNER user is denied access to admin audit endpoints (403 Forbidden)")
    @WithMockUser(username = "signer_bob", roles = {"SIGNER"})
    void signerRole_deniedAdminAuditEndpoint() throws Exception {
        mockMvc.perform(get("/admin/audit"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("ROLE_ADMIN user is authorized to access admin audit endpoints")
    @WithMockUser(username = "admin_carol", roles = {"ADMIN"})
    void adminRole_authorizedAdminAuditEndpoint() throws Exception {
        mockMvc.perform(get("/admin/audit"))
                .andExpect(status().isOk());
    }

    // ── CSRF Protection ───────────────────────────────────────────────────────

    @Test
    @DisplayName("POST request without CSRF token is rejected with 403 Forbidden")
    @WithMockUser(username = "signer_bob")
    void postWithoutCsrf_rejected403() throws Exception {
        mockMvc.perform(post("/logout"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("POST request with valid CSRF token is accepted")
    @WithMockUser(username = "signer_bob")
    void postWithCsrf_accepted() throws Exception {
        mockMvc.perform(post("/logout").with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?logout"));
    }

    // ── Security Headers ──────────────────────────────────────────────────────

    @Test
    @DisplayName("Hardened HTTP security headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) are present")
    void securityHeaders_areEnforced() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Referrer-Policy", "strict-origin-when-cross-origin"))
                .andExpect(header().string("Content-Security-Policy", containsString("default-src 'self'")));
    }

    // ── Authentication & Lockout Integration ──────────────────────────────────

    @Test
    @DisplayName("Successful login with valid credentials redirects to /dashboard and clears lockout")
    void validLogin_redirectsToDashboard() throws Exception {
        mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", "signer_bob")
                        .param("password", "SecretPass123!"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/dashboard"));

        assertFalse(loginAttemptService.isBlocked("signer_bob"));
    }

    @Test
    @DisplayName("Invalid login credentials redirect to /login?error and increment failure count")
    void invalidLogin_redirectsToError() throws Exception {
        mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", "signer_bob")
                        .param("password", "WrongPassword!"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?error"));

        assertEquals(1, loginAttemptService.getAttempts("signer_bob"));
    }

    @Test
    @DisplayName("5 consecutive failed logins triggers lockout, rejecting subsequent login attempts")
    void fiveFailedLogins_triggersLockout() throws Exception {
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/login")
                            .with(csrf())
                            .param("username", "signer_bob")
                            .param("password", "WrongPassword!"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/login?error"));
        }

        assertTrue(loginAttemptService.isBlocked("signer_bob"));

        // Even with the CORRECT password now, the locked account cannot log in
        mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", "signer_bob")
                        .param("password", "SecretPass123!"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?error"));

        // Repeated attempts while locked must not increment failure counter or extend lockout
        assertEquals(5, loginAttemptService.getAttempts("signer_bob"));
    }
}
