package com.acns.dsig.server.web;

import com.acns.dsig.server.persistence.KeyPairEntity;
import com.acns.dsig.server.persistence.User;
import com.acns.dsig.server.service.KeyManagementService;
import com.acns.dsig.server.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * UI integration tests for the Key Management screen.
 *
 * Owner: KVS Varshith (Member 7 — Signing Web Interface)
 *
 * Covers:
 *   - Key list page loads successfully for an authenticated user
 *   - Key generation with valid inputs produces a success message
 *   - Key generation with mismatched passphrases shows an accessible error
 *   - Key generation with a short passphrase shows an accessible error
 *   - Key generation with an empty label shows an accessible error
 *   - Public key export requires authentication and enforces ownership
 *   - Retire key with a valid owner marks the key as RETIRED
 *   - Retire key from a non-owner is rejected with an error message
 *   - Private key bytes are never rendered in any response
 *   - Unauthenticated requests to /keys are redirected to /login
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("KeyController — Signing Web Interface Tests")
class KeyControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private KeyManagementService keyManagementService;

    @MockBean
    private UserService userService;

    private User testUser;
    private KeyPairEntity activeKey;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("testuser");
        testUser.setPasswordHash("$2a$10$dummy");
        testUser.setRole("ROLE_SIGNER");

        activeKey = new KeyPairEntity();
        activeKey.setKeyId("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
        activeKey.setOwnerId(1L);
        activeKey.setLabel("My Test Key");
        activeKey.setPublicPem("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----\n");
        activeKey.setKeyFilePath("runtime/keys/test.pk8");
        activeKey.setStatus("ACTIVE");

        when(userService.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(keyManagementService.getKeysForUser(1L)).thenReturn(List.of(activeKey));
    }

    // ── GET /keys ─────────────────────────────────────────────────────────────

    @Test
    @DisplayName("GET /keys — authenticated user sees key list page")
    @WithMockUser(username = "testuser")
    void listKeys_authenticated_rendersPage() throws Exception {
        mockMvc.perform(get("/keys"))
                .andExpect(status().isOk())
                .andExpect(view().name("keys"))
                .andExpect(model().attributeExists("keys"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("My Test Key")));
    }

    @Test
    @DisplayName("GET /keys — unauthenticated request redirects to /login")
    void listKeys_unauthenticated_redirectsToLogin() throws Exception {
        mockMvc.perform(get("/keys"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login"));
    }

    @Test
    @DisplayName("GET /keys — response does not contain 'PRIVATE KEY' (private key bytes never rendered)")
    @WithMockUser(username = "testuser")
    void listKeys_neverRendersPrivateKeyMaterial() throws Exception {
        mockMvc.perform(get("/keys"))
                .andExpect(status().isOk())
                .andExpect(content().string(
                        org.hamcrest.Matchers.not(
                                org.hamcrest.Matchers.containsString("PRIVATE KEY"))));
    }

    // ── POST /keys/generate ────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /keys/generate — valid inputs generate a key and show success message")
    @WithMockUser(username = "testuser")
    void generateKey_validInputs_showsSuccess() throws Exception {
        when(keyManagementService.generateAndStoreKey(eq(1L), eq("Finance Key"), any(char[].class)))
                .thenReturn(activeKey);

        mockMvc.perform(post("/keys/generate")
                        .with(csrf())
                        .param("label", "Finance Key")
                        .param("passphrase", "StrongPass123!")
                        .param("passphraseConfirm", "StrongPass123!"))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("success"))
                .andExpect(model().attributeDoesNotExist("error"));
    }

    @Test
    @DisplayName("POST /keys/generate — mismatched passphrases show accessible error, no key generated")
    @WithMockUser(username = "testuser")
    void generateKey_mismatchedPassphrases_showsError() throws Exception {
        mockMvc.perform(post("/keys/generate")
                        .with(csrf())
                        .param("label", "Finance Key")
                        .param("passphrase", "StrongPass123!")
                        .param("passphraseConfirm", "DifferentPass456!"))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("error"))
                .andExpect(model().attributeDoesNotExist("success"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("do not match")));

        // Must not generate a key when passphrases don't match
        verify(keyManagementService, never()).generateAndStoreKey(any(), any(), any());
    }

    @Test
    @DisplayName("POST /keys/generate — passphrase shorter than 8 chars shows error")
    @WithMockUser(username = "testuser")
    void generateKey_shortPassphrase_showsError() throws Exception {
        mockMvc.perform(post("/keys/generate")
                        .with(csrf())
                        .param("label", "Test Key")
                        .param("passphrase", "short")
                        .param("passphraseConfirm", "short"))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("error"))
                .andExpect(model().attributeDoesNotExist("success"));

        verify(keyManagementService, never()).generateAndStoreKey(any(), any(), any());
    }

    @Test
    @DisplayName("POST /keys/generate — blank label shows error")
    @WithMockUser(username = "testuser")
    void generateKey_blankLabel_showsError() throws Exception {
        mockMvc.perform(post("/keys/generate")
                        .with(csrf())
                        .param("label", "   ")
                        .param("passphrase", "StrongPass123!")
                        .param("passphraseConfirm", "StrongPass123!"))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("error"))
                .andExpect(model().attributeDoesNotExist("success"));

        verify(keyManagementService, never()).generateAndStoreKey(any(), any(), any());
    }

    // ── GET /keys/{keyId}/public ───────────────────────────────────────────────

    @Test
    @DisplayName("GET /keys/{id}/public — owner downloads PEM file successfully")
    @WithMockUser(username = "testuser")
    void downloadPublicKey_owner_downloadsPem() throws Exception {
        when(keyManagementService.getKey(activeKey.getKeyId())).thenReturn(Optional.of(activeKey));

        mockMvc.perform(get("/keys/" + activeKey.getKeyId() + "/public"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition",
                        org.hamcrest.Matchers.containsString("attachment")))
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("BEGIN PUBLIC KEY")));
    }

    @Test
    @DisplayName("GET /keys/{id}/public — response does not include PRIVATE KEY text")
    @WithMockUser(username = "testuser")
    void downloadPublicKey_neverContainsPrivateKeyText() throws Exception {
        when(keyManagementService.getKey(activeKey.getKeyId())).thenReturn(Optional.of(activeKey));

        mockMvc.perform(get("/keys/" + activeKey.getKeyId() + "/public"))
                .andExpect(status().isOk())
                .andExpect(content().string(
                        org.hamcrest.Matchers.not(
                                org.hamcrest.Matchers.containsString("PRIVATE KEY"))));
    }

    @Test
    @DisplayName("GET /keys/{id}/public — non-owner receives 403 Forbidden")
    @WithMockUser(username = "testuser")
    void downloadPublicKey_nonOwner_returns403() throws Exception {
        KeyPairEntity otherUserKey = new KeyPairEntity();
        otherUserKey.setKeyId("aaaa1111bbbb2222cccc3333dddd4444aaaa1111bbbb2222cccc3333dddd4444");
        otherUserKey.setOwnerId(999L);   // different owner
        otherUserKey.setLabel("Other User Key");
        otherUserKey.setPublicPem("-----BEGIN PUBLIC KEY-----\nMIIBIj...\n-----END PUBLIC KEY-----\n");
        otherUserKey.setKeyFilePath("runtime/keys/other.pk8");
        otherUserKey.setStatus("ACTIVE");

        when(keyManagementService.getKey(otherUserKey.getKeyId())).thenReturn(Optional.of(otherUserKey));

        mockMvc.perform(get("/keys/" + otherUserKey.getKeyId() + "/public"))
                .andExpect(status().isForbidden());
    }

    // ── POST /keys/{keyId}/retire ──────────────────────────────────────────────

    @Test
    @DisplayName("POST /keys/{id}/retire — owner retires key successfully")
    @WithMockUser(username = "testuser")
    void retireKey_owner_success() throws Exception {
        doNothing().when(keyManagementService).retireKey(1L, activeKey.getKeyId());

        mockMvc.perform(post("/keys/" + activeKey.getKeyId() + "/retire")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("success"))
                .andExpect(model().attributeDoesNotExist("error"));
    }

    @Test
    @DisplayName("POST /keys/{id}/retire — service throws SecurityException — error shown")
    @WithMockUser(username = "testuser")
    void retireKey_nonOwner_showsError() throws Exception {
        doThrow(new SecurityException("You do not own this key."))
                .when(keyManagementService).retireKey(eq(1L), anyString());

        mockMvc.perform(post("/keys/" + activeKey.getKeyId() + "/retire")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("error"))
                .andExpect(model().attributeDoesNotExist("success"));
    }

    @Test
    @DisplayName("POST /keys/generate — CSRF protection active (missing CSRF token returns 403)")
    @WithMockUser(username = "testuser")
    void generateKey_missingCsrfToken_returns403() throws Exception {
        mockMvc.perform(post("/keys/generate")
                        .param("label", "Test Key")
                        .param("passphrase", "StrongPass123!")
                        .param("passphraseConfirm", "StrongPass123!"))
                // No .with(csrf()) — expect CSRF rejection
                .andExpect(status().isForbidden());
    }
}
