package com.acns.dsig.server.web;

import com.acns.dsig.server.persistence.TrustedSigner;
import com.acns.dsig.server.persistence.User;
import com.acns.dsig.server.service.TrustStoreService;
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

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * UI integration tests for the Signer Trust Store and Fingerprint Pinning.
 *
 * Technical Owner: Member 8 — Jay Pandya (Verification Web Interface & Trust UI)
 * Review Partner: Member 7 — KVS Varshith (Signing Web Interface)
 *
 * Covers:
 *   - Trust page loads successfully for authenticated user
 *   - Pre-filled fingerprint & label support on GET /trust
 *   - Unauthenticated access redirects to /login
 *   - CSRF protection on POST /trust/pin and POST /trust/revoke
 *   - Pinning valid 64-character SHA-256 fingerprint succeeds
 *   - Pinning with invalid fingerprint length or empty label rejected
 *   - Revoking a pinned signer updates status and redirects
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("TrustController — Trust Store UI Integration Tests")
class TrustControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private TrustStoreService trustStoreService;

    @MockBean
    private UserService userService;

    private User testUser;
    private TrustedSigner sampleSigner;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setId(201L);
        testUser.setUsername("trust_admin_jay");

        when(userService.findByUsername("trust_admin_jay")).thenReturn(Optional.of(testUser));

        sampleSigner = new TrustedSigner();
        sampleSigner.setId(55L);
        sampleSigner.setOwnerId(201L);
        sampleSigner.setFingerprint("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        sampleSigner.setLabel("Finance Director");
        sampleSigner.setStatus("TRUSTED");
        sampleSigner.setAddedAt(Instant.now());
        sampleSigner.setNote("In-person verification on 2026-10-11");
    }

    @Test
    @DisplayName("GET /trust — Returns trust view with list of pinned signers")
    @WithMockUser(username = "trust_admin_jay", roles = {"VERIFIER"})
    void testListTrustStore_Authenticated() throws Exception {
        when(trustStoreService.getSignersForUser(201L)).thenReturn(List.of(sampleSigner));

        mockMvc.perform(get("/trust"))
                .andExpect(status().isOk())
                .andExpect(view().name("trust"))
                .andExpect(model().attributeExists("signers"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Finance Director")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")));
    }

    @Test
    @DisplayName("GET /trust with prefill parameters populates form fields")
    @WithMockUser(username = "trust_admin_jay", roles = {"VERIFIER"})
    void testListTrustStore_WithPrefill() throws Exception {
        when(trustStoreService.getSignersForUser(201L)).thenReturn(List.of());

        String fp = "4a2b9f3e1c8d5a7b4a2b9f3e1c8d5a7b4a2b9f3e1c8d5a7b4a2b9f3e1c8d5a7b";
        mockMvc.perform(get("/trust")
                        .param("fingerprint", fp)
                        .param("label", "External Auditor"))
                .andExpect(status().isOk())
                .andExpect(model().attribute("prefillFingerprint", fp))
                .andExpect(model().attribute("prefillLabel", "External Auditor"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString(fp)))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("External Auditor")));
    }

    @Test
    @DisplayName("GET /trust — Unauthenticated request redirects to /login")
    void testListTrustStore_UnauthenticatedRedirects() throws Exception {
        mockMvc.perform(get("/trust"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login"));
    }

    @Test
    @DisplayName("POST /trust/pin without CSRF token is rejected with 403 Forbidden")
    @WithMockUser(username = "trust_admin_jay", roles = {"VERIFIER"})
    void testPinFingerprint_RequiresCsrf() throws Exception {
        mockMvc.perform(post("/trust/pin")
                        .param("fingerprint", "4a2b9f3e1c8d5a7b4a2b9f3e1c8d5a7b4a2b9f3e1c8d5a7b4a2b9f3e1c8d5a7b")
                        .param("label", "Test Signer"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("POST /trust/pin with valid 64-char fingerprint successfully pins signer")
    @WithMockUser(username = "trust_admin_jay", roles = {"VERIFIER"})
    void testPinFingerprint_ValidInput() throws Exception {
        String fp = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        TrustedSigner created = new TrustedSigner();
        created.setFingerprint(fp);
        created.setLabel("New Legal Team");
        created.setStatus("TRUSTED");

        when(trustStoreService.pinFingerprint(eq(201L), eq(fp), eq("New Legal Team"), eq("Verified via phone")))
                .thenReturn(created);
        when(trustStoreService.getSignersForUser(201L)).thenReturn(List.of(created));

        mockMvc.perform(post("/trust/pin")
                        .param("fingerprint", fp)
                        .param("label", "New Legal Team")
                        .param("note", "Verified via phone")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("trust"))
                .andExpect(model().attributeExists("success"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("successfully pinned as TRUSTED")));

        verify(trustStoreService).pinFingerprint(201L, fp, "New Legal Team", "Verified via phone");
    }

    @Test
    @DisplayName("POST /trust/pin with invalid fingerprint length (<64 chars) is rejected")
    @WithMockUser(username = "trust_admin_jay", roles = {"VERIFIER"})
    void testPinFingerprint_InvalidLengthRejected() throws Exception {
        mockMvc.perform(post("/trust/pin")
                        .param("fingerprint", "short_hash_123")
                        .param("label", "Invalid Signer")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("trust"))
                .andExpect(model().attributeExists("error"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Expected exactly 64 hexadecimal characters")));

        verify(trustStoreService, never()).pinFingerprint(anyLong(), anyString(), anyString(), any());
    }

    @Test
    @DisplayName("POST /trust/pin with empty label is rejected")
    @WithMockUser(username = "trust_admin_jay", roles = {"VERIFIER"})
    void testPinFingerprint_EmptyLabelRejected() throws Exception {
        String fp = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        mockMvc.perform(post("/trust/pin")
                        .param("fingerprint", fp)
                        .param("label", "   ")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("trust"))
                .andExpect(model().attributeExists("error"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Signer label or organization name is required")));

        verify(trustStoreService, never()).pinFingerprint(anyLong(), anyString(), anyString(), any());
    }

    @Test
    @DisplayName("POST /trust/revoke/{id} revokes signer trust and redirects to /trust")
    @WithMockUser(username = "trust_admin_jay", roles = {"VERIFIER"})
    void testRevokeSigner_SuccessRedirect() throws Exception {
        mockMvc.perform(post("/trust/revoke/55")
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/trust"))
                .andExpect(flash().attributeExists("success"));

        verify(trustStoreService).revokeSigner(201L, 55L);
    }
}
