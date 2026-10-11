package com.acns.dsig.server.web;

import com.acns.dsig.core.sign.SigningService;
import com.acns.dsig.server.persistence.KeyPairEntity;
import com.acns.dsig.server.persistence.User;
import com.acns.dsig.server.security.UploadGuard;
import com.acns.dsig.server.service.KeyManagementService;
import com.acns.dsig.server.service.SigningAppService;
import com.acns.dsig.server.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.file.Path;
import java.nio.file.Files;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * UI integration tests for the Document Signing screen.
 *
 * Owner: KVS Varshith (Member 7 — Signing Web Interface)
 *
 * Covers:
 *   - Sign page loads with key list for an authenticated user
 *   - Sign page load redirects unauthenticated users to /login
 *   - Successful sign flow displays hash and fingerprint in result panel
 *   - Successful sign flow with download=true triggers file download
 *   - Empty file upload is rejected with an error (not a crash)
 *   - Wrong passphrase (key decryption failure) shows user-friendly error without stack trace
 *   - Key not owned by user is rejected with an error
 *   - Retired key cannot be used for signing
 *   - CSRF token is required on POST /sign
 *   - No private key material appears in any sign response
 *   - No stack traces are exposed to the user on signing errors
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("SignController — Sign Flow UI Integration Tests")
class SignControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private SigningAppService signingAppService;

    @MockBean
    private KeyManagementService keyManagementService;

    @MockBean
    private UserService userService;

    @MockBean
    private UploadGuard uploadGuard;

    private User testUser;
    private KeyPairEntity activeKey;
    private SigningService.SignResult fakeResult;

    private static final String KEY_ID = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    private static final String SAMPLE_DOC_HASH = "a" .repeat(64);
    private static final String SAMPLE_FINGERPRINT = KEY_ID;

    @BeforeEach
    void setUp() throws Exception {
        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("testuser");
        testUser.setPasswordHash("$2a$10$dummy");
        testUser.setRole("ROLE_SIGNER");

        activeKey = new KeyPairEntity();
        activeKey.setKeyId(KEY_ID);
        activeKey.setOwnerId(1L);
        activeKey.setLabel("My Test Key");
        activeKey.setPublicPem("-----BEGIN PUBLIC KEY-----\nMIIBIj...\n-----END PUBLIC KEY-----\n");
        activeKey.setKeyFilePath("runtime/keys/test.pk8");
        activeKey.setStatus("ACTIVE");

        fakeResult = new SigningService.SignResult(
                null,
                "{\"format\":\"ACNS-DSIG\",\"version\":1}",
                SAMPLE_DOC_HASH,
                SAMPLE_FINGERPRINT,
                1024L
        );

        when(userService.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(keyManagementService.getKeysForUser(1L)).thenReturn(List.of(activeKey));

        // Default: save to a real temp path so the controller can open it
        Path tmpFile = Files.createTempFile("test-upload", ".tmp");
        Files.write(tmpFile, "Hello, world!".getBytes());
        when(uploadGuard.saveToIsolatedTempFile(any())).thenReturn(tmpFile);
        doNothing().when(uploadGuard).cleanupTempFile(any());
    }

    // ── GET /sign ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("GET /sign — authenticated user sees signing page with key list")
    @WithMockUser(username = "testuser")
    void showSignPage_authenticated_rendersPage() throws Exception {
        mockMvc.perform(get("/sign"))
                .andExpect(status().isOk())
                .andExpect(view().name("sign"))
                .andExpect(model().attributeExists("keys"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("My Test Key")));
    }

    @Test
    @DisplayName("GET /sign — unauthenticated request redirects to /login")
    void showSignPage_unauthenticated_redirectsToLogin() throws Exception {
        mockMvc.perform(get("/sign"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login"));
    }

    // ── POST /sign — success flows ─────────────────────────────────────────────

    @Test
    @DisplayName("POST /sign — valid upload without download flag shows result in model")
    @WithMockUser(username = "testuser")
    void processSign_validDocument_showsSignResult() throws Exception {
        when(signingAppService.signDocument(
                eq(1L), eq(KEY_ID), any(char[].class),
                anyString(), any(), eq("testuser")))
                .thenReturn(fakeResult);

        MockMultipartFile file = new MockMultipartFile(
                "document", "report.pdf",
                "application/pdf", "PDF content".getBytes());

        mockMvc.perform(multipart("/sign")
                        .file(file)
                        .with(csrf())
                        .param("keyId", KEY_ID)
                        .param("passphrase", "correct-passphrase"))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("signResult"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Signature Generated")));
    }

    @Test
    @DisplayName("POST /sign — download=true returns attachment with .dsig.json filename")
    @WithMockUser(username = "testuser")
    void processSign_withDownload_returnsAttachment() throws Exception {
        when(signingAppService.signDocument(
                eq(1L), eq(KEY_ID), any(char[].class),
                anyString(), any(), eq("testuser")))
                .thenReturn(fakeResult);

        MockMultipartFile file = new MockMultipartFile(
                "document", "contract.pdf",
                "application/pdf", "Contract content".getBytes());

        mockMvc.perform(multipart("/sign")
                        .file(file)
                        .with(csrf())
                        .param("keyId", KEY_ID)
                        .param("passphrase", "correct-passphrase")
                        .param("download", "true"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition",
                        org.hamcrest.Matchers.containsString("contract.pdf.dsig.json")));
    }

    // ── POST /sign — error flows ───────────────────────────────────────────────

    @Test
    @DisplayName("POST /sign — wrong passphrase shows user-friendly error, no stack trace exposed")
    @WithMockUser(username = "testuser")
    void processSign_wrongPassphrase_showsUserFriendlyError() throws Exception {
        when(signingAppService.signDocument(
                eq(1L), eq(KEY_ID), any(char[].class),
                anyString(), any(), eq("testuser")))
                .thenThrow(new RuntimeException("Invalid passphrase or decryption failure"));

        MockMultipartFile file = new MockMultipartFile(
                "document", "letter.pdf",
                "application/pdf", "Letter".getBytes());

        mockMvc.perform(multipart("/sign")
                        .file(file)
                        .with(csrf())
                        .param("keyId", KEY_ID)
                        .param("passphrase", "wrong-passphrase"))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("error"))
                .andExpect(model().attributeDoesNotExist("signResult"))
                // Must not expose internal exception class names to the user
                .andExpect(content().string(
                        org.hamcrest.Matchers.not(
                                org.hamcrest.Matchers.containsString("java.lang"))))
                .andExpect(content().string(
                        org.hamcrest.Matchers.not(
                                org.hamcrest.Matchers.containsString("at com.acns"))));
    }

    @Test
    @DisplayName("POST /sign — empty file upload is rejected with user-friendly error")
    @WithMockUser(username = "testuser")
    void processSign_emptyFile_showsError() throws Exception {
        when(uploadGuard.saveToIsolatedTempFile(any()))
                .thenThrow(new IllegalArgumentException("Upload file is empty or missing"));

        MockMultipartFile emptyFile = new MockMultipartFile(
                "document", "empty.pdf",
                "application/pdf", new byte[0]);

        mockMvc.perform(multipart("/sign")
                        .file(emptyFile)
                        .with(csrf())
                        .param("keyId", KEY_ID)
                        .param("passphrase", "any-passphrase"))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("error"))
                .andExpect(model().attributeDoesNotExist("signResult"));
    }

    @Test
    @DisplayName("POST /sign — signing with a key owned by another user is rejected")
    @WithMockUser(username = "testuser")
    void processSign_keyOwnedByOtherUser_showsError() throws Exception {
        when(signingAppService.signDocument(
                eq(1L), eq(KEY_ID), any(char[].class),
                anyString(), any(), eq("testuser")))
                .thenThrow(new SecurityException("User does not own this signing key"));

        MockMultipartFile file = new MockMultipartFile(
                "document", "report.pdf",
                "application/pdf", "Report".getBytes());

        mockMvc.perform(multipart("/sign")
                        .file(file)
                        .with(csrf())
                        .param("keyId", KEY_ID)
                        .param("passphrase", "any-passphrase"))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("error"))
                .andExpect(model().attributeDoesNotExist("signResult"));
    }

    @Test
    @DisplayName("POST /sign — retired key rejected with user-friendly error")
    @WithMockUser(username = "testuser")
    void processSign_retiredKey_showsError() throws Exception {
        when(signingAppService.signDocument(
                eq(1L), eq(KEY_ID), any(char[].class),
                anyString(), any(), eq("testuser")))
                .thenThrow(new IllegalStateException(
                        "Key 'My Test Key' has status 'RETIRED' and cannot be used for new signing operations."));

        MockMultipartFile file = new MockMultipartFile(
                "document", "report.pdf",
                "application/pdf", "Report".getBytes());

        mockMvc.perform(multipart("/sign")
                        .file(file)
                        .with(csrf())
                        .param("keyId", KEY_ID)
                        .param("passphrase", "any-passphrase"))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("error"))
                .andExpect(model().attributeDoesNotExist("signResult"));
    }

    // ── Security checks ────────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /sign — missing CSRF token returns 403 Forbidden")
    @WithMockUser(username = "testuser")
    void processSign_missingCsrfToken_returns403() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "document", "report.pdf",
                "application/pdf", "Report".getBytes());

        mockMvc.perform(multipart("/sign")
                        .file(file)
                        // No .with(csrf())
                        .param("keyId", KEY_ID)
                        .param("passphrase", "any-passphrase"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("POST /sign — response body does not contain 'PRIVATE KEY' text")
    @WithMockUser(username = "testuser")
    void processSign_responseNeverContainsPrivateKeyMaterial() throws Exception {
        when(signingAppService.signDocument(
                eq(1L), eq(KEY_ID), any(char[].class),
                anyString(), any(), eq("testuser")))
                .thenReturn(fakeResult);

        MockMultipartFile file = new MockMultipartFile(
                "document", "report.pdf",
                "application/pdf", "Report".getBytes());

        mockMvc.perform(multipart("/sign")
                        .file(file)
                        .with(csrf())
                        .param("keyId", KEY_ID)
                        .param("passphrase", "correct-passphrase"))
                .andExpect(status().isOk())
                .andExpect(content().string(
                        org.hamcrest.Matchers.not(
                                org.hamcrest.Matchers.containsString("PRIVATE KEY"))));
    }

    @Test
    @DisplayName("POST /sign — uploaded filenames with path traversal tokens are sanitized")
    @WithMockUser(username = "testuser")
    void processSign_sanitizesUploadedFilename() throws Exception {
        when(uploadGuard.sanitizeFilename("../../evil_script.sh")).thenReturn("evil_script.sh");
        when(signingAppService.signDocument(
                eq(1L), eq(KEY_ID), any(char[].class),
                eq("evil_script.sh"), any(), eq("testuser")))
                .thenReturn(fakeResult);

        MockMultipartFile file = new MockMultipartFile(
                "document", "../../evil_script.sh",
                "application/octet-stream", "Payload".getBytes());

        mockMvc.perform(multipart("/sign")
                        .file(file)
                        .with(csrf())
                        .param("keyId", KEY_ID)
                        .param("passphrase", "correct-passphrase")
                        .param("download", "true"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition",
                        org.hamcrest.Matchers.containsString("evil_script.sh.dsig.json")));
    }
}
