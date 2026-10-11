package com.acns.dsig.server.web;

import com.acns.dsig.core.api.ResultCode;
import com.acns.dsig.core.api.TrustStatus;
import com.acns.dsig.core.api.VerificationResult;
import com.acns.dsig.server.persistence.User;
import com.acns.dsig.server.security.UploadGuard;
import com.acns.dsig.server.service.UserService;
import com.acns.dsig.server.service.VerificationAppService;
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

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * UI integration tests for the Document Verification & Results screens.
 *
 * Technical Owner: Member 8 — Jay Pandya (Verification Web Interface & Trust UI)
 * Review Partner: Member 7 — KVS Varshith (Signing Web Interface)
 *
 * Covers:
 *   - Verification page loads successfully for an authenticated user
 *   - Unauthenticated requests are redirected to /login
 *   - CSRF protection on POST /verify
 *   - Missing document or envelope triggers accessible validation error
 *   - VALID_TRUSTED outcome renders green badge and verified metadata
 *   - DOCUMENT_TAMPERED outcome displays side-by-side hash comparison and alert
 *   - VALID_UNTRUSTED_SIGNER outcome displays warning and quick-pin CTA
 *   - Envelope size cap rejection via UploadGuard
 *   - Temporary upload cleanup guarantee
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("VerifyController — Verification Web Interface Integration Tests")
class VerifyControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private VerificationAppService verificationAppService;

    @MockBean
    private UserService userService;

    @MockBean
    private UploadGuard uploadGuard;

    private User testUser;
    private Path tempDocFile;

    @BeforeEach
    void setUp() throws Exception {
        testUser = new User();
        testUser.setId(101L);
        testUser.setUsername("verifier_jay");

        when(userService.findByUsername("verifier_jay")).thenReturn(Optional.of(testUser));

        tempDocFile = Files.createTempFile("verify-test-doc-", ".tmp");
        Files.writeString(tempDocFile, "Sample contract content for verification");

        when(uploadGuard.saveToIsolatedTempFile(any())).thenReturn(tempDocFile);
    }

    @Test
    @DisplayName("GET /verify — Loads verification page with upload forms")
    @WithMockUser(username = "verifier_jay", roles = {"VERIFIER"})
    void testShowVerifyPage_Authenticated() throws Exception {
        mockMvc.perform(get("/verify"))
                .andExpect(status().isOk())
                .andExpect(view().name("verify"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Verify Document Authenticity")));
    }

    @Test
    @DisplayName("GET /verify — Unauthenticated user is redirected to /login")
    void testShowVerifyPage_UnauthenticatedRedirects() throws Exception {
        mockMvc.perform(get("/verify"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login"));
    }

    @Test
    @DisplayName("POST /verify without CSRF token is rejected with 403 Forbidden")
    @WithMockUser(username = "verifier_jay", roles = {"VERIFIER"})
    void testProcessVerification_RequiresCsrf() throws Exception {
        MockMultipartFile doc = new MockMultipartFile("document", "test.pdf", "application/pdf", "dummy".getBytes());
        MockMultipartFile env = new MockMultipartFile("envelope", "test.dsig.json", "application/json", "{}".getBytes());

        mockMvc.perform(multipart("/verify")
                        .file(doc)
                        .file(env))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("POST /verify with empty document displays validation error")
    @WithMockUser(username = "verifier_jay", roles = {"VERIFIER"})
    void testProcessVerification_MissingDocument() throws Exception {
        MockMultipartFile doc = new MockMultipartFile("document", "", "application/pdf", new byte[0]);
        MockMultipartFile env = new MockMultipartFile("envelope", "test.dsig.json", "application/json", "{}".getBytes());

        mockMvc.perform(multipart("/verify")
                        .file(doc)
                        .file(env)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("verify"))
                .andExpect(model().attributeExists("error"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Received document file is required")));
    }

    @Test
    @DisplayName("POST /verify with empty envelope displays validation error")
    @WithMockUser(username = "verifier_jay", roles = {"VERIFIER"})
    void testProcessVerification_MissingEnvelope() throws Exception {
        MockMultipartFile doc = new MockMultipartFile("document", "test.pdf", "application/pdf", "data".getBytes());
        MockMultipartFile env = new MockMultipartFile("envelope", "", "application/json", new byte[0]);

        mockMvc.perform(multipart("/verify")
                        .file(doc)
                        .file(env)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("verify"))
                .andExpect(model().attributeExists("error"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Signature envelope (.dsig.json) is required")));
    }

    @Test
    @DisplayName("POST /verify with VALID_TRUSTED outcome renders result view with green status")
    @WithMockUser(username = "verifier_jay", roles = {"VERIFIER"})
    void testProcessVerification_ValidTrustedOutcome() throws Exception {
        MockMultipartFile doc = new MockMultipartFile("document", "contract.pdf", "application/pdf", "contract bytes".getBytes());
        MockMultipartFile env = new MockMultipartFile("envelope", "contract.pdf.dsig.json", "application/json", "{\"version\":1}".getBytes());

        VerificationResult validResult = new VerificationResult(
                ResultCode.VALID_TRUSTED,
                TrustStatus.TRUSTED,
                "contract.pdf",
                1420L,
                "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "Alice Officer",
                "9f8e7d6c5b4a39f8e7d6c5b4a39f8e7d6c5b4a39f8e7d6c5b4a39f8e7d6c5b4a",
                Instant.parse("2026-10-11T12:00:00Z"),
                "nonce-12345",
                "Cryptographic signature verified and signer fingerprint is trusted."
        );

        when(verificationAppService.verifyDocument(eq(101L), any(InputStream.class), anyString()))
                .thenReturn(validResult);

        mockMvc.perform(multipart("/verify")
                        .file(doc)
                        .file(env)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("result"))
                .andExpect(model().attribute("result", validResult))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("VALID &amp; TRUSTED")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Alice Officer")));

        verify(uploadGuard).cleanupTempFile(tempDocFile);
    }

    @Test
    @DisplayName("POST /verify with DOCUMENT_TAMPERED renders red tamper alert and side-by-side hashes")
    @WithMockUser(username = "verifier_jay", roles = {"VERIFIER"})
    void testProcessVerification_TamperedDocumentOutcome() throws Exception {
        MockMultipartFile doc = new MockMultipartFile("document", "statement.txt", "text/plain", "tampered text".getBytes());
        MockMultipartFile env = new MockMultipartFile("envelope", "statement.txt.dsig.json", "application/json", "{\"version\":1}".getBytes());

        VerificationResult tamperedResult = new VerificationResult(
                ResultCode.DOCUMENT_TAMPERED,
                TrustStatus.TRUSTED,
                "statement.txt",
                800L,
                "1111111111111111111111111111111111111111111111111111111111111111",
                "2222222222222222222222222222222222222222222222222222222222222222",
                "Bob Signer",
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                Instant.parse("2026-10-11T12:00:00Z"),
                "nonce-tamper-check",
                "Recomputed document hash does not match signed manifest hash."
        );

        when(verificationAppService.verifyDocument(eq(101L), any(InputStream.class), anyString()))
                .thenReturn(tamperedResult);

        mockMvc.perform(multipart("/verify")
                        .file(doc)
                        .file(env)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("result"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("DOCUMENT TAMPERED")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("1111111111111111111111111111111111111111111111111111111111111111")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("2222222222222222222222222222222222222222222222222222222222222222")));

        verify(uploadGuard).cleanupTempFile(tempDocFile);
    }

    @Test
    @DisplayName("POST /verify with VALID_UNTRUSTED_SIGNER renders warning badge and quick-pin button")
    @WithMockUser(username = "verifier_jay", roles = {"VERIFIER"})
    void testProcessVerification_UntrustedSignerOutcome() throws Exception {
        MockMultipartFile doc = new MockMultipartFile("document", "memo.pdf", "application/pdf", "memo bytes".getBytes());
        MockMultipartFile env = new MockMultipartFile("envelope", "memo.pdf.dsig.json", "application/json", "{\"version\":1}".getBytes());

        String unpinnedFp = "abababababababababababababababababababababababababababababababab";
        VerificationResult untrustedResult = new VerificationResult(
                ResultCode.VALID_UNTRUSTED_SIGNER,
                TrustStatus.UNTRUSTED,
                "memo.pdf",
                500L,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "Charlie External",
                unpinnedFp,
                Instant.parse("2026-10-11T12:00:00Z"),
                "nonce-untrusted",
                "Signature authentic but signer key fingerprint is not pinned in trust store."
        );

        when(verificationAppService.verifyDocument(eq(101L), any(InputStream.class), anyString()))
                .thenReturn(untrustedResult);

        mockMvc.perform(multipart("/verify")
                        .file(doc)
                        .file(env)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("result"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("VALID SIGNATURE (UNTRUSTED SIGNER)")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("+ Pin to Trust Store")));
    }

    @Test
    @DisplayName("POST /verify envelope exceeding cap throws safe error without crashing")
    @WithMockUser(username = "verifier_jay", roles = {"VERIFIER"})
    void testProcessVerification_OversizedEnvelopeRejected() throws Exception {
        MockMultipartFile doc = new MockMultipartFile("document", "doc.pdf", "application/pdf", "data".getBytes());
        MockMultipartFile env = new MockMultipartFile("envelope", "oversized.json", "application/json", new byte[600 * 1024]);

        doThrow(new IllegalArgumentException("Envelope file size exceeds maximum allowable limit of 524288 bytes"))
                .when(uploadGuard).validateEnvelope(any());

        mockMvc.perform(multipart("/verify")
                        .file(doc)
                        .file(env)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("verify"))
                .andExpect(model().attributeExists("error"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("exceeds maximum allowable limit")));
    }
}
