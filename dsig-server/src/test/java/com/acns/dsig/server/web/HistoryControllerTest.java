package com.acns.dsig.server.web;

import com.acns.dsig.server.persistence.User;
import com.acns.dsig.server.persistence.VerificationRecord;
import com.acns.dsig.server.service.HistoryService;
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

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * UI integration tests for the Verification History screen.
 *
 * Technical Owner: Member 8 — Jay Pandya (Verification Web Interface & Trust UI)
 * Review Partner: Member 7 — KVS Varshith (Signing Web Interface)
 *
 * Covers:
 *   - History page loads successfully for authenticated users
 *   - Aggregates and displays verification statistics in the model
 *   - Renders chronological records table
 *   - Handles empty records list gracefully
 *   - Unauthenticated requests are redirected to /login
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("HistoryController — Verification History UI Integration Tests")
class HistoryControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private HistoryService historyService;

    @MockBean
    private UserService userService;

    private User testUser;
    private VerificationRecord record1;
    private VerificationRecord record2;
    private VerificationRecord record3;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setId(301L);
        testUser.setUsername("history_user_jay");

        when(userService.findByUsername("history_user_jay")).thenReturn(Optional.of(testUser));

        record1 = new VerificationRecord();
        record1.setId(1L);
        record1.setUserId(301L);
        record1.setDocName("valid_document.pdf");
        record1.setResultCode("VALID_TRUSTED");
        record1.setTrustStatus("TRUSTED");
        record1.setKeyId("1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff");
        record1.setVerifiedAt(Instant.parse("2026-10-11T10:00:00Z"));

        record2 = new VerificationRecord();
        record2.setId(2L);
        record2.setUserId(301L);
        record2.setDocName("tampered_document.docx");
        record2.setResultCode("DOCUMENT_TAMPERED");
        record2.setTrustStatus("TRUSTED");
        record2.setKeyId("1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff");
        record2.setVerifiedAt(Instant.parse("2026-10-11T11:00:00Z"));

        record3 = new VerificationRecord();
        record3.setId(3L);
        record3.setUserId(301L);
        record3.setDocName("untrusted_doc.txt");
        record3.setResultCode("VALID_UNTRUSTED_SIGNER");
        record3.setTrustStatus("UNTRUSTED");
        record3.setKeyId("9999888877776666555544443333222211110000aaaabbbbccccddddeeeeffff");
        record3.setVerifiedAt(Instant.parse("2026-10-11T12:00:00Z"));
    }

    @Test
    @DisplayName("GET /history — Displays records and summary statistics")
    @WithMockUser(username = "history_user_jay", roles = {"VERIFIER"})
    void testShowHistory_DisplaysRecordsAndMetrics() throws Exception {
        when(historyService.getHistoryForUser(301L)).thenReturn(List.of(record1, record2, record3));

        mockMvc.perform(get("/history"))
                .andExpect(status().isOk())
                .andExpect(view().name("history"))
                .andExpect(model().attribute("totalCount", 3L))
                .andExpect(model().attribute("validTrustedCount", 1L))
                .andExpect(model().attribute("tamperedCount", 1L))
                .andExpect(model().attribute("untrustedSignerCount", 1L))
                .andExpect(model().attribute("otherCount", 0L))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("valid_document.pdf")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("tampered_document.docx")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("untrusted_doc.txt")));
    }

    @Test
    @DisplayName("GET /history with empty records renders empty state view")
    @WithMockUser(username = "history_user_jay", roles = {"VERIFIER"})
    void testShowHistory_EmptyRecords() throws Exception {
        when(historyService.getHistoryForUser(301L)).thenReturn(List.of());

        mockMvc.perform(get("/history"))
                .andExpect(status().isOk())
                .andExpect(view().name("history"))
                .andExpect(model().attribute("totalCount", 0L))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("No document verifications recorded yet")));
    }

    @Test
    @DisplayName("GET /history — Unauthenticated request redirects to /login")
    void testShowHistory_UnauthenticatedRedirects() throws Exception {
        mockMvc.perform(get("/history"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login"));
    }
}
