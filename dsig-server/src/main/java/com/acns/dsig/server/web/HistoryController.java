package com.acns.dsig.server.web;

import com.acns.dsig.server.persistence.User;
import com.acns.dsig.server.persistence.VerificationRecord;
import com.acns.dsig.server.service.HistoryService;
import com.acns.dsig.server.service.UserService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

/**
 * Controller for Verification History and Audit Views.
 *
 * Technical Owner: Member 8 — Jay Pandya (Verification Web Interface & Trust UI)
 * Coordinates with: Member 6 (Nityanand Upadhyay - Persistence & H2 Verification Records)
 */
@Controller
@RequestMapping("/history")
public class HistoryController {

    private final HistoryService historyService;
    private final UserService userService;

    public HistoryController(HistoryService historyService, UserService userService) {
        this.historyService = historyService;
        this.userService = userService;
    }

    @GetMapping
    public String showHistory(@AuthenticationPrincipal UserDetails userDetails, Model model) {
        User user = userService.findByUsername(userDetails.getUsername()).orElseThrow();
        List<VerificationRecord> records = historyService.getHistoryForUser(user.getId());
        model.addAttribute("records", records);

        // Compute summary metrics for UI display
        long totalCount = records.size();
        long validTrustedCount = records.stream()
                .filter(r -> "VALID_TRUSTED".equals(r.getResultCode()))
                .count();
        long untrustedSignerCount = records.stream()
                .filter(r -> "VALID_UNTRUSTED_SIGNER".equals(r.getResultCode()))
                .count();
        long tamperedCount = records.stream()
                .filter(r -> "DOCUMENT_TAMPERED".equals(r.getResultCode()))
                .count();
        long otherCount = totalCount - (validTrustedCount + untrustedSignerCount + tamperedCount);

        model.addAttribute("totalCount", totalCount);
        model.addAttribute("validTrustedCount", validTrustedCount);
        model.addAttribute("untrustedSignerCount", untrustedSignerCount);
        model.addAttribute("tamperedCount", tamperedCount);
        model.addAttribute("otherCount", otherCount);

        return "history";
    }
}
