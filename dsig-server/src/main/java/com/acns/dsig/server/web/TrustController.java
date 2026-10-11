package com.acns.dsig.server.web;

import com.acns.dsig.server.persistence.TrustedSigner;
import com.acns.dsig.server.persistence.User;
import com.acns.dsig.server.service.TrustStoreService;
import com.acns.dsig.server.service.UserService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

/**
 * Controller for Signer Trust Store and Fingerprint Pinning.
 *
 * Technical Owner: Member 8 — Jay Pandya (Verification Web Interface & Trust UI)
 * Coordinates with: Member 6 (Nityanand Upadhyay - Persistence & H2 Trust Store)
 */
@Controller
@RequestMapping("/trust")
public class TrustController {

    private final TrustStoreService trustStoreService;
    private final UserService userService;

    public TrustController(TrustStoreService trustStoreService, UserService userService) {
        this.trustStoreService = trustStoreService;
        this.userService = userService;
    }

    @GetMapping
    public String listTrustStore(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(value = "fingerprint", required = false) String prefillFingerprint,
            @RequestParam(value = "label", required = false) String prefillLabel,
            Model model
    ) {
        User user = userService.findByUsername(userDetails.getUsername()).orElseThrow();
        List<TrustedSigner> signers = trustStoreService.getSignersForUser(user.getId());
        model.addAttribute("signers", signers);
        if (prefillFingerprint != null && !prefillFingerprint.isBlank()) {
            model.addAttribute("prefillFingerprint", prefillFingerprint.trim());
        }
        if (prefillLabel != null && !prefillLabel.isBlank()) {
            model.addAttribute("prefillLabel", prefillLabel.trim());
        }
        return "trust";
    }

    @PostMapping("/pin")
    public String pinFingerprint(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam("fingerprint") String fingerprint,
            @RequestParam("label") String label,
            @RequestParam(value = "note", required = false) String note,
            Model model
    ) {
        User user = userService.findByUsername(userDetails.getUsername()).orElseThrow();

        if (label == null || label.trim().isEmpty()) {
            model.addAttribute("error", "Signer label or organization name is required.");
            return reloadTrustModel(user, model, fingerprint, label, note);
        }

        String cleanFp = (fingerprint != null) ? fingerprint.replaceAll("[^a-fA-F0-9]", "").toLowerCase() : "";
        if (cleanFp.length() != 64) {
            model.addAttribute("error", "Invalid SHA-256 fingerprint: Expected exactly 64 hexadecimal characters.");
            return reloadTrustModel(user, model, fingerprint, label, note);
        }

        try {
            trustStoreService.pinFingerprint(user.getId(), cleanFp, label.trim(), note != null ? note.trim() : null);
            model.addAttribute("success", "Signer fingerprint successfully pinned as TRUSTED!");
        } catch (Exception e) {
            model.addAttribute("error", "Failed to pin fingerprint: " + e.getMessage());
            return reloadTrustModel(user, model, fingerprint, label, note);
        }

        List<TrustedSigner> signers = trustStoreService.getSignersForUser(user.getId());
        model.addAttribute("signers", signers);
        return "trust";
    }

    @PostMapping("/revoke/{id}")
    public String revokeSigner(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable("id") Long id,
            RedirectAttributes redirectAttributes
    ) {
        User user = userService.findByUsername(userDetails.getUsername()).orElseThrow();
        try {
            trustStoreService.revokeSigner(user.getId(), id);
            redirectAttributes.addFlashAttribute("success", "Signer trust was successfully revoked.");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Failed to revoke signer: " + e.getMessage());
        }
        return "redirect:/trust";
    }

    private String reloadTrustModel(User user, Model model, String fp, String label, String note) {
        List<TrustedSigner> signers = trustStoreService.getSignersForUser(user.getId());
        model.addAttribute("signers", signers);
        model.addAttribute("prefillFingerprint", fp);
        model.addAttribute("prefillLabel", label);
        model.addAttribute("prefillNote", note);
        return "trust";
    }
}
