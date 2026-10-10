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

import java.util.List;

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
    public String listTrustStore(@AuthenticationPrincipal UserDetails userDetails, Model model) {
        User user = userService.findByUsername(userDetails.getUsername()).orElseThrow();
        List<TrustedSigner> signers = trustStoreService.getSignersForUser(user.getId());
        model.addAttribute("signers", signers);
        return "trust";
    }

    @PostMapping("/pin")
    public String pinFingerprint(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam String fingerprint,
            @RequestParam String label,
            @RequestParam(required = false) String note,
            Model model
    ) {
        User user = userService.findByUsername(userDetails.getUsername()).orElseThrow();
        try {
            trustStoreService.pinFingerprint(user.getId(), fingerprint, label, note);
            model.addAttribute("success", "Signer fingerprint successfully pinned!");
        } catch (Exception e) {
            model.addAttribute("error", "Failed to pin fingerprint: " + e.getMessage());
        }
        return listTrustStore(userDetails, model);
    }

    @PostMapping("/revoke/{id}")
    public String revokeSigner(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long id
    ) {
        User user = userService.findByUsername(userDetails.getUsername()).orElseThrow();
        trustStoreService.revokeSigner(user.getId(), id);
        return "redirect:/trust";
    }
}
