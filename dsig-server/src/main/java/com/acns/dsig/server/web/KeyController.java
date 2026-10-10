package com.acns.dsig.server.web;

import com.acns.dsig.core.keys.Fingerprint;
import com.acns.dsig.server.persistence.KeyPairEntity;
import com.acns.dsig.server.persistence.User;
import com.acns.dsig.server.service.KeyManagementService;
import com.acns.dsig.server.service.UserService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/keys")
public class KeyController {

    private final KeyManagementService keyManagementService;
    private final UserService userService;

    public KeyController(KeyManagementService keyManagementService, UserService userService) {
        this.keyManagementService = keyManagementService;
        this.userService = userService;
    }

    @GetMapping
    public String listKeys(@AuthenticationPrincipal UserDetails userDetails, Model model) {
        User user = userService.findByUsername(userDetails.getUsername()).orElseThrow();
        List<KeyPairEntity> keys = keyManagementService.getKeysForUser(user.getId());
        model.addAttribute("keys", keys);
        return "keys";
    }

    @PostMapping("/generate")
    public String generateKey(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam String label,
            @RequestParam String passphrase,
            Model model
    ) {
        User user = userService.findByUsername(userDetails.getUsername()).orElseThrow();
        try {
            KeyPairEntity created = keyManagementService.generateAndStoreKey(user.getId(), label, passphrase.toCharArray());
            model.addAttribute("success", "Key generated! Fingerprint: " + Fingerprint.formatGrouped(created.getKeyId()));
        } catch (Exception e) {
            model.addAttribute("error", "Failed to generate key: " + e.getMessage());
        }
        return listKeys(userDetails, model);
    }
}
