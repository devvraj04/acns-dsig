package com.acns.dsig.server.web;

import com.acns.dsig.core.keys.Fingerprint;
import com.acns.dsig.server.persistence.KeyPairEntity;
import com.acns.dsig.server.persistence.User;
import com.acns.dsig.server.service.KeyManagementService;
import com.acns.dsig.server.service.UserService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Web controller for RSA key management.
 * Owns: key-generation screen, key listing, public-key export, key retirement.
 * Security guarantee: private-key material is never rendered to the browser or
 * returned through any response body or template.
 */
@Controller
@RequestMapping("/keys")
public class KeyController {

    private final KeyManagementService keyManagementService;
    private final UserService userService;

    public KeyController(KeyManagementService keyManagementService, UserService userService) {
        this.keyManagementService = keyManagementService;
        this.userService = userService;
    }

    // ── GET /keys ────────────────────────────────────────────────────────────

    @GetMapping
    public String listKeys(@AuthenticationPrincipal UserDetails userDetails, Model model) {
        User user = userService.findByUsername(userDetails.getUsername()).orElseThrow();
        List<KeyPairEntity> keys = keyManagementService.getKeysForUser(user.getId());
        model.addAttribute("keys", keys);
        return "keys";
    }

    // ── POST /keys/generate ───────────────────────────────────────────────────

    /**
     * Generates an RSA-3072 key pair for the authenticated user.
     * Validates passphrase confirmation client-side (sign.js) and server-side here.
     * Private key bytes are encrypted at rest and never returned to the browser.
     */
    @PostMapping("/generate")
    public String generateKey(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam("label") String label,
            @RequestParam("passphrase") String passphrase,
            @RequestParam(value = "passphraseConfirm", defaultValue = "") String passphraseConfirm,
            Model model
    ) {
        User user = userService.findByUsername(userDetails.getUsername()).orElseThrow();

        // Server-side passphrase confirmation (defence-in-depth; client also validates)
        if (!passphrase.equals(passphraseConfirm)) {
            model.addAttribute("error", "Passphrases do not match. Please re-enter both fields.");
            return listKeys(userDetails, model);
        }
        if (passphrase.length() < 8) {
            model.addAttribute("error", "Passphrase must be at least 8 characters.");
            return listKeys(userDetails, model);
        }
        if (label == null || label.isBlank()) {
            model.addAttribute("error", "A key label is required.");
            return listKeys(userDetails, model);
        }

        try {
            KeyPairEntity created = keyManagementService.generateAndStoreKey(
                    user.getId(), label.strip(), passphrase.toCharArray());
            String grouped = Fingerprint.formatGrouped(created.getKeyId());
            model.addAttribute("success",
                    "RSA-3072 key pair generated successfully.\n" +
                    "Label: " + created.getLabel() + "\n" +
                    "SHA-256 Fingerprint: " + grouped + "\n" +
                    "Share the fingerprint out-of-band so verifiers can pin your key.");
            model.addAttribute("newKeyId", created.getKeyId());
        } catch (Exception e) {
            model.addAttribute("error", "Key generation failed: " + e.getMessage());
        }
        return listKeys(userDetails, model);
    }

    // ── GET /keys/{keyId}/public ──────────────────────────────────────────────

    /**
     * Downloads the PEM-encoded SubjectPublicKeyInfo for the specified key.
     * Ownership is enforced: only the key owner may export it.
     * Private key material is never returned by this or any other endpoint.
     */
    @GetMapping("/{keyId}/public")
    public ResponseEntity<byte[]> downloadPublicKey(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable("keyId") String keyId
    ) {
        User user = userService.findByUsername(userDetails.getUsername()).orElseThrow();
        KeyPairEntity keyEntity = keyManagementService.getKey(keyId)
                .orElseThrow(() -> new IllegalArgumentException("Key not found: " + keyId));

        // Ownership check — prevent IDOR
        if (!keyEntity.getOwnerId().equals(user.getId())) {
            return ResponseEntity.status(403).build();
        }

        byte[] pemBytes = keyEntity.getPublicPem().getBytes(StandardCharsets.UTF_8);
        String safeFilename = "public-" + keyId.substring(0, 8) + ".pem";

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + safeFilename + "\"")
                .contentType(MediaType.valueOf("application/x-pem-file"))
                .body(pemBytes);
    }

    // ── POST /keys/{keyId}/retire ─────────────────────────────────────────────

    /**
     * Marks the specified key as RETIRED.
     * Retired keys cannot be used for new signatures; old signatures may remain
     * mathematically verifiable but trust status is evaluated separately.
     */
    @PostMapping("/{keyId}/retire")
    public String retireKey(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable("keyId") String keyId,
            Model model
    ) {
        User user = userService.findByUsername(userDetails.getUsername()).orElseThrow();
        try {
            keyManagementService.retireKey(user.getId(), keyId);
            model.addAttribute("success",
                    "Key " + keyId.substring(0, 8) + "... has been marked as RETIRED. " +
                    "It can no longer be used for new signing operations.");
        } catch (SecurityException e) {
            model.addAttribute("error", "Unauthorised: " + e.getMessage());
        } catch (Exception e) {
            model.addAttribute("error", "Retire operation failed: " + e.getMessage());
        }
        return listKeys(userDetails, model);
    }
}
