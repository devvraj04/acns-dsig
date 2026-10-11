package com.acns.dsig.server.web;

import com.acns.dsig.core.api.VerificationResult;
import com.acns.dsig.server.persistence.User;
import com.acns.dsig.server.security.UploadGuard;
import com.acns.dsig.server.service.UserService;
import com.acns.dsig.server.service.VerificationAppService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

@Controller
@RequestMapping("/verify")
public class VerifyController {

    private final VerificationAppService verificationAppService;
    private final UserService userService;
    private final UploadGuard uploadGuard;

    public VerifyController(
            VerificationAppService verificationAppService,
            UserService userService,
            UploadGuard uploadGuard
    ) {
        this.verificationAppService = verificationAppService;
        this.userService = userService;
        this.uploadGuard = uploadGuard;
    }

    @GetMapping
    public String showVerifyPage() {
        return "verify";
    }

    @PostMapping
    public String processVerification(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam("document") MultipartFile documentFile,
            @RequestParam("envelope") MultipartFile envelopeFile,
            Model model
    ) {
        Long userId = null;
        if (userDetails != null) {
            userId = userService.findByUsername(userDetails.getUsername()).map(User::getId).orElse(null);
        }

        Path tempDoc = null;
        try {
            uploadGuard.validateEnvelope(envelopeFile);
            tempDoc = uploadGuard.saveToIsolatedTempFile(documentFile);
            String envelopeJson = new String(envelopeFile.getBytes(), StandardCharsets.UTF_8);

            try (InputStream in = new FileInputStream(tempDoc.toFile())) {
                VerificationResult result = verificationAppService.verifyDocument(userId, in, envelopeJson);
                model.addAttribute("result", result);
                return "result";
            }
        } catch (Exception e) {
            model.addAttribute("error", "Verification execution failed: " + e.getMessage());
            return "verify";
        } finally {
            uploadGuard.cleanupTempFile(tempDoc);
        }
    }
}
