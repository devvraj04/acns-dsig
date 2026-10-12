package com.acns.dsig.server.web;

import com.acns.dsig.core.sign.SigningService;
import com.acns.dsig.server.persistence.KeyPairEntity;
import com.acns.dsig.server.persistence.User;
import com.acns.dsig.server.security.UploadGuard;
import com.acns.dsig.server.service.KeyManagementService;
import com.acns.dsig.server.service.SigningAppService;
import com.acns.dsig.server.service.UserService;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

@Controller
@RequestMapping("/sign")
public class SignController {

    private final SigningAppService signingAppService;
    private final KeyManagementService keyManagementService;
    private final UserService userService;
    private final UploadGuard uploadGuard;

    public SignController(
            SigningAppService signingAppService,
            KeyManagementService keyManagementService,
            UserService userService,
            UploadGuard uploadGuard
    ) {
        this.signingAppService = signingAppService;
        this.keyManagementService = keyManagementService;
        this.userService = userService;
        this.uploadGuard = uploadGuard;
    }

    @GetMapping
    public String showSignPage(@AuthenticationPrincipal UserDetails userDetails, Model model) {
        User user = userService.findByUsername(userDetails.getUsername()).orElseThrow();
        List<KeyPairEntity> keys = keyManagementService.getKeysForUser(user.getId());
        model.addAttribute("keys", keys);
        model.addAttribute("engineInfo", new com.acns.dsig.core.crypto.SignatureService().describeEngine());
        return "sign";
    }

    @PostMapping
    public Object processSign(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam("document") MultipartFile documentFile,
            @RequestParam("keyId") String keyId,
            @RequestParam("passphrase") String passphrase,
            @RequestParam(value = "download", defaultValue = "false") boolean download,
            Model model
    ) {
        User user = userService.findByUsername(userDetails.getUsername()).orElseThrow();
        Path tempPath = null;
        try {
            String originalName = documentFile.getOriginalFilename();
            String safeDocName = uploadGuard != null ? uploadGuard.sanitizeFilename(originalName) : null;
            if (safeDocName == null || safeDocName.isBlank()) {
                safeDocName = originalName != null ? originalName : "unnamed_document";
            }
            tempPath = uploadGuard.saveToIsolatedTempFile(documentFile);
            try (InputStream in = new FileInputStream(tempPath.toFile())) {
                SigningService.SignResult result = signingAppService.signDocument(
                        user.getId(),
                        keyId,
                        passphrase.toCharArray(),
                        safeDocName,
                        in,
                        user.getUsername()
                );

                if (download) {
                    byte[] envelopeBytes = result.envelopeJson().getBytes(StandardCharsets.UTF_8);
                    ByteArrayResource resource = new ByteArrayResource(envelopeBytes);
                    String fileName = safeDocName + ".dsig.json";
                    ContentDisposition contentDisposition = ContentDisposition.attachment()
                            .filename(fileName, StandardCharsets.UTF_8)
                            .build();
                    return ResponseEntity.ok()
                            .header(HttpHeaders.CONTENT_DISPOSITION, contentDisposition.toString())
                            .contentType(MediaType.APPLICATION_JSON)
                            .body(resource);
                }

                model.addAttribute("documentName", safeDocName);
                model.addAttribute("signResult", result);
                return showSignPage(userDetails, model);
            }
        } catch (Exception e) {
            model.addAttribute("error", "Signing failed: " + e.getMessage());
            return showSignPage(userDetails, model);
        } finally {
            uploadGuard.cleanupTempFile(tempPath);
        }
    }
}
