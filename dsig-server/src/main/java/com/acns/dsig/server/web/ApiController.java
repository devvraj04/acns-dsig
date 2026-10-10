package com.acns.dsig.server.web;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        return ResponseEntity.ok(Map.of(
                "status", "UP",
                "system", "ACNS-DSIG Server",
                "timestamp", Instant.now().toString(),
                "algorithms", Map.of(
                        "hash", "SHA-256",
                        "signature", "RSASSA-PSS-SHA256-MGF1SHA256-S32",
                        "rsaModulusBits", 3072
                )
        ));
    }
}
