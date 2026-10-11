package com.acns.dsig.server.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("SecurityHeadersConfig — Security Policy Specification & Wire Header Tests")
class SecurityHeadersTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Actual HTTP responses contain strict CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy")
    void actualHttpResponses_containAllSecurityHeaders() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Referrer-Policy", "strict-origin-when-cross-origin"))
                .andExpect(header().string("Content-Security-Policy", containsString("default-src 'self'")))
                .andExpect(header().string("Permissions-Policy", containsString("camera=()")));
    }

    @Test
    @DisplayName("Content Security Policy defines strict script, frame, object, and style rules")
    void cspPolicy_isStrict() {
        String csp = SecurityHeadersConfig.CSP_POLICY;
        assertNotNull(csp);
        assertTrue(csp.contains("default-src 'self'"));
        assertTrue(csp.contains("object-src 'none'"));
        assertTrue(csp.contains("frame-ancestors 'none'"));
        assertTrue(csp.contains("base-uri 'self'"));
        assertTrue(csp.contains("form-action 'self'"));
    }

    @Test
    @DisplayName("HSTS max age is configured to 1 year (31536000 seconds)")
    void hstsMaxAge_isOneYear() {
        assertEquals(31536000L, SecurityHeadersConfig.HSTS_MAX_AGE_SECONDS);
    }

    @Test
    @DisplayName("Permissions Policy restricts invasive browser capabilities")
    void permissionsPolicy_restrictsFeatures() {
        String permissions = SecurityHeadersConfig.PERMISSIONS_POLICY;
        assertNotNull(permissions);
        assertTrue(permissions.contains("camera=()"));
        assertTrue(permissions.contains("microphone=()"));
        assertTrue(permissions.contains("geolocation=()"));
    }

    @Test
    @DisplayName("Referrer Policy enforces strict origin when cross-origin")
    void referrerPolicy_isStrictOrigin() {
        assertEquals("strict-origin-when-cross-origin", SecurityHeadersConfig.REFERRER_POLICY);
    }
}
