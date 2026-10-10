package com.acns.dsig.server.security;

import org.springframework.context.annotation.Configuration;

/**
 * Constants and specifications for HTTP security hardening headers.
 */
@Configuration
public class SecurityHeadersConfig {
    public static final String CSP_POLICY =
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none';";
}
