package com.acns.dsig.server.security;

import org.springframework.context.annotation.Configuration;

/**
 * Constants and specifications for HTTP security hardening headers.
 * Defines Content Security Policy (CSP), HTTP Strict Transport Security (HSTS),
 * Permissions Policy, and Referrer Policy directives.
 */
public final class SecurityHeadersConfig {

    private SecurityHeadersConfig() {}

    public static final String CSP_POLICY =
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';";

    public static final String PERMISSIONS_POLICY =
            "camera=(), microphone=(), geolocation=()";

    public static final long HSTS_MAX_AGE_SECONDS = 31536000L; // 1 year

    public static final String REFERRER_POLICY =
            "strict-origin-when-cross-origin";
}
