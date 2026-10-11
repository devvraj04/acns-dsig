package com.acns.dsig.server.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Sliding window rate limiting filter for sensitive endpoints.
 * Protects CPU-intensive cryptographic endpoints (signing, verification, key generation)
 * and authentication endpoints (login, register) against brute-force and denial-of-service.
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    public static final int DEFAULT_MAX_REQUESTS_PER_MINUTE = 60;
    private static final long WINDOW_MS = 60_000L;

    private final int maxRequestsPerMinute;
    private final boolean trustForwardedFor;
    private final Map<String, RequestCounter> requestCounts = new ConcurrentHashMap<>();

    private static class RequestCounter {
        final long windowStart;
        final AtomicInteger count;

        RequestCounter(long windowStart) {
            this.windowStart = windowStart;
            this.count = new AtomicInteger(1);
        }
    }

    @Autowired
    public RateLimitFilter(
            @Value("${dsig.security.rate-limit.max-per-minute:60}") int maxRequestsPerMinute,
            @Value("${dsig.security.rate-limit.trust-forwarded-for:false}") boolean trustForwardedFor
    ) {
        this.maxRequestsPerMinute = maxRequestsPerMinute > 0 ? maxRequestsPerMinute : DEFAULT_MAX_REQUESTS_PER_MINUTE;
        this.trustForwardedFor = trustForwardedFor;
    }

    public RateLimitFilter(int maxRequestsPerMinute) {
        this(maxRequestsPerMinute, false);
    }

    public RateLimitFilter() {
        this(DEFAULT_MAX_REQUESTS_PER_MINUTE, false);
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String uri = request.getRequestURI();

        if (isRateLimitedEndpoint(uri)) {
            String clientIp = resolveClientIp(request);
            String key = clientIp + ":" + getEndpointCategory(uri);

            long now = System.currentTimeMillis();
            pruneExpiredEntries(now);

            RequestCounter counter = requestCounts.compute(key, (k, v) -> {
                if (v == null || (now - v.windowStart) > WINDOW_MS) {
                    return new RequestCounter(now);
                }
                v.count.incrementAndGet();
                return v;
            });

            if (counter.count.get() > maxRequestsPerMinute) {
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setHeader("Retry-After", "60");

                String acceptHeader = request.getHeader("Accept");
                if (uri.startsWith("/api/") || (acceptHeader != null && acceptHeader.contains("application/json"))) {
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"Too Many Requests\",\"message\":\"Rate limit exceeded. Try again in 60 seconds.\",\"retryAfter\":60}");
                } else {
                    response.setContentType("text/plain");
                    response.getWriter().write("429 Too Many Requests - Rate limit exceeded. Try again in 1 minute.");
                }
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean isRateLimitedEndpoint(String uri) {
        if (uri == null) return false;
        return uri.equals("/login") || uri.startsWith("/login")
                || uri.equals("/sign") || uri.startsWith("/sign")
                || uri.equals("/verify") || uri.startsWith("/verify")
                || uri.startsWith("/api/sign") || uri.startsWith("/api/verify")
                || uri.startsWith("/keys/generate")
                || uri.equals("/register") || uri.startsWith("/register");
    }

    private String getEndpointCategory(String uri) {
        if (uri.startsWith("/login")) return "/login";
        if (uri.startsWith("/sign") || uri.startsWith("/api/sign")) return "/sign";
        if (uri.startsWith("/verify") || uri.startsWith("/api/verify")) return "/verify";
        if (uri.startsWith("/keys/generate")) return "/keys/generate";
        if (uri.startsWith("/register")) return "/register";
        return uri;
    }

    private String resolveClientIp(HttpServletRequest request) {
        if (trustForwardedFor) {
            String xForwardedFor = request.getHeader("X-Forwarded-For");
            if (xForwardedFor != null && !xForwardedFor.isBlank() && !"unknown".equalsIgnoreCase(xForwardedFor)) {
                int commaIdx = xForwardedFor.indexOf(',');
                if (commaIdx != -1) {
                    return xForwardedFor.substring(0, commaIdx).trim();
                }
                return xForwardedFor.trim();
            }
        }
        String remoteAddr = request.getRemoteAddr();
        return (remoteAddr != null && !remoteAddr.isBlank()) ? remoteAddr : "unknown";
    }

    private void pruneExpiredEntries(long now) {
        if (requestCounts.size() > 500) {
            requestCounts.entrySet().removeIf(entry -> (now - entry.getValue().windowStart) > (2 * WINDOW_MS));
        }
    }

    public void reset() {
        requestCounts.clear();
    }

    public int getMaxRequestsPerMinute() {
        return maxRequestsPerMinute;
    }
}
