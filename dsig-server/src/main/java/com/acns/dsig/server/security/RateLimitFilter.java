package com.acns.dsig.server.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Sliding window rate limiting filter for sensitive endpoints.
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final int MAX_REQUESTS_PER_MINUTE = 60;
    private final Map<String, RequestCounter> requestCounts = new ConcurrentHashMap<>();

    private static class RequestCounter {
        long windowStart = System.currentTimeMillis();
        AtomicInteger count = new AtomicInteger(0);
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String uri = request.getRequestURI();

        if (uri.startsWith("/login") || uri.startsWith("/api/sign") || uri.startsWith("/api/verify") || uri.startsWith("/verify")) {
            String clientIp = request.getRemoteAddr();
            String key = clientIp + ":" + uri;

            long now = System.currentTimeMillis();
            RequestCounter counter = requestCounts.compute(key, (k, v) -> {
                if (v == null || (now - v.windowStart) > 60_000) {
                    RequestCounter fresh = new RequestCounter();
                    fresh.count.set(1);
                    return fresh;
                }
                v.count.incrementAndGet();
                return v;
            });

            if (counter.count.get() > MAX_REQUESTS_PER_MINUTE) {
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setContentType("text/plain");
                response.getWriter().write("429 Too Many Requests - Rate limit exceeded. Try again in 1 minute.");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
