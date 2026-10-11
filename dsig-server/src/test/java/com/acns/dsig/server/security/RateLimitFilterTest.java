package com.acns.dsig.server.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@DisplayName("RateLimitFilter — Sliding Window Rate Limiting Tests")
class RateLimitFilterTest {

    private RateLimitFilter rateLimitFilter;
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        // Instantiate with low threshold (3 requests/min) for fast deterministic testing
        rateLimitFilter = new RateLimitFilter(3);
        filterChain = mock(FilterChain.class);
    }

    @Test
    @DisplayName("Requests within limit pass through filterChain")
    void requestsWithinLimit_pass() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login");
        request.setRemoteAddr("192.168.1.100");
        MockHttpServletResponse response = new MockHttpServletResponse();

        rateLimitFilter.doFilter(request, response, filterChain);

        assertEquals(200, response.getStatus());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    @DisplayName("Exceeding request limit on /login triggers 429 Too Many Requests with Retry-After header")
    void exceedingLimit_returns429() throws ServletException, IOException {
        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest req = new MockHttpServletRequest("GET", "/login");
            req.setRemoteAddr("10.0.0.1");
            MockHttpServletResponse resp = new MockHttpServletResponse();
            rateLimitFilter.doFilter(req, resp, filterChain);
            assertEquals(200, resp.getStatus());
        }

        // 4th request exceeds max 3
        MockHttpServletRequest blockedReq = new MockHttpServletRequest("GET", "/login");
        blockedReq.setRemoteAddr("10.0.0.1");
        MockHttpServletResponse blockedResp = new MockHttpServletResponse();

        rateLimitFilter.doFilter(blockedReq, blockedResp, filterChain);

        assertEquals(429, blockedResp.getStatus());
        assertEquals("60", blockedResp.getHeader("Retry-After"));
        assertTrue(blockedResp.getContentAsString().contains("Rate limit exceeded"));
    }

    @Test
    @DisplayName("API endpoint rate limiting returns JSON response")
    void apiEndpoint_returnsJson429() throws ServletException, IOException {
        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/sign");
            req.setRemoteAddr("10.0.0.2");
            MockHttpServletResponse resp = new MockHttpServletResponse();
            rateLimitFilter.doFilter(req, resp, filterChain);
        }

        MockHttpServletRequest blockedReq = new MockHttpServletRequest("POST", "/api/sign");
        blockedReq.setRemoteAddr("10.0.0.2");
        blockedReq.addHeader("Accept", "application/json");
        MockHttpServletResponse blockedResp = new MockHttpServletResponse();

        rateLimitFilter.doFilter(blockedReq, blockedResp, filterChain);

        assertEquals(429, blockedResp.getStatus());
        assertEquals("application/json", blockedResp.getContentType());
        assertTrue(blockedResp.getContentAsString().contains("\"error\":\"Too Many Requests\""));
    }

    @Test
    @DisplayName("Non-sensitive endpoints are not throttled")
    void nonSensitiveEndpoint_notThrottled() throws ServletException, IOException {
        for (int i = 0; i < 10; i++) {
            MockHttpServletRequest req = new MockHttpServletRequest("GET", "/css/app.css");
            req.setRemoteAddr("10.0.0.3");
            MockHttpServletResponse resp = new MockHttpServletResponse();
            rateLimitFilter.doFilter(req, resp, filterChain);
            assertEquals(200, resp.getStatus());
        }
        verify(filterChain, times(10)).doFilter(any(), any());
    }

    @Test
    @DisplayName("Different IP addresses are rate-limited independently")
    void independentIPs_isolatedLimits() throws ServletException, IOException {
        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest req = new MockHttpServletRequest("GET", "/sign");
            req.setRemoteAddr("10.0.0.4");
            MockHttpServletResponse resp = new MockHttpServletResponse();
            rateLimitFilter.doFilter(req, resp, filterChain);
        }

        // IP 10.0.0.4 is now at limit
        MockHttpServletRequest blockedReq = new MockHttpServletRequest("GET", "/sign");
        blockedReq.setRemoteAddr("10.0.0.4");
        MockHttpServletResponse blockedResp = new MockHttpServletResponse();
        rateLimitFilter.doFilter(blockedReq, blockedResp, filterChain);
        assertEquals(429, blockedResp.getStatus());

        // IP 10.0.0.5 is fresh and should pass
        MockHttpServletRequest freshReq = new MockHttpServletRequest("GET", "/sign");
        freshReq.setRemoteAddr("10.0.0.5");
        MockHttpServletResponse freshResp = new MockHttpServletResponse();
        rateLimitFilter.doFilter(freshReq, freshResp, filterChain);
        assertEquals(200, freshResp.getStatus());
    }

    @Test
    @DisplayName("By default, X-Forwarded-For is ignored to prevent IP spoofing and limits bind to remoteAddr")
    void xForwardedFor_ignoredByDefault() throws ServletException, IOException {
        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest req = new MockHttpServletRequest("GET", "/verify");
            req.setRemoteAddr("198.51.100.1");
            req.addHeader("X-Forwarded-For", "203.0.113." + i); // Attempt spoofing different IPs
            MockHttpServletResponse resp = new MockHttpServletResponse();
            rateLimitFilter.doFilter(req, resp, filterChain);
            assertEquals(200, resp.getStatus());
        }

        // 4th request from same remoteAddr must be throttled despite different X-Forwarded-For header
        MockHttpServletRequest req4 = new MockHttpServletRequest("GET", "/verify");
        req4.setRemoteAddr("198.51.100.1");
        req4.addHeader("X-Forwarded-For", "203.0.113.99");
        MockHttpServletResponse resp4 = new MockHttpServletResponse();
        rateLimitFilter.doFilter(req4, resp4, filterChain);

        assertEquals(429, resp4.getStatus());
    }

    @Test
    @DisplayName("When trustForwardedFor is enabled, X-Forwarded-For is parsed for client IP behind trusted proxy")
    void xForwardedFor_respectedWhenConfigured() throws ServletException, IOException {
        RateLimitFilter proxyFilter = new RateLimitFilter(3, true);

        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest req = new MockHttpServletRequest("GET", "/verify");
            req.setRemoteAddr("127.0.0.1"); // Proxy IP
            req.addHeader("X-Forwarded-For", "203.0.113.195, 70.41.3.18");
            MockHttpServletResponse resp = new MockHttpServletResponse();
            proxyFilter.doFilter(req, resp, filterChain);
        }

        MockHttpServletRequest req4 = new MockHttpServletRequest("GET", "/verify");
        req4.setRemoteAddr("127.0.0.1");
        req4.addHeader("X-Forwarded-For", "203.0.113.195, 70.41.3.18");
        MockHttpServletResponse resp4 = new MockHttpServletResponse();
        proxyFilter.doFilter(req4, resp4, filterChain);

        assertEquals(429, resp4.getStatus());
    }
}
