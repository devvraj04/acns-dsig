package com.acns.dsig.server.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("GlobalExceptionHandler — Safe Error Handling & Information Leakage Defense Tests")
class GlobalExceptionHandlerTest {

    private GlobalExceptionHandler exceptionHandler;

    @BeforeEach
    void setUp() {
        exceptionHandler = new GlobalExceptionHandler();
    }

    @Test
    @DisplayName("HTML browser request: generic exception renders error view with incident reference ID and no stack trace")
    void htmlGenericException_rendersErrorViewWithoutStackTrace() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/dashboard");
        MockHttpServletResponse response = new MockHttpServletResponse();
        Model model = new ConcurrentModel();
        Exception ex = new RuntimeException("Internal SQL syntax error near line 42: SELECT * FROM secret");

        Object result = exceptionHandler.handleGenericException(ex, request, response, model);

        assertEquals("error", result);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), response.getStatus());
        assertTrue(model.containsAttribute("errorRef"));
        assertTrue(model.containsAttribute("errorMessage"));

        String msg = (String) model.getAttribute("errorMessage");
        assertNotNull(msg);
        assertFalse(msg.contains("SQL"));
        assertFalse(msg.contains("secret"));
        assertTrue(msg.contains("An error occurred while processing your request"));
    }

    @Test
    @DisplayName("API request: generic exception returns JSON 500 response with referenceId and no stack trace")
    void apiGenericException_returnsJsonWithoutStackTrace() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/sign");
        MockHttpServletResponse response = new MockHttpServletResponse();
        Model model = new ConcurrentModel();
        Exception ex = new NullPointerException("Null reference at com.acns.dsig.internal.SecretEngine.java:123");

        Object result = exceptionHandler.handleGenericException(ex, request, response, model);

        assertInstanceOf(ResponseEntity.class, result);
        @SuppressWarnings("unchecked")
        ResponseEntity<Map<String, Object>> responseEntity = (ResponseEntity<Map<String, Object>>) result;

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
        Map<String, Object> body = responseEntity.getBody();
        assertNotNull(body);
        assertTrue(body.containsKey("referenceId"));
        assertEquals("Internal Server Error", body.get("error"));

        String message = (String) body.get("message");
        assertFalse(message.contains("Null reference"));
        assertFalse(message.contains("com.acns.dsig.internal"));
    }

    @Test
    @DisplayName("AccessDeniedException returns 403 Forbidden with clean incident reference")
    void accessDenied_returns403() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/audit");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AccessDeniedException ex = new AccessDeniedException("User lacks ROLE_ADMIN authority");

        Object result = exceptionHandler.handleAccessDenied(ex, request, response, new ConcurrentModel());

        assertInstanceOf(ResponseEntity.class, result);
        @SuppressWarnings("unchecked")
        ResponseEntity<Map<String, Object>> entity = (ResponseEntity<Map<String, Object>>) result;

        assertEquals(HttpStatus.FORBIDDEN, entity.getStatusCode());
        assertEquals("Access Denied", entity.getBody().get("error"));
        assertTrue(entity.getBody().containsKey("referenceId"));
    }

    @Test
    @DisplayName("Upload limit exceeded returns 413 Payload Too Large")
    void uploadLimitExceeded_returns413() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/upload");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MaxUploadSizeExceededException ex = new MaxUploadSizeExceededException(52428800);

        Object result = exceptionHandler.handleUploadLimitExceeded(ex, request, response, new ConcurrentModel());

        assertInstanceOf(ResponseEntity.class, result);
        @SuppressWarnings("unchecked")
        ResponseEntity<Map<String, Object>> entity = (ResponseEntity<Map<String, Object>>) result;

        assertEquals(HttpStatus.PAYLOAD_TOO_LARGE, entity.getStatusCode());
        assertEquals("Payload Too Large", entity.getBody().get("error"));
    }

    @Test
    @DisplayName("BadRequest exceptions return 400 with safe message")
    void badRequest_returns400() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/verify");
        MockHttpServletResponse response = new MockHttpServletResponse();
        IllegalArgumentException ex = new IllegalArgumentException("Invalid key format");

        Object result = exceptionHandler.handleBadRequest(ex, request, response, new ConcurrentModel());

        assertInstanceOf(ResponseEntity.class, result);
        @SuppressWarnings("unchecked")
        ResponseEntity<Map<String, Object>> entity = (ResponseEntity<Map<String, Object>>) result;

        assertEquals(HttpStatus.BAD_REQUEST, entity.getStatusCode());
        assertEquals("Bad Request", entity.getBody().get("error"));
        assertEquals("Invalid key format", entity.getBody().get("message"));
    }

    @Test
    @DisplayName("BadRequest exceptions containing system paths or SQL are masked")
    void badRequest_sanitizesInternalDetails() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/verify");
        MockHttpServletResponse response = new MockHttpServletResponse();
        IllegalArgumentException ex = new IllegalArgumentException("Failure at /etc/shadow or SELECT * FROM users");

        Object result = exceptionHandler.handleBadRequest(ex, request, response, new ConcurrentModel());

        assertInstanceOf(ResponseEntity.class, result);
        @SuppressWarnings("unchecked")
        ResponseEntity<Map<String, Object>> entity = (ResponseEntity<Map<String, Object>>) result;

        assertEquals(HttpStatus.BAD_REQUEST, entity.getStatusCode());
        assertEquals("Invalid request parameter format or value.", entity.getBody().get("message"));
    }
}
