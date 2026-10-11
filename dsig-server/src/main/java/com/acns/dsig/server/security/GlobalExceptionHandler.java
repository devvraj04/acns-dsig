package com.acns.dsig.server.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.MultipartException;

import java.util.Map;
import java.util.UUID;

/**
 * Global exception handler providing safe error responses across the application.
 * Enforces that internal stack traces and server internals are never exposed to clients,
 * while generating trackable incident reference IDs and writing full details to logs.
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AccessDeniedException.class)
    public Object handleAccessDenied(
            AccessDeniedException ex,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model
    ) {
        String errorRef = generateRef();
        log.warn("Access Denied [Ref: {}] on URI '{}': {}", errorRef, request.getRequestURI(), ex.getMessage());

        response.setStatus(HttpStatus.FORBIDDEN.value());

        if (isApiRequest(request)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of(
                            "error", "Access Denied",
                            "message", "You do not have permission to access this resource.",
                            "referenceId", errorRef
                    ));
        }

        if (model != null) {
            model.addAttribute("errorRef", errorRef);
            model.addAttribute("errorMessage", "Access Denied: You do not have permission to access this resource.");
        }
        return "error";
    }

    @ExceptionHandler({MaxUploadSizeExceededException.class, MultipartException.class})
    public Object handleUploadLimitExceeded(
            Exception ex,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model
    ) {
        String errorRef = generateRef();
        log.warn("File upload limit exceeded [Ref: {}] on URI '{}': {}", errorRef, request.getRequestURI(), ex.getMessage());

        response.setStatus(HttpStatus.PAYLOAD_TOO_LARGE.value());

        if (isApiRequest(request)) {
            return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
                    .body(Map.of(
                            "error", "Payload Too Large",
                            "message", "Uploaded file exceeds the maximum permitted size limit.",
                            "referenceId", errorRef
                    ));
        }

        if (model != null) {
            model.addAttribute("errorRef", errorRef);
            model.addAttribute("errorMessage", "Uploaded file exceeds the maximum allowable size limit.");
        }
        return "error";
    }

    @ExceptionHandler({IllegalArgumentException.class, IllegalStateException.class})
    public Object handleBadRequest(
            Exception ex,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model
    ) {
        String errorRef = generateRef();
        log.warn("Bad Request [Ref: {}] on URI '{}': {}", errorRef, request.getRequestURI(), ex.getMessage());

        response.setStatus(HttpStatus.BAD_REQUEST.value());

        String safeMsg = sanitizeBadRequestMessage(ex.getMessage());

        if (isApiRequest(request)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of(
                            "error", "Bad Request",
                            "message", safeMsg,
                            "referenceId", errorRef
                    ));
        }

        if (model != null) {
            model.addAttribute("errorRef", errorRef);
            model.addAttribute("errorMessage", safeMsg);
        }
        return "error";
    }

    private String sanitizeBadRequestMessage(String rawMsg) {
        if (rawMsg == null || rawMsg.isBlank()) {
            return "Invalid request parameters.";
        }
        if (rawMsg.contains("/") || rawMsg.contains("\\") || rawMsg.contains(".java")
                || rawMsg.contains("Exception") || rawMsg.toLowerCase().contains("select ")
                || rawMsg.toLowerCase().contains("from ") || rawMsg.contains("org.hibernate")
                || rawMsg.length() > 200) {
            return "Invalid request parameter format or value.";
        }
        return rawMsg.trim();
    }

    @ExceptionHandler(Exception.class)
    public Object handleGenericException(
            Exception ex,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model
    ) {
        String errorRef = generateRef();
        log.error("Internal Server Error [Ref: {}] on URI '{}': {}", errorRef, request.getRequestURI(), ex.getMessage(), ex);

        response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());

        if (isApiRequest(request)) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "error", "Internal Server Error",
                            "message", "An unexpected error occurred while processing your request.",
                            "referenceId", errorRef
                    ));
        }

        if (model != null) {
            model.addAttribute("errorRef", errorRef);
            model.addAttribute("errorMessage", "An error occurred while processing your request. Please contact support with Ref: " + errorRef);
        }
        return "error";
    }

    private boolean isApiRequest(HttpServletRequest request) {
        if (request == null) return false;
        String uri = request.getRequestURI();
        if (uri != null && uri.startsWith("/api/")) return true;

        String accept = request.getHeader("Accept");
        if (accept != null && accept.contains("application/json")) return true;

        String requestedWith = request.getHeader("X-Requested-With");
        return "XMLHttpRequest".equalsIgnoreCase(requestedWith);
    }

    private String generateRef() {
        return UUID.randomUUID().toString().substring(0, 8);
    }
}
