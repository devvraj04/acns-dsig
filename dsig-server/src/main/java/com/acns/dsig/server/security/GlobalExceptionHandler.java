package com.acns.dsig.server.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.Map;
import java.util.UUID;

@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(Exception.class)
    public Object handleGenericException(Exception ex, Model model) {
        String errorRef = UUID.randomUUID().toString().substring(0, 8);
        log.error("Internal Server Error [Ref: {}]: {}", errorRef, ex.getMessage(), ex);

        if (model != null) {
            model.addAttribute("errorRef", errorRef);
            model.addAttribute("errorMessage", "An error occurred while processing your request. Please contact support with Ref: " + errorRef);
            return "error";
        }

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of(
                        "error", "An internal error occurred",
                        "referenceId", errorRef
                ));
    }
}
