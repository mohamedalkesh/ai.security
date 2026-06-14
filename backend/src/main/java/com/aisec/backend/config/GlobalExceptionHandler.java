package com.aisec.backend.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(ResourceAccessException.class)
    public ResponseEntity<Map<String, Object>> handleMlDown(ResourceAccessException ex) {
        log.error("ML service unreachable: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of(
                "error", "ML service unreachable",
                "detail", ex.getMessage(),
                "timestamp", Instant.now().toString()
        ));
    }

    @ExceptionHandler(HttpStatusCodeException.class)
    public ResponseEntity<Map<String, Object>> handleMlError(HttpStatusCodeException ex) {
        log.error("ML service error {}: {}", ex.getStatusCode(), ex.getResponseBodyAsString());
        return ResponseEntity.status(ex.getStatusCode()).body(Map.of(
                "error", "ML service returned an error",
                "status", ex.getStatusCode().value(),
                "detail", ex.getResponseBodyAsString(),
                "timestamp", Instant.now().toString()
        ));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleAccessDenied(AccessDeniedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                "error", "Access denied",
                "detail", ex.getMessage() == null ? "Insufficient permissions" : ex.getMessage(),
                "timestamp", Instant.now().toString()
        ));
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Map<String, Object>> handleAuth(AuthenticationException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                "error", "Authentication required",
                "detail", ex.getMessage() == null ? "" : ex.getMessage(),
                "timestamp", Instant.now().toString()
        ));
    }

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Map<String, Object>> handleResponseStatus(ResponseStatusException ex) {
        return ResponseEntity.status(ex.getStatusCode()).body(Map.of(
                "error", ex.getReason() == null ? "Error" : ex.getReason(),
                "status", ex.getStatusCode().value(),
                "timestamp", Instant.now().toString()
        ));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGeneric(Exception ex) {
        log.error("Unhandled exception", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                "error", ex.getClass().getSimpleName(),
                "detail", ex.getMessage() == null ? "" : ex.getMessage(),
                "timestamp", Instant.now().toString()
        ));
    }
}
