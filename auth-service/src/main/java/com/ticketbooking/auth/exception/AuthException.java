package com.ticketbooking.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Base exception for all Auth Service business logic errors.
 *
 * Carries HttpStatus and errorCode so GlobalExceptionHandler
 * needs no switch statement — it reads these fields directly
 * from any AuthException subclass.
 *
 * Design: unchecked (extends RuntimeException).
 * Spring's @Transactional rolls back on RuntimeException by default.
 * Checked exceptions require explicit rollbackFor configuration —
 * a footgun in a service with many transactional boundaries.
 * All business errors in Auth Service are unrecoverable at the
 * call site — the caller cannot "handle" an invalid credential,
 * it can only propagate it upward to the HTTP boundary.
 *
 * Never throw AuthException directly. Always throw a typed subclass.
 * AuthException is package-accessible for subclassing only.
 */
public abstract class AuthException extends RuntimeException {

    private final HttpStatus status;
    private final String errorCode;

    protected AuthException(HttpStatus status, String errorCode, String message) {
        super(message);
        this.status = status;
        this.errorCode = errorCode;
    }

    protected AuthException(
            HttpStatus status,
            String errorCode,
            String message,
            Throwable cause
    ) {
        super(message, cause);
        this.status = status;
        this.errorCode = errorCode;
    }
    // cause-carrying constructor for wrapping third-party exceptions
    // (e.g., Keycloak HTTP client errors wrapped in KeycloakIntegrationException).
    // Never swallow the original cause — it is essential for debugging.

    public HttpStatus getStatus() {
        return status;
    }

    public String getErrorCode() {
        return errorCode;
    }
}