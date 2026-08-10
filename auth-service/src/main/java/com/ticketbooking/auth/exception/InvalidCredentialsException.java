package com.ticketbooking.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when email/password authentication fails.
 *
 * Thrown by: AuthService.login()
 * Scenarios:
 *   - No user found for the given email
 *   - BCrypt.checkpw() returns false (wrong password)
 *
 * Critical security requirement: BOTH scenarios throw this same exception
 * with this same message. Never differentiate between "email not found"
 * and "wrong password" in the response. Either distinction enables
 * email enumeration — an attacker learns which emails are registered
 * by observing which error they receive.
 *
 * HTTP 401 UNAUTHORIZED.
 */
public class InvalidCredentialsException extends AuthException {

    private static final String ERROR_CODE = "INVALID_CREDENTIALS";
    private static final String MESSAGE = "Invalid email or password.";

    public InvalidCredentialsException() {
        super(HttpStatus.UNAUTHORIZED, ERROR_CODE, MESSAGE);
    }
    // No constructor parameters — the message is always the same.
    // If we allowed callers to pass a custom message, a developer
    // could accidentally pass "Email not found" or "Wrong password"
    // — breaking the enumeration protection. Fixed message, no overrides.
}