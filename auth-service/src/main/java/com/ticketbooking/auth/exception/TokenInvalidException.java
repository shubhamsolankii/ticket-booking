package com.ticketbooking.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when a token does not exist in the DB.
 *
 * Thrown by: AuthService.verifyEmail(), AuthService.refreshToken(),
 *            AuthService.resetPassword(), AuthService.logout()
 * Scenarios:
 *   - Token hash not found (never existed, already deleted, or fabricated)
 *   - Token already used (rotation: old token deleted, new one issued —
 *     client retries with the old token after network error)
 *   - Token for a different environment (staging token sent to production)
 *
 * HTTP 401 UNAUTHORIZED for refresh tokens (session invalid).
 * HTTP 400 BAD_REQUEST for verification and reset tokens (invalid link).
 *
 * Caller passes the appropriate status. Same pattern as TokenExpiredException.
 */
public class TokenInvalidException extends AuthException {

    private static final String ERROR_CODE = "TOKEN_INVALID";

    public TokenInvalidException(HttpStatus status, String message) {
        super(status, ERROR_CODE, message);
    }

    public static TokenInvalidException forRefreshToken() {
        return new TokenInvalidException(
                HttpStatus.UNAUTHORIZED,
                "Invalid or revoked session token. Please log in again."
        );
    }

    public static TokenInvalidException forEmailVerification() {
        return new TokenInvalidException(
                HttpStatus.BAD_REQUEST,
                "Invalid verification link. Please request a new one."
        );
    }

    public static TokenInvalidException forPasswordReset() {
        return new TokenInvalidException(
                HttpStatus.BAD_REQUEST,
                "Invalid password reset link. Please request a new one."
        );
    }
}