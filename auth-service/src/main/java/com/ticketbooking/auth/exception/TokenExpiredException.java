package com.ticketbooking.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when a token exists in the DB but its expiry window has passed.
 *
 * Thrown by: AuthService.verifyEmail(), AuthService.refreshToken(),
 *            AuthService.resetPassword()
 *
 * Why a dedicated exception instead of reusing TokenInvalidException:
 * TokenInvalidException means "token not found" — the client sent a token
 * that has no matching record. The user cannot recover by retrying.
 * TokenExpiredException means "token found but expired" — the client
 * can recover by requesting a new token (resend verification, re-login
 * to get a new refresh token, re-request password reset).
 * Different errors, different recovery actions, different HTTP semantics.
 *
 * HTTP status is context-dependent:
 *   Email verification link expired → 410 GONE
 *     (the link is permanently invalid — request a new one)
 *   Refresh token expired            → 401 UNAUTHORIZED
 *     (session expired — re-login required)
 *   Password reset link expired      → 400 BAD_REQUEST
 *     (request a new reset link)
 *
 * The caller passes the appropriate HttpStatus for their context.
 * The exception carries it — the handler reads it. No switch needed.
 */
public class TokenExpiredException extends AuthException {

    private static final String ERROR_CODE = "TOKEN_EXPIRED";

    public TokenExpiredException(HttpStatus status, String message) {
        super(status, ERROR_CODE, message);
    }

    // Static factory methods: named constructors for each context.
    // Caller intent is explicit. No ambiguity about which status applies.

    /**
     * Email verification link has expired (410 GONE).
     */
    public static TokenExpiredException forEmailVerification() {
        return new TokenExpiredException(
                HttpStatus.GONE,
                "Your verification link has expired. "
                        + "Please request a new verification email."
        );
    }

    /**
     * Refresh token has expired (401 UNAUTHORIZED).
     */
    public static TokenExpiredException forRefreshToken() {
        return new TokenExpiredException(
                HttpStatus.UNAUTHORIZED,
                "Your session has expired. Please log in again."
        );
    }

    /**
     * Password reset link has expired (400 BAD_REQUEST).
     */
    public static TokenExpiredException forPasswordReset() {
        return new TokenExpiredException(
                HttpStatus.BAD_REQUEST,
                "Your password reset link has expired. "
                        + "Please request a new one."
        );
    }
}