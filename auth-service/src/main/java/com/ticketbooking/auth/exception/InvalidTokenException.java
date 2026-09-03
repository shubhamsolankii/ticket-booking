package com.ticketbooking.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when a token (refresh token, email verification token,
 * or password reset token) is not found in the database or has
 * already been used (consumed by a previous successful operation).
 *
 * 401 Unauthorized: the presented credential (token) is not valid.
 * Distinct from TokenExpiredException (410) which covers TTL expiry.
 * A client receiving 401 should redirect to login.
 * A client receiving 410 should offer a "resend" / "request new link" option.
 */
public class InvalidTokenException extends AuthException {

    public InvalidTokenException() {
        super(
                "The provided token is invalid or has already been used.",
                HttpStatus.UNAUTHORIZED,
                "INVALID_TOKEN"
        );
    }
}