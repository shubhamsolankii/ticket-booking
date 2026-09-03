package com.ticketbooking.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when a token's expires_at timestamp has passed.
 * Applies to: email verification tokens (24h TTL),
 *             password reset tokens (1h TTL),
 *             refresh tokens (7d TTL).
 *
 * 410 Gone: the resource existed but is no longer available.
 * This is semantically more precise than 401 (invalid) for expiry —
 * the token WAS valid, it has since expired. The client should
 * prompt "your link has expired, click here to get a new one."
 * A 401 would suggest the token was never valid, leading to confusion.
 */
public class TokenExpiredException extends AuthException {

    public TokenExpiredException(String tokenType) {
        super(
                tokenType + " has expired. Please request a new one.",
                HttpStatus.GONE,
                "TOKEN_EXPIRED"
        );
    }
}