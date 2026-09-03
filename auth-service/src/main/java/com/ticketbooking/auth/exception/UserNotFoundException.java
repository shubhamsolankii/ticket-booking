package com.ticketbooking.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when a user lookup by ID is expected to succeed but finds nothing.
 *
 * When to use vs when NOT to use:
 * - DO throw for internal lookups where the userId should always resolve
 *   (e.g., during token refresh — the userId from the refresh_tokens row
 *   must exist in the users table; if it doesn't, data integrity is broken).
 * - DO NOT throw from the forgotPassword endpoint when an email is not found
 *   — that endpoint always returns 200 to prevent email enumeration.
 */
public class UserNotFoundException extends AuthException {

    public UserNotFoundException(String userId) {
        super(
                "User not found with id: " + userId,
                HttpStatus.NOT_FOUND,
                "USER_NOT_FOUND"
        );
    }
}