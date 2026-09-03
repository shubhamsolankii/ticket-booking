package com.ticketbooking.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when registration is attempted with an email already in the users table.
 * 409 Conflict: the resource (this email identity) already exists.
 *
 * Security note: we expose the email in the message deliberately.
 * For a ticket booking platform, the UX benefit of "this email is already
 * registered — try logging in" outweighs the email enumeration risk.
 * For a healthcare or financial product, this message would be suppressed.
 */
public class UserAlreadyExistsException extends AuthException {

    public UserAlreadyExistsException(String email) {
        super(
                "An account already exists for email: " + email,
                HttpStatus.CONFLICT,
                "USER_ALREADY_EXISTS"
        );
    }
}