package com.ticketbooking.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when email/password login fails for any reason:
 * email not found OR password does not match.
 *
 * Critically: we do NOT differentiate between "email not found" and
 * "wrong password" in the message or errorCode. Both produce the
 * identical response. This prevents user enumeration — an attacker
 * cannot distinguish "this email isn't registered" from "wrong password"
 * by observing the error response.
 */
public class InvalidCredentialsException extends AuthException {

    public InvalidCredentialsException() {
        super(
                "Invalid email or password.",
                HttpStatus.UNAUTHORIZED,
                "INVALID_CREDENTIALS"
        );
    }
}