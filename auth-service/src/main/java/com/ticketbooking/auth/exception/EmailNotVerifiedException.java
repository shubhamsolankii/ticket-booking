package com.ticketbooking.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when an email/password login is attempted on an account
 * where email_verified = false.
 *
 * 403 Forbidden: the identity is known but not authorised to proceed
 * until email verification is complete.
 * 401 would be wrong here — the credentials are correct, the account
 * state is what prevents access. 403 is semantically precise.
 */
public class EmailNotVerifiedException extends AuthException {

    public EmailNotVerifiedException() {
        super(
                "Email address has not been verified. "
                        + "Please check your inbox for the verification link.",
                HttpStatus.FORBIDDEN,
                "EMAIL_NOT_VERIFIED"
        );
    }
}