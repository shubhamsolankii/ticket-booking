package com.ticketbooking.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when a user attempts password-based login before verifying
 * their email address.
 *
 * Thrown by: AuthService.login()
 * Scenario: user.isEmailVerified() == false on the login path.
 *
 * HTTP 403 FORBIDDEN — not 401.
 * 401 means "I don't know who you are."
 * 403 means "I know who you are, but you cannot do this yet."
 * The user IS authenticated (credentials are correct) but FORBIDDEN
 * from receiving tokens until email verification is complete.
 *
 * The response message explicitly tells the user what to do next.
 * Unlike InvalidCredentialsException (which is deliberately vague),
 * this error is not a security risk to be explicit about —
 * the user registered themselves and knows their email is unverified.
 */
public class EmailNotVerifiedException extends AuthException {

    private static final String ERROR_CODE = "EMAIL_NOT_VERIFIED";
    private static final String MESSAGE =
            "Please verify your email address before logging in. "
                    + "Check your inbox for the verification link.";

    public EmailNotVerifiedException() {
        super(HttpStatus.FORBIDDEN, ERROR_CODE, MESSAGE);
    }
}