package com.ticketbooking.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when registration is attempted with an already-registered email.
 *
 * Thrown by: AuthService.register()
 *
 * HTTP 409 CONFLICT — the request conflicts with existing resource state.
 * This is the correct semantic: the client is trying to create a resource
 * (user account) that already exists.
 *
 * Security note from Phase 2 API contract:
 * We return 409 explicitly (not a vague 200) because this is a ticket
 * booking platform, not a healthcare or finance product. Email enumeration
 * risk is low-severity here. UX benefit of "this email is already registered,
 * try logging in" outweighs the marginal enumeration risk.
 * If requirements change to require enumeration protection, this becomes
 * a 200 with a generic message — one file to change, not scattered logic.
 */
public class EmailAlreadyExistsException extends AuthException {

    private static final String ERROR_CODE = "EMAIL_ALREADY_EXISTS";

    public EmailAlreadyExistsException(String email) {
        super(
                HttpStatus.CONFLICT,
                ERROR_CODE,
                String.format(
                        "An account with email '%s' already exists. "
                                + "Please log in or use a different email.",
                        email
                )
        );
        // Including the email in the message is intentional here.
        // The user just typed it — they know it. We're not revealing
        // anything they don't already have.
    }
}