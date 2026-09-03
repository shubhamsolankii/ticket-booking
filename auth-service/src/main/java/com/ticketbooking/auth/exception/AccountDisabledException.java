package com.ticketbooking.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when any login attempt is made against an account
 * where is_active = false.
 *
 * 403 Forbidden: the identity is known, the account is suspended.
 * Intentionally vague message — we do not tell the user WHY their
 * account is disabled (ToS violation, fraud flag, admin action).
 * They are directed to contact support, who have the full context.
 */
public class AccountDisabledException extends AuthException {

    public AccountDisabledException() {
        super(
                "This account has been disabled. Please contact support.",
                HttpStatus.FORBIDDEN,
                "ACCOUNT_DISABLED"
        );
    }
}