package com.ticketbooking.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when a deactivated account attempts any login path.
 *
 * Thrown by: AuthService.login(), AuthService.verifyOtp()
 * Scenario: user.isActive() == false.
 *
 * HTTP 403 FORBIDDEN.
 * Same reasoning as EmailNotVerifiedException — we know who the user
 * is but they are forbidden from accessing the system.
 *
 * Message does not reveal the reason for deactivation.
 * "Your account has been deactivated" is all the user sees.
 * Internal audit logs contain the full deactivation reason and
 * the admin who triggered it — but that context never surfaces
 * in the API response.
 */
public class AccountInactiveException extends AuthException {

    private static final String ERROR_CODE = "ACCOUNT_INACTIVE";
    private static final String MESSAGE =
            "Your account has been deactivated. "
                    + "Please contact support if you believe this is an error.";

    public AccountInactiveException() {
        super(HttpStatus.FORBIDDEN, ERROR_CODE, MESSAGE);
    }
}