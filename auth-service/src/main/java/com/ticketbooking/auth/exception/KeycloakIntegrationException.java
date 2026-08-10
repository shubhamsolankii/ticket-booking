package com.ticketbooking.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when the Keycloak OAuth2 token exchange fails due to
 * an infrastructure problem (Keycloak unreachable, timeout, 5xx from Keycloak).
 *
 * Thrown by: KeycloakService.exchangeToken()
 *
 * HTTP 503 SERVICE_UNAVAILABLE.
 * The client can retry — the failure is transient, not caused by
 * a bad request. The Retry-After header is set in GlobalExceptionHandler
 * to instruct clients on when to retry.
 *
 * Distinct from a Keycloak 401/400 response (invalid code, redirectUri mismatch).
 * Those are client errors → HTTP 400/401 from us, not 503.
 * This exception is exclusively for infrastructure failures.
 *
 * Carries the original cause for logging in GlobalExceptionHandler.
 * The cause (FeignException, timeout, etc.) is logged server-side
 * but never surfaced in the API response — internal infrastructure
 * details must not leak to clients.
 */
public class KeycloakIntegrationException extends AuthException {

    private static final String ERROR_CODE = "AUTH_PROVIDER_UNAVAILABLE";
    private static final String MESSAGE =
            "Social login is temporarily unavailable. "
                    + "Please try again shortly or use email/password login.";

    public KeycloakIntegrationException(Throwable cause) {
        super(HttpStatus.SERVICE_UNAVAILABLE, ERROR_CODE, MESSAGE, cause);
    }
}