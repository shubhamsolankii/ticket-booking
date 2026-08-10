package com.ticketbooking.auth.exception;

import com.ticketbooking.auth.dto.response.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.OffsetDateTime;
import java.util.stream.Collectors;

/**
 * Central exception-to-HTTP-response mapping for the Auth Service.
 *
 * Spring routes every unhandled exception from @RestController methods
 * through this handler before writing the HTTP response.
 *
 * Design principle: no switch statements. Each AuthException subclass
 * carries its own HttpStatus and errorCode. The handler reads both —
 * adding a new exception type requires zero changes here.
 *
 * Handler precedence (Spring applies the most specific match first):
 *   1. AuthException          → business logic errors (our domain)
 *   2. MethodArgumentNotValidException → @Valid failures (request DTOs)
 *   3. CannotAcquireLockException      → DB lock timeout (infrastructure)
 *   4. Exception              → fallback for anything unexpected
 */
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    private static final String CORRELATION_ID_HEADER = "X-Correlation-ID";

    // =========================================================================
    // AUTH DOMAIN EXCEPTIONS
    // =========================================================================

    /**
     * Handles all AuthException subclasses (InvalidCredentialsException,
     * TokenExpiredException, EmailAlreadyExistsException, etc.).
     *
     * No switch statement. HttpStatus and errorCode come directly
     * from the exception instance — the subclass set them at throw time.
     *
     * Log level is INFO, not WARN or ERROR.
     * These are expected business errors — a user typing the wrong
     * password is not an ERROR condition for the service. Logging them
     * as ERROR would fill Grafana alert queues with noise, masking
     * real infrastructure problems. INFO is correct. If the error rate
     * for a specific code spikes (e.g., INVALID_CREDENTIALS doubling),
     * Prometheus metrics on error codes surface it — not log levels.
     */
    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ErrorResponse> handleAuthException(
            AuthException ex,
            HttpServletRequest request
    ) {
        log.info(
                "Auth exception [{}] on {} {}: {}",
                ex.getErrorCode(),
                request.getMethod(),
                request.getRequestURI(),
                ex.getMessage()
        );

        ErrorResponse body = ErrorResponse.builder()
                .timestamp(OffsetDateTime.now())
                .status(ex.getStatus().value())
                .error(ex.getStatus().getReasonPhrase())
                .errorCode(ex.getErrorCode())
                .message(ex.getMessage())
                .correlationId(extractCorrelationId(request))
                .path(request.getRequestURI())
                .build();

        return ResponseEntity
                .status(ex.getStatus())
                .body(body);
    }

    // =========================================================================
    // VALIDATION FAILURES
    // =========================================================================

    /**
     * Handles @Valid failures on request DTOs.
     *
     * Thrown when: a @RequestBody fails Bean Validation constraints
     * (@NotBlank, @Email, @Size, @Pattern, etc.).
     *
     * Spring populates BindingResult with one FieldError per failing field.
     * We aggregate all field errors into a single comma-separated message.
     *
     * Example output:
     *   "email: must be a well-formed email address; password: size must be between 8 and 100"
     *
     * HTTP 400 BAD_REQUEST.
     * errorCode: VALIDATION_FAILED — uniform across all validation errors.
     * Client switches on this code to display field-level validation UI.
     *
     * Log level: DEBUG — validation failures are extremely common (typos,
     * form errors) and carry no operational signal worth INFO logging.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationException(
            MethodArgumentNotValidException ex,
            HttpServletRequest request
    ) {
        String message = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(FieldError::getDefaultMessage)
                .collect(Collectors.joining("; "));

        log.debug(
                "Validation failure on {} {}: {}",
                request.getMethod(),
                request.getRequestURI(),
                message
        );

        ErrorResponse body = ErrorResponse.builder()
                .timestamp(OffsetDateTime.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error(HttpStatus.BAD_REQUEST.getReasonPhrase())
                .errorCode("VALIDATION_FAILED")
                .message(message)
                .correlationId(extractCorrelationId(request))
                .path(request.getRequestURI())
                .build();

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(body);
    }

    // =========================================================================
    // LOCK TIMEOUT — INFRASTRUCTURE
    // =========================================================================

    /**
     * Handles PostgreSQL lock timeout exceptions.
     *
     * Thrown when: a SELECT FOR UPDATE exceeds the configured timeout
     * (5s on refresh tokens, 3s on password reset tokens).
     *
     * At 100K RPS, lock contention on the refresh token table is a real
     * operational condition — not a bug. A burst of concurrent refresh
     * requests for the same token causes one to win and others to queue.
     * If the queue exceeds the timeout, they surface here.
     *
     * HTTP 503 SERVICE_UNAVAILABLE with Retry-After: 1.
     * The client should retry after 1 second. This is the correct signal
     * for a transient infrastructure condition — not a client error (4xx).
     *
     * Log level: WARN — lock timeouts are operationally significant.
     * A spike in CannotAcquireLockException at 60K RPS indicates either
     * a connection pool exhaustion or an unexpectedly slow transaction
     * holding the row lock. Worth alerting on in Grafana.
     */
    @ExceptionHandler(CannotAcquireLockException.class)
    public ResponseEntity<ErrorResponse> handleLockTimeoutException(
            CannotAcquireLockException ex,
            HttpServletRequest request
    ) {
        log.warn(
                "DB lock timeout on {} {}: {}",
                request.getMethod(),
                request.getRequestURI(),
                ex.getMessage()
        );

        ErrorResponse body = ErrorResponse.builder()
                .timestamp(OffsetDateTime.now())
                .status(HttpStatus.SERVICE_UNAVAILABLE.value())
                .error(HttpStatus.SERVICE_UNAVAILABLE.getReasonPhrase())
                .errorCode("SERVICE_TEMPORARILY_UNAVAILABLE")
                .message("The service is temporarily under high load. Please retry in a moment.")
                .correlationId(extractCorrelationId(request))
                .path(request.getRequestURI())
                .build();

        return ResponseEntity
                .status(HttpStatus.SERVICE_UNAVAILABLE)
                .header("Retry-After", "1")
                .body(body);
    }

    // =========================================================================
    // FALLBACK — UNEXPECTED ERRORS
    // =========================================================================

    /**
     * Catches anything not matched by the handlers above.
     *
     * This handler must exist. Without it, Spring's default error handling
     * returns a /error redirect with a Whitelabel Error Page — not an
     * ErrorResponse JSON body. Every client parsing our API contract would
     * receive an unexpected HTML response for unhandled exceptions.
     *
     * Log level: ERROR — an unexpected exception reaching this handler
     * means we have an unhandled code path. This should alert on-call.
     *
     * The exception cause is logged server-side with full stack trace.
     * The response body contains a generic message with no internal details.
     * Stack traces must never appear in HTTP responses — they leak
     * implementation details and package structure to attackers.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(
            Exception ex,
            HttpServletRequest request
    ) {
        log.error(
                "Unexpected exception on {} {}: ",
                request.getMethod(),
                request.getRequestURI(),
                ex   // SLF4J logs the full stack trace when the last argument
                // is a Throwable without a corresponding {} placeholder.
                // This is the correct pattern — not ex.getMessage().
        );

        ErrorResponse body = ErrorResponse.builder()
                .timestamp(OffsetDateTime.now())
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .error(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase())
                .errorCode("INTERNAL_SERVER_ERROR")
                .message("An unexpected error occurred. Please try again later.")
                .correlationId(extractCorrelationId(request))
                .path(request.getRequestURI())
                .build();

        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(body);
    }

    // =========================================================================
    // PRIVATE UTILITIES
    // =========================================================================

    /**
     * Extracts the X-Correlation-ID header from the incoming request.
     *
     * If absent (direct calls that bypass the API Gateway, health checks,
     * integration tests), returns "NO-CORRELATION-ID" rather than null.
     * Null in the correlationId field produces a JSON null — breaking
     * clients that expect a string. A sentinel value is cleaner.
     *
     * In production: X-Correlation-ID is always injected by the API Gateway.
     * Its absence in production is itself a signal that something bypassed
     * the gateway — worth noting in logs.
     */
    private String extractCorrelationId(HttpServletRequest request) {
        String correlationId = request.getHeader(CORRELATION_ID_HEADER);
        return correlationId != null ? correlationId : "NO-CORRELATION-ID";
    }
}