package com.ticketbooking.auth.exception;

import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;

/**
 * Global exception handler for the Auth Service.
 *
 * This class IS a Spring AOP Aspect, applied transparently to every
 * @RestController in this application. Spring creates a proxy around
 * each controller and intercepts any exception thrown by a controller
 * method. The proxy delegates to the matching @ExceptionHandler here.
 * The controller method itself has no try-catch, no awareness of this class.
 * That is the AOP cross-cutting concern pattern (SB-12) in production use.
 *
 * Handler priority when multiple @ExceptionHandler methods could match:
 * Spring picks the MOST SPECIFIC matching handler. If InvalidCredentialsException
 * (a subclass of AuthException) is thrown, Spring matches handleAuthException
 * (AuthException.class) correctly via polymorphism — the single handler
 * covers all subclasses. Spring does NOT call the generic Exception handler
 * when a more specific handler exists.
 *
 * @RestControllerAdvice = @ControllerAdvice + @ResponseBody.
 * Without @ResponseBody, the handler return value is treated as a view name,
 * not a serialised response body. For a REST API that always returns JSON,
 * @RestControllerAdvice is always correct over @ControllerAdvice.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /*
     * HANDLER 1 — All AuthException subclasses (8 concrete types).
     *
     * One handler covers all 8 concrete exceptions via polymorphism.
     * When a new exception type is added (extend AuthException, set the
     * right HttpStatus and errorCode), this handler picks it up with zero
     * changes. Open/Closed Principle: handler is closed for modification.
     *
     * Log level: WARN for 4xx (client errors — they tell us about
     * bad clients or expired tokens; not service-side failures).
     * ERROR would be misleading — the service is behaving correctly.
     * The correlationId in the log line lets us trace the specific request.
     */
    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ErrorResponse> handleAuthException(
            AuthException ex,
            HttpServletRequest request) {

        log.warn(
                "[{}] {} {} — {}: {}",
                extractCorrelationId(request),
                request.getMethod(),
                request.getRequestURI(),
                ex.getErrorCode(),
                ex.getMessage()
        );

        ErrorResponse body = ErrorResponse.of(
                ex.getHttpStatus().value(),
                ex.getHttpStatus().getReasonPhrase(),
                ex.getErrorCode(),
                ex.getMessage(),
                extractCorrelationId(request),
                request.getRequestURI()
        );

        return ResponseEntity.status(ex.getHttpStatus()).body(body);
    }

    /*
     * HANDLER 2 — Bean Validation failures (@Valid on request DTOs).
     *
     * Triggered when a @RequestBody annotated with @Valid fails validation:
     * - Email format invalid
     * - Password too short / missing required characters
     * - Phone number wrong format
     * Each failing field produces one FieldValidationError entry.
     *
     * We do NOT expose internal field paths like "registerRequest.email" —
     * we extract just the field name and the user-facing message from the
     * constraint annotation (e.g., @Email(message = "Invalid email format")).
     *
     * Log level: DEBUG — validation failures are expected client behaviour,
     * not worth polluting WARN-level logs with at 100K RPS.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationException(
            MethodArgumentNotValidException ex,
            HttpServletRequest request) {

        List<FieldValidationError> fieldErrors = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(fieldError -> new FieldValidationError(
                        fieldError.getField(),
                        /*
                         * getDefaultMessage() returns the message from the constraint
                         * annotation: @NotBlank(message = "Email is required") → "Email is required"
                         * If no message is set, Spring provides a default like "must not be blank".
                         * Both are safe to return to the client — no internals leak.
                         */
                        fieldError.getDefaultMessage()
                ))
                .toList();

        log.debug(
                "[{}] Validation failed on {} {}: {} field(s)",
                extractCorrelationId(request),
                request.getMethod(),
                request.getRequestURI(),
                fieldErrors.size()
        );

        ErrorResponse body = ErrorResponse.ofValidation(
                extractCorrelationId(request),
                request.getRequestURI(),
                fieldErrors
        );

        return ResponseEntity.badRequest().body(body);
    }

    /*
     * HANDLER 3 — Malformed JSON request body.
     *
     * Triggered when Jackson cannot deserialise the request body:
     * - Body is not valid JSON (syntax error)
     * - JSON value has wrong type for the target field
     *   (e.g., "expiresIn": "notanumber")
     *
     * We return 400 with a generic message — we do NOT include the
     * Jackson parse exception message because it often contains
     * internal class names (e.g., "cannot deserialize value of type
     * `com.ticketbooking.auth.dto.request.RegisterRequest`").
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleMalformedJson(
            HttpMessageNotReadableException ex,
            HttpServletRequest request) {

        log.debug(
                "[{}] Malformed JSON on {} {}",
                extractCorrelationId(request),
                request.getMethod(),
                request.getRequestURI()
        );

        ErrorResponse body = ErrorResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                HttpStatus.BAD_REQUEST.getReasonPhrase(),
                "MALFORMED_REQUEST",
                "Request body is missing or contains invalid JSON.",
                extractCorrelationId(request),
                request.getRequestURI()
        );

        return ResponseEntity.badRequest().body(body);
    }

    /*
     * HANDLER 4 — Database lock acquisition failure (SELECT FOR UPDATE).
     *
     * When does this occur?
     * The token refresh endpoint (POST /auth/token/refresh) uses
     * SELECT FOR UPDATE with a configured lock timeout on the
     * refresh_tokens row. At 100K RPS with 60K of those being refresh
     * operations, two requests carrying the SAME refresh token can arrive
     * simultaneously (client retry on network timeout is the common case).
     *
     * Request A: acquires the exclusive row lock, proceeds.
     * Request B: tries to acquire the same lock, waits up to lock_timeout,
     *            PostgreSQL throws "ERROR: could not obtain lock on row".
     * Spring DataAccessException translator converts this to
     * CannotAcquireLockException.
     *
     * Why 409 Conflict and not 503?
     * 503 implies "the service is down, retry later". The service is
     * perfectly healthy — it is intentionally serialising concurrent
     * access to a shared row. 409 is semantically correct: there is a
     * conflict on this specific resource (refresh token row).
     * The client should treat 409 on token refresh as "refresh token is
     * being processed — use the most recently issued access token instead".
     *
     * This handler is the direct application of DB-56 (exclusive locks)
     * in the exception layer.
     */
    @ExceptionHandler(CannotAcquireLockException.class)
    public ResponseEntity<ErrorResponse> handleCannotAcquireLock(
            CannotAcquireLockException ex,
            HttpServletRequest request) {

        log.warn(
                "[{}] Lock acquisition failed on {} {} — concurrent request contention",
                extractCorrelationId(request),
                request.getMethod(),
                request.getRequestURI()
        );

        ErrorResponse body = ErrorResponse.of(
                HttpStatus.CONFLICT.value(),
                HttpStatus.CONFLICT.getReasonPhrase(),
                "LOCK_ACQUISITION_FAILED",
                "This request conflicts with another in-progress operation. "
                        + "Please retry after a moment.",
                extractCorrelationId(request),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.CONFLICT).body(body);
    }

    /*
     * HANDLER 5 — Database unique constraint violation.
     *
     * DataIntegrityViolationException is Spring's translation of any
     * constraint violation from the JDBC layer:
     * - Unique constraint on users.email (duplicate registration)
     * - Unique constraint on refresh_tokens.token_hash (hash collision —
     *   astronomically unlikely but handled for completeness)
     *
     * Why handle this separately from UserAlreadyExistsException?
     * The service layer throws UserAlreadyExistsException BEFORE the insert
     * (it checks first). But under race conditions, two simultaneous
     * registrations with the same email can both pass the "does email exist?"
     * check and then race to insert. The UNIQUE constraint on users.email
     * at the DB level catches the second insert — DataIntegrityViolationException.
     * This handler is the safety net for that race condition.
     *
     * Returning 409 is correct — the resource already exists.
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponse> handleDataIntegrity(
            DataIntegrityViolationException ex,
            HttpServletRequest request) {

        log.warn(
                "[{}] Data integrity violation on {} {}: {}",
                extractCorrelationId(request),
                request.getMethod(),
                request.getRequestURI(),
                ex.getMostSpecificCause().getMessage()
        );

        ErrorResponse body = ErrorResponse.of(
                HttpStatus.CONFLICT.value(),
                HttpStatus.CONFLICT.getReasonPhrase(),
                "DATA_CONFLICT",
                "The request conflicts with existing data. "
                        + "The resource may already exist.",
                extractCorrelationId(request),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.CONFLICT).body(body);
    }

    /*
     * HANDLER 6 — Resilience4j circuit breaker open (Keycloak down).
     *
     * When Keycloak's circuit breaker trips (failure rate exceeds threshold),
     * Resilience4j throws CallNotPermittedException immediately — no network
     * call is made. This protects Auth Service from cascading failure when
     * the OAuth2 provider is having an outage.
     *
     * Only POST /auth/oauth2/token calls Keycloak. All other endpoints
     * (email/password login, OTP, token refresh, logout) are entirely
     * independent of Keycloak. A Keycloak outage degrades ONE feature,
     * not the entire auth surface.
     *
     * 503 Service Unavailable is correct: the service is available but
     * a downstream dependency (Keycloak) it requires for this operation is not.
     */
    @ExceptionHandler(CallNotPermittedException.class)
    public ResponseEntity<ErrorResponse> handleCircuitBreakerOpen(
            CallNotPermittedException ex,
            HttpServletRequest request) {

        log.error(
                "[{}] Circuit breaker OPEN for {} {}: {}",
                extractCorrelationId(request),
                request.getMethod(),
                request.getRequestURI(),
                ex.getMessage()
        );

        ErrorResponse body = ErrorResponse.of(
                HttpStatus.SERVICE_UNAVAILABLE.value(),
                HttpStatus.SERVICE_UNAVAILABLE.getReasonPhrase(),
                "OAUTH2_PROVIDER_UNAVAILABLE",
                "OAuth2 login is temporarily unavailable. "
                        + "Please use email/password or OTP login instead.",
                extractCorrelationId(request),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(body);
    }

    /*
     * HANDLER 7 — Safety net for all unhandled exceptions.
     *
     * This handler MUST exist. Without it, Spring's default exception
     * handling produces a response with potentially sensitive information:
     * the exception class name, the message (which might contain internal
     * paths, SQL fragments, or field names), and sometimes a stack trace.
     * None of that should ever reach a client.
     *
     * Log level: ERROR — an unhandled exception is a bug. It means a
     * case we did not anticipate is occurring in production. It warrants
     * immediate investigation. The full stack trace is logged here so
     * engineers have everything they need to debug it.
     *
     * Response: always 500, always generic message. Never expose what
     * threw, where it threw, or what the message says. The correlationId
     * lets the engineer find the ERROR log with the full detail.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(
            Exception ex,
            HttpServletRequest request) {

        log.error(
                "[{}] Unhandled exception on {} {}",
                extractCorrelationId(request),
                request.getMethod(),
                request.getRequestURI(),
                ex  // logs full stack trace at ERROR level
        );

        ErrorResponse body = ErrorResponse.of(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase(),
                "INTERNAL_ERROR",
                "An unexpected error occurred. "
                        + "Please contact support with correlation ID: "
                        + extractCorrelationId(request),
                extractCorrelationId(request),
                request.getRequestURI()
        );

        return ResponseEntity.internalServerError().body(body);
    }

    /*
     * Extracts the correlation ID for inclusion in error responses and logs.
     *
     * Priority order:
     * 1. X-Correlation-ID request header (set by API Gateway, or by the
     *    client directly during development before Gateway exists)
     * 2. "NO_CORRELATION_ID" fallback — never null in a response.
     *    A null correlationId in an error log is useless. A placeholder
     *    is immediately visible and searchable.
     *
     * After CorrelationIdFilter is implemented (Step 7), this value will
     * also be available in MDC under the key "correlationId". The filter
     * reads the header and puts it into MDC — both sources then agree.
     * We read the header directly here to avoid a dependency on the filter
     * at this step in the implementation sequence.
     */
    private String extractCorrelationId(HttpServletRequest request) {
        String correlationId = request.getHeader("X-Correlation-ID");
        return (correlationId != null && !correlationId.isBlank())
                ? correlationId
                : "NO_CORRELATION_ID";
    }
}