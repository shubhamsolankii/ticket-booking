package com.ticketbooking.auth.exception;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;
import java.util.List;

/**
 * The single, uniform error response contract for the Auth Service.
 * Every non-2xx response from every endpoint produces exactly this shape.
 *
 * Consistent error responses matter for clients:
 * - The mobile app can parse a single error model, not ad-hoc JSON shapes
 * - The API Gateway can log a structured error with all context fields present
 * - Support engineers can grep logs by correlationId and see the full picture
 *
 * @JsonInclude(NON_NULL): Jackson omits null fields from the serialised JSON.
 * fieldErrors is null for all non-validation errors — omitting it keeps the
 * response clean. Clients check for its presence rather than getting an
 * empty array they must always handle.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponse {

    /*
     * timestamp: when the error occurred, in UTC.
     * Using Instant (not LocalDateTime) — timezone-unambiguous.
     * Jackson serialises Instant as an ISO-8601 string:
     * "2025-07-29T10:30:00.000Z" when configured with
     * spring.jackson.serialization.write-dates-as-timestamps=false
     * We configure this in application.yml at Step 8 (DTOs step).
     * For now, Instant is the correct type regardless of serialisation format.
     */
    private final Instant timestamp;

    /*
     * status: the HTTP status code as an integer (e.g., 401, 409, 503).
     * Duplicates the HTTP response code intentionally — clients reading the
     * body in an error handler may not have direct access to the response
     * status line (some HTTP client libraries lose it).
     */
    private final int status;

    /*
     * error: the HTTP status reason phrase (e.g., "UNAUTHORIZED", "CONFLICT").
     * Derived from HttpStatus.getReasonPhrase(). Human-readable label for
     * the status code. Not the errorCode — that is application-specific.
     */
    private final String error;

    /*
     * errorCode: application-specific error identifier.
     * Examples: "USER_ALREADY_EXISTS", "INVALID_TOKEN", "OTP_INVALID"
     * This is what the frontend uses for programmatic branching:
     *   if (error.errorCode === "EMAIL_NOT_VERIFIED") showVerifyEmailPrompt()
     * The HTTP status alone is insufficient — 401 covers invalid credentials,
     * expired tokens, and invalid OTPs, which require different UI responses.
     */
    private final String errorCode;

    /*
     * message: human-readable description of what went wrong.
     * Safe to show to developers, NOT to end users in production
     * (use the errorCode to drive user-facing copy in the client).
     * Never includes stack traces, internal class names, or SQL.
     */
    private final String message;

    /*
     * correlationId: the X-Correlation-ID from the request.
     * Allows support engineers to find the exact request in logs
     * and in Grafana Tempo traces, even without knowing which
     * service instance handled it.
     */
    private final String correlationId;

    /*
     * path: the request URI that produced this error.
     * Example: "/api/v1/auth/token/refresh"
     * Combined with correlationId and timestamp, uniquely identifies
     * the failing request in any log aggregation system.
     */
    private final String path;

    /*
     * fieldErrors: populated only for Bean Validation failures.
     * Null for all other error types — @JsonInclude(NON_NULL) omits it.
     * When present, each entry identifies which DTO field failed and why.
     */
    private final List<FieldValidationError> fieldErrors;

    /*
     * Single constructor — all fields set at construction, none mutated.
     * Builder pattern would be appropriate here if fieldErrors were optional
     * in many call sites. Since only one handler populates fieldErrors,
     * two factory methods are cleaner than a builder.
     */
    private ErrorResponse(
            Instant timestamp,
            int status,
            String error,
            String errorCode,
            String message,
            String correlationId,
            String path,
            List<FieldValidationError> fieldErrors) {

        this.timestamp = timestamp;
        this.status = status;
        this.error = error;
        this.errorCode = errorCode;
        this.message = message;
        this.correlationId = correlationId;
        this.path = path;
        this.fieldErrors = fieldErrors;
    }

    /**
     * Factory method for standard errors (no field-level details).
     * Used for all exceptions except MethodArgumentNotValidException.
     */
    public static ErrorResponse of(
            int status,
            String error,
            String errorCode,
            String message,
            String correlationId,
            String path) {

        return new ErrorResponse(
                Instant.now(),
                status,
                error,
                errorCode,
                message,
                correlationId,
                path,
                null
        );
    }

    /**
     * Factory method for Bean Validation errors with field-level details.
     * Used exclusively by the MethodArgumentNotValidException handler.
     */
    public static ErrorResponse ofValidation(
            String correlationId,
            String path,
            List<FieldValidationError> fieldErrors) {

        return new ErrorResponse(
                Instant.now(),
                400,
                "BAD_REQUEST",
                "VALIDATION_FAILED",
                "Request validation failed. See fieldErrors for details.",
                correlationId,
                path,
                fieldErrors
        );
    }

    public Instant getTimestamp() { return timestamp; }
    public int getStatus() { return status; }
    public String getError() { return error; }
    public String getErrorCode() { return errorCode; }
    public String getMessage() { return message; }
    public String getCorrelationId() { return correlationId; }
    public String getPath() { return path; }
    public List<FieldValidationError> getFieldErrors() { return fieldErrors; }
}