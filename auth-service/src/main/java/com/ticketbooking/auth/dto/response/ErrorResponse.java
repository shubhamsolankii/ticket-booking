package com.ticketbooking.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Builder;
import lombok.Getter;

import java.time.OffsetDateTime;

/**
 * Standardized error response body for all 4xx and 5xx responses.
 *
 * Every service in the platform uses this exact shape — agreed in Phase 2
 * API contract design. The API Gateway and client applications parse this
 * structure to display meaningful error messages and trigger retry logic.
 *
 * correlationId: sourced from X-Correlation-ID request header.
 * Present on every error so a support engineer can find the full
 * trace in Grafana Tempo by querying this ID.
 */
@Getter
@Builder
public class ErrorResponse {

    @JsonFormat(shape = JsonFormat.Shape.STRING)
    // OffsetDateTime serializes as ISO-8601 by default in Jackson.
    // @JsonFormat makes this explicit — no ambiguity if Jackson defaults
    // change between versions. Output: "2025-07-29T10:30:00Z"
    private final OffsetDateTime timestamp;

    // HTTP status code as integer. e.g. 401
    // Duplicates the HTTP response status line intentionally —
    // some API clients (mobile apps, SDKs) parse the body rather
    // than the status line. Both must be consistent.
    private final int status;

    // HTTP status reason phrase. e.g. "UNAUTHORIZED"
    // Machine-readable. Never localized.
    private final String error;

    // Machine-readable error code specific to our domain.
    // e.g. "INVALID_CREDENTIALS", "TOKEN_EXPIRED", "EMAIL_ALREADY_EXISTS"
    // Client applications switch on this value to display localized
    // UI messages. Never switch on the human-readable message string
    // — that is an API contract violation waiting to happen.
    private final String errorCode;

    // Human-readable description. English only. Not localized server-side.
    // e.g. "Invalid email or password."
    private final String message;

    // ULID from X-Correlation-ID header. Links this error response
    // to the full distributed trace in Grafana Tempo.
    // Present on every error response — never omitted.
    private final String correlationId;

    // Request path that produced this error. e.g. "/api/v1/auth/login"
    // Included so log aggregation tools can group errors by endpoint
    // without parsing the request line.
    private final String path;
}