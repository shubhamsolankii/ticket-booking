package com.ticketbooking.auth.exception;

/**
 * Represents a single field-level validation failure.
 * Included in ErrorResponse only when the failure is a
 * Bean Validation error (@Valid on a request DTO).
 * Immutable by design — constructed once, never mutated.
 * No framework annotations — this is plain Java.
 */
public class FieldValidationError {

    private final String field;
    private final String message;

    public FieldValidationError(String field, String message) {
        this.field = field;
        this.message = message;
    }

    public String getField() {
        return field;
    }

    public String getMessage() {
        return message;
    }
}