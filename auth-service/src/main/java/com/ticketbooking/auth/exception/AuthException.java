package com.ticketbooking.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Abstract base for all Auth Service business exceptions.
 *
 * Every concrete exception carries two things beyond its message:
 * - httpStatus: the HTTP status code to return to the client
 * - errorCode:  the machine-readable error identifier for client branching
 *
 * This design eliminates every status-code decision from GlobalExceptionHandler.
 * The handler never asks "which exception is this, what status does it get?" —
 * it calls ex.getHttpStatus() and gets the answer directly from the exception.
 * Adding a new exception type requires zero changes to GlobalExceptionHandler.
 * That is the Open/Closed Principle in practice.
 *
 * Why RuntimeException and not Exception?
 * Checked exceptions (extends Exception) force every call site to declare
 * "throws X" or catch it. For business exceptions that propagate up to the
 * controller layer to be handled by GlobalExceptionHandler, checked exceptions
 * add ceremony without safety — the GlobalExceptionHandler IS the handling.
 * Spring's own exception hierarchy (DataAccessException, etc.) uses
 * RuntimeException for the same reason.
 *
 * Abstract: AuthException itself is never thrown directly.
 * Every throw site uses a concrete, named subclass that communicates
 * exactly what went wrong. "throw new AuthException(...)" is meaningless
 * — "throw new InvalidTokenException(...)" is precise and searchable.
 */
public abstract class AuthException extends RuntimeException {

    private final HttpStatus httpStatus;
    private final String errorCode;

    protected AuthException(String message, HttpStatus httpStatus, String errorCode) {
        super(message);
        this.httpStatus = httpStatus;
        this.errorCode = errorCode;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public String getErrorCode() {
        return errorCode;
    }
}