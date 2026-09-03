package com.ticketbooking.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when OTP verification fails: wrong OTP value,
 * or maximum verification attempts exceeded for this OTP.
 *
 * Both cases produce the same response — we do not tell the client
 * "you have N attempts remaining" as that gives an attacker a
 * progress indicator for brute-forcing.
 *
 * 401 Unauthorized: the presented credential (OTP) is not valid.
 * After max attempts, the OTP is deleted from Redis by OtpService —
 * subsequent attempts will receive InvalidTokenException (OTP no longer
 * exists) or TokenExpiredException (OTP TTL elapsed), not this exception.
 */
public class OtpVerificationException extends AuthException {

    public OtpVerificationException() {
        super(
                "OTP verification failed. Please request a new OTP.",
                HttpStatus.UNAUTHORIZED,
                "OTP_INVALID"
        );
    }
}