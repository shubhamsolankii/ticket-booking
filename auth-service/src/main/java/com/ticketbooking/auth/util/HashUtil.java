package com.ticketbooking.auth.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;

/**
 * Cryptographic utility methods for token generation and hashing.
 *
 * Design: static utility class, not a Spring bean.
 * No state, no Spring dependencies, pure functions.
 * Making this a @Component would add Spring lifecycle overhead for
 * zero benefit — it has nothing to inject and nothing to manage.
 *
 * Two responsibilities:
 *   1. generateSecureToken() — produces a raw token for client delivery
 *   2. sha256Hex()           — produces a storable hash of that token
 *
 * Usage pattern (consistent across all token flows):
 *   String rawToken  = HashUtil.generateSecureToken(); // send to client
 *   String tokenHash = HashUtil.sha256Hex(rawToken);  // store in DB
 *
 * On incoming request:
 *   String incomingHash = HashUtil.sha256Hex(request.getToken());
 *   repository.findByTokenHash(incomingHash);          // lookup in DB
 */
public final class HashUtil {

    // =========================================================================
    // SECURE RANDOM — static singleton
    // =========================================================================

    /**
     * SecureRandom is thread-safe. One instance shared across all threads
     * is correct and intentional.
     *
     * Why SecureRandom and not java.util.Random:
     * java.util.Random uses a linear congruential generator — the output
     * is predictable if an attacker observes enough values. For tokens
     * that grant authentication or password reset access, a predictable
     * generator means an attacker can compute the next token without
     * ever receiving it. This is a token prediction attack.
     *
     * SecureRandom uses the OS entropy source (e.g., /dev/urandom on Linux)
     * — output is cryptographically unpredictable. The standard for any
     * security-sensitive token generation.
     *
     * Instantiation cost: SecureRandom initialization seeds from the OS
     * entropy source — relatively expensive. One static instance per JVM
     * amortizes this cost across all calls for the lifetime of the process.
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // =========================================================================
    // MESSAGE DIGEST — ThreadLocal pool
    // =========================================================================

    /**
     * MessageDigest is NOT thread-safe. A shared static instance would
     * corrupt hash state under concurrent access — two threads calling
     * digest() on the same instance simultaneously produces incorrect output.
     *
     * Two solutions:
     *   Option A: new MessageDigest per call
     *     Simple. Safe. But at 100K RPS with hashing on every auth operation,
     *     this allocates ~100K short-lived MessageDigest objects per second
     *     on hot paths. GC pressure that grows with throughput.
     *
     *   Option B: ThreadLocal<MessageDigest>
     *     Each thread gets its own MessageDigest instance, initialized once
     *     and reused for the thread's lifetime. Zero allocation after warm-up.
     *     reset() before each use clears prior digest state.
     *     Correct under any level of concurrency.
     *
     * We choose Option B. At 100K RPS, allocation reduction on hot paths
     * is not a premature optimization — it is a p99 latency concern.
     *
     * Virtual threads (Java 21) wrinkle:
     * Virtual threads can be mounted on different carrier (OS) threads
     * between suspensions. A ThreadLocal bound to the carrier thread
     * could leak across virtual thread boundaries in theory.
     * In practice: MessageDigest.digest() is a synchronous CPU operation
     * with no suspension points — a virtual thread never yields during
     * a single sha256Hex() call. The ThreadLocal is safe here.
     * If this ever becomes a concern, ScopedValue (Java 21 preview) is
     * the correct replacement — noted for a future migration if needed.
     */
    private static final ThreadLocal<MessageDigest> SHA256_DIGEST =
            ThreadLocal.withInitial(() -> {
                try {
                    return MessageDigest.getInstance("SHA-256");
                } catch (NoSuchAlgorithmException e) {
                    // SHA-256 is mandated by the Java Security Standard
                    // Algorithm Names spec — every compliant JVM must provide it.
                    // This catch block is unreachable in any standard JVM.
                    // We throw IllegalStateException rather than swallowing the
                    // exception — a missing algorithm is a JVM misconfiguration
                    // that must surface loudly, not be silently ignored.
                    throw new IllegalStateException(
                            "SHA-256 algorithm unavailable — JVM configuration error", e
                    );
                }
            });

    // Private constructor: prevents instantiation.
    // This class is a namespace for static methods, not an object.
    private HashUtil() {
        throw new UnsupportedOperationException(
                "HashUtil is a static utility class and cannot be instantiated"
        );
    }

    // =========================================================================
    // TOKEN GENERATION
    // =========================================================================

    /**
     * Generates a cryptographically secure random token.
     *
     * Output: 64-character lowercase hex string (256 bits of entropy).
     *
     * Used for:
     *   - Email verification tokens (sent in verification link)
     *   - Password reset tokens (sent in reset link)
     *   - Refresh tokens (returned to client after login)
     *
     * NOT used for:
     *   - OTP codes (6-digit numeric, different generation — see OtpService)
     *   - Entity primary keys (ULID — see UlidGenerator)
     *   - JWTs (RS256 signed by JJWT — see TokenService)
     *
     * 256 bits of entropy means:
     *   2^256 possible tokens ≈ 10^77
     *   At 1 trillion guesses per second, brute-forcing takes longer
     *   than the age of the universe. Token length is not a concern.
     *
     * @return 64-character hex string, e.g.:
     *   "a3f8d2c1e9b047f6a1d2c3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4"
     */
    public static String generateSecureToken() {
        byte[] tokenBytes = new byte[32]; // 32 bytes = 256 bits
        SECURE_RANDOM.nextBytes(tokenBytes);
        return HexFormat.of().formatHex(tokenBytes);
        // HexFormat.of() is available since Java 17.
        // Produces lowercase hex — consistent with our storage format.
        // No external dependency needed. No Apache Commons, no Guava.
    }

    // =========================================================================
    // HASHING
    // =========================================================================

    /**
     * Computes the SHA-256 hash of a string and returns it as a
     * lowercase hex string.
     *
     * Output: always exactly 64 characters (256 bits = 32 bytes = 64 hex chars).
     * This fixed length is why the DB columns are CHAR(64), not VARCHAR(64).
     *
     * Used for:
     *   - Hashing raw refresh tokens before DB storage
     *   - Hashing incoming refresh tokens before DB lookup
     *   - Hashing email verification tokens before DB storage/lookup
     *   - Hashing password reset tokens before DB storage/lookup
     *
     * NOT used for:
     *   - Password hashing (BCrypt — handled in AuthService via PasswordEncoder)
     *   - OTP hashing (OtpService uses this — but OTPs go to Redis, not SQL)
     *
     * Why SHA-256 for token hashing, not BCrypt:
     * BCrypt is intentionally slow (cost=12 ≈ 300ms per hash) to resist
     * brute-force attacks against low-entropy secrets like passwords.
     * Refresh tokens, email verification tokens, and reset tokens are
     * 256-bit random values — not low-entropy secrets.
     * Brute-forcing SHA-256(256-bit-random) requires iterating 2^256 values.
     * At 1 trillion SHA-256 hashes per second, this takes 10^65 years.
     * BCrypt's slowness adds 300ms of latency to every token operation
     * with zero security benefit for high-entropy tokens.
     * SHA-256 computes in microseconds. Correct choice for this use case.
     *
     * Input encoding: UTF-8 explicitly.
     * Never rely on the platform default charset — it varies by OS and
     * JVM configuration. A token hashed on a Windows dev machine with
     * CP-1252 default encoding produces a different hash than the same
     * token hashed on a Linux container with UTF-8. Explicit UTF-8
     * guarantees the same hash everywhere.
     *
     * @param input the raw string to hash (raw token, never the hash itself)
     * @return 64-character lowercase hex SHA-256 hash
     * @throws IllegalArgumentException if input is null
     */
    public static String sha256Hex(String input) {
        if (input == null) {
            throw new IllegalArgumentException(
                    "Cannot hash a null value — caller passed null token"
            );
        }

        MessageDigest digest = SHA256_DIGEST.get();
        digest.reset();
        // reset() clears any state from a prior digest() call on this thread.
        // Mandatory when reusing a ThreadLocal MessageDigest instance.
        // Forgetting reset() means the hash includes bytes from a previous
        // call — a silent data corruption bug that only appears under load
        // when a thread is reused across requests.

        byte[] hashBytes = digest.digest(
                input.getBytes(StandardCharsets.UTF_8)
        );

        return HexFormat.of().formatHex(hashBytes);
    }
}