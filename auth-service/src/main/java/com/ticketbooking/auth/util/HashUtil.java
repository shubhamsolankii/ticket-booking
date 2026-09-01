package com.ticketbooking.auth.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;

/**
 * Static utility class for cryptographic operations.
 *
 * <p>Why static and NOT a Spring bean?
 * These methods are pure functions: given the same input, they produce
 * the same output (SHA-256) or consume OS entropy (SecureRandom).
 * They have no dependencies, no configuration, no state that varies
 * between call sites. Spring's IOC container manages object LIFECYCLE
 * and DEPENDENCIES — this class has neither. Making it a bean would
 * add framework overhead with zero benefit and would prevent usage
 * in static contexts (e.g., inside @PrePersist callbacks or static
 * factory methods on entities).
 *
 * <p>Thread safety: all methods are safe for concurrent use.
 * ThreadLocal ensures each thread (including virtual threads) has
 * its own MessageDigest instance. SecureRandom is inherently thread-safe.
 */
public final class HashUtil {

    /*
     * MessageDigest is NOT thread-safe. Its internal state is mutated
     * by each digest() call. Two threads calling digest() on the same
     * MessageDigest instance simultaneously will corrupt each other's
     * hash output — silently. No exception. Wrong hash values.
     *
     * The naive fix is synchronization:
     *   synchronized (digest) { digest.reset(); return digest.digest(input); }
     * This serializes ALL hash operations across ALL threads — a throughput
     * bottleneck at 100K RPS.
     *
     * The correct fix is ThreadLocal: each thread gets its own
     * MessageDigest instance, created lazily on first access.
     * Zero contention. Zero synchronization overhead.
     *
     * Virtual threads (Java 21) and ThreadLocal:
     * ThreadLocal works correctly with virtual threads. Each virtual thread
     * has its own ThreadLocal storage, independently of carrier threads.
     * The concern with ThreadLocal + virtual threads is memory: if millions
     * of virtual threads exist simultaneously, each holds a ThreadLocal entry.
     * For MessageDigest (~200 bytes each), this is negligible. The virtual
     * thread's ThreadLocal storage is garbage-collected when the thread
     * terminates — per-request virtual threads terminate quickly.
     * If this were a large object (say, a 1MB buffer), we would use a
     * commons-pool2 object pool instead.
     */
    private static final ThreadLocal<MessageDigest> SHA_256 =
            ThreadLocal.withInitial(() -> {
                try {
                    return MessageDigest.getInstance("SHA-256");
                } catch (NoSuchAlgorithmException e) {
                    /*
                     * SHA-256 is mandated by the Java Security Standard
                     * Algorithm Names specification. Every compliant JVM
                     * MUST provide it. This exception is architecturally
                     * impossible. If it occurs, the JVM installation is
                     * broken and no recovery is possible — fail hard and
                     * fast with an unambiguous message.
                     */
                    throw new IllegalStateException(
                            "SHA-256 algorithm unavailable — JVM installation is corrupt", e
                    );
                }
            });

    /*
     * SecureRandom IS thread-safe. Its implementation uses an internal
     * lock on the seed state, designed for concurrent access.
     * One static instance is correct and efficient.
     *
     * Do NOT create new SecureRandom() per call. SecureRandom initialisation
     * seeds itself from OS entropy sources (/dev/urandom on Linux,
     * CryptGenRandom on Windows). This is an expensive operation —
     * typically 10–100ms. One initialisation at class load time.
     * All subsequent calls reuse the seeded instance.
     *
     * Do NOT use Random or Math.random() for anything security-related.
     * java.util.Random uses a linear congruential generator — predictable
     * given any two consecutive outputs. An attacker who observes two
     * OTPs can compute all future OTPs. SecureRandom uses a
     * cryptographically secure PRNG (DRBG on modern JVMs) where
     * past outputs reveal nothing about future outputs.
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /*
     * Private constructor with guard: this is a utility class.
     * It must never be instantiated.
     *
     * Without this, anyone can write: new HashUtil().sha256Hex(...)
     * which works but is misleading (implies instance state exists).
     * The UnsupportedOperationException makes the mistake immediately
     * visible if someone tries via reflection or accidental instantiation.
     */
    private HashUtil() {
        throw new UnsupportedOperationException(
                "HashUtil is a static utility class and cannot be instantiated"
        );
    }

    /**
     * Computes the SHA-256 hash of the given string and returns it
     * as a 64-character lowercase hex string.
     *
     * <p>Usage: storing refresh token hashes, verification token hashes,
     * and password reset token hashes in PostgreSQL. The client receives
     * the raw token; the DB stores SHA-256(raw_token). If the DB is
     * breached, the attacker has hashes — not the raw tokens needed
     * to authenticate.
     *
     * <p>Why SHA-256 for tokens and NOT bcrypt?
     * Refresh tokens, verification tokens, and reset tokens are already
     * 256 bits of SecureRandom output. The brute-force search space is
     * 2^256 — computationally infeasible regardless of hashing speed.
     * bcrypt's intentional slowness (the entire point of its cost factor)
     * adds 300ms overhead to the token refresh endpoint, which runs at
     * 60K RPS. SHA-256 is O(microseconds) and provides the same security
     * guarantee for this use case. bcrypt is the right tool for passwords
     * (where the input space is small and brute-force is feasible).
     *
     * @param input the raw string to hash — must not be null
     * @return 64-character lowercase hex SHA-256 digest
     */
    public static String sha256Hex(String input) {
        MessageDigest digest = SHA_256.get();
        /*
         * CRITICAL: reset() before every use.
         * MessageDigest accumulates state with each update() call.
         * Without reset(), a subsequent call to digest() appends
         * to the previous call's partial state — producing a wrong hash.
         * Because we reuse the same instance via ThreadLocal, reset()
         * is mandatory before each new hash computation.
         */
        digest.reset();
        byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        /*
         * HexFormat (Java 17+): standard library hex encoding.
         * No external dependencies (Apache Commons Codec, Guava)
         * needed. HexFormat.of() returns a lowercase hex formatter.
         * formatHex(byte[]) converts each byte to two hex characters.
         * SHA-256 output is 32 bytes → 64 hex characters. Always.
         */
        return HexFormat.of().formatHex(hashBytes);
    }

    /**
     * Generates a cryptographically secure random token.
     *
     * <p>Used for: email verification tokens, password reset tokens,
     * and raw refresh tokens (before hashing for storage).
     *
     * <p>Output: 32 random bytes → 64 hex characters.
     * 32 bytes = 256 bits of entropy. The probability of two tokens
     * colliding is 1 in 2^256 — less likely than two random atoms
     * in the observable universe occupying the same quantum state.
     * The UNIQUE constraint on token_hash columns will catch any
     * collision if the impossible occurs.
     *
     * @return 64-character lowercase hex string
     */
    public static String generateSecureToken() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    /**
     * Generates a 6-digit numeric OTP using a cryptographically
     * secure random number generator.
     *
     * <p>Range: 100000–999999 inclusive. The lower bound of 100000
     * ensures the OTP is always exactly 6 digits — no leading zeros,
     * no ambiguity about whether "042951" should be parsed as 6 or 5
     * digits by an SMS app. Simple string comparison in the verify
     * endpoint: no parseInt() needed.
     *
     * <p>The OTP is stored in Redis as SHA-256(otp) with a 5-minute TTL.
     * The raw OTP is sent to the user via SMS. On verify, the incoming
     * OTP is hashed and compared against the stored hash using the
     * Redis Lua script (Step 14) — atomically.
     *
     * @return 6-character numeric string, e.g. "482951"
     */
    public static String generateOtp() {
        /*
         * nextInt(bound) returns a value in [0, bound).
         * nextInt(900000) → [0, 899999]
         * + 100000        → [100000, 999999]
         * Always exactly 6 digits. No modulo bias because SecureRandom
         * uses rejection sampling internally to eliminate bias.
         */
        int otp = 100000 + SECURE_RANDOM.nextInt(900000);
        return String.valueOf(otp);
    }
}