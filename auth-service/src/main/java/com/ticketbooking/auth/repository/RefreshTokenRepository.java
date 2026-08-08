package com.ticketbooking.auth.repository;

import com.ticketbooking.auth.entity.RefreshToken;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import jakarta.persistence.QueryHint;
import java.util.Optional;

/**
 * Data access layer for the refresh_tokens table.
 *
 * All queries execute against the PRIMARY PostgreSQL node.
 * Refresh token state is security-critical. Stale replica reads
 * are never acceptable here — a revoked token visible as valid
 * on a replica is a session hijacking vulnerability.
 *
 * Query coverage:
 *   findByTokenHashForUpdate → token rotation (FOR UPDATE row lock)
 *   deleteByTokenHash        → single device logout
 *   deleteAllByUserId        → logout-all + password reset session revocation
 *   countByUserId            → session count guard (max sessions per user)
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {

    // =========================================================================
    // READ WITH LOCK — TOKEN ROTATION HOT PATH
    // =========================================================================

    /**
     * Fetches a refresh token row by its SHA-256 hash and acquires an
     * exclusive row-level lock (SELECT FOR UPDATE).
     *
     * This is the entry point for POST /auth/token/refresh at 60K RPS.
     *
     * Generated SQL:
     *   SELECT rt.* FROM refresh_tokens rt
     *   WHERE rt.token_hash = $1
     *   FOR UPDATE
     *
     * Why FOR UPDATE here, not on a plain findByTokenHash:
     * Two concurrent requests arrive with the same refresh token.
     * Without FOR UPDATE:
     *   T1 reads row → valid
     *   T2 reads row → valid
     *   T1 deletes row, inserts new token, issues new JWT pair → commits
     *   T2 deletes row → row already gone (T1 deleted it)
     *   T2 inserts new token, issues new JWT pair → commits
     *   Result: two valid JWT pairs issued from one refresh token.
     *           The original session is now duplicated. Security breach.
     *
     * With FOR UPDATE:
     *   T1 reads row, acquires exclusive lock → valid
     *   T2 attempts to read same row → BLOCKS (waits for T1's lock)
     *   T1 deletes row, inserts new token → commits, lock released
     *   T2 unblocks, reads row → row is gone → returns Optional.empty()
     *   T2 service layer → throws TokenInvalidException → 401
     *   Result: exactly one new token pair issued. Correct.
     *
     * @QueryHints with TIMEOUT:
     * If T1 is slow (bcrypt, external call, GC pause), T2 could block
     * indefinitely. We set a 5-second lock wait timeout. After 5 seconds,
     * PostgreSQL throws a lock timeout exception → Spring maps to
     * CannotAcquireLockException → service layer returns 503.
     * A 503 is recoverable. An indefinitely blocked thread is not.
     *
     * MUST be called within an active @Transactional boundary.
     * @Lock without an active transaction is a no-op — the lock is
     * acquired but released immediately when the connection returns
     * to the pool. The @Transactional on the service method that
     * calls this provides the transaction boundary.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @QueryHints(
            @QueryHint(name = "jakarta.persistence.lock.timeout", value = "5000")
            // 5000 milliseconds. PostgreSQL interprets this via the
            // SET lock_timeout = '5000ms' statement issued before the query.
            // After 5 seconds of waiting for the row lock, PostgreSQL throws:
            // ERROR 55P03: canceling statement due to lock timeout
            // Spring translates this to CannotAcquireLockException.
    )
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.tokenHash = :tokenHash")
    Optional<RefreshToken> findByTokenHashForUpdate(@Param("tokenHash") String tokenHash);

    // =========================================================================
    // DELETE — SINGLE DEVICE LOGOUT
    // =========================================================================

    /**
     * Deletes a single refresh token by its hash.
     *
     * Used by: POST /auth/logout (single device — no ?all=true flag).
     *
     * Generated SQL:
     *   DELETE FROM refresh_tokens WHERE token_hash = $1
     *
     * Why @Modifying with JPQL DELETE instead of Spring Data's
     * derived deleteByTokenHash:
     * Spring Data's derived deleteBy first executes:
     *   SELECT * FROM refresh_tokens WHERE token_hash = $1
     * then for each result:
     *   DELETE FROM refresh_tokens WHERE id = $2
     * That is 2 round-trips for a single row deletion.
     * Our JPQL DELETE is 1 round-trip. At logout volume, this matters.
     *
     * clearAutomatically = true: clears the persistence context after
     * the DELETE. If the deleted entity was loaded earlier in the same
     * transaction, the stale managed instance is evicted. Subsequent
     * findById calls go to the DB, not the cache.
     *
     * flushAutomatically = true: flushes any pending changes in the
     * persistence context before executing the DELETE. Prevents the
     * case where a newly created RefreshToken entity is pending in
     * the context and a DELETE runs before Hibernate flushes the INSERT.
     * In that scenario without flushAutomatically, the INSERT and DELETE
     * could execute in the wrong order — the DELETE fires first (no-op
     * since row doesn't exist yet), then the INSERT creates the row that
     * was supposed to be deleted.
     *
     * Returns int: number of rows deleted (0 or 1).
     * Service layer ignores this count — logout is idempotent.
     * Deleting a token that doesn't exist is not an error.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("DELETE FROM RefreshToken rt WHERE rt.tokenHash = :tokenHash")
    int deleteByTokenHash(@Param("tokenHash") String tokenHash);

    // =========================================================================
    // DELETE — BULK LOGOUT (ALL DEVICES + PASSWORD RESET)
    // =========================================================================

    /**
     * Deletes ALL refresh tokens for a given user in a single statement.
     *
     * Used by two callers — both require all sessions revoked atomically:
     *
     * 1. POST /auth/logout?all=true
     *    User explicitly logs out all devices. Every active session
     *    must be invalidated in a single atomic operation. If we deleted
     *    tokens one by one, a concurrent refresh on session 3 could
     *    succeed between deletes of session 2 and session 4 — leaving
     *    a valid session that the user thought they revoked.
     *
     * 2. POST /auth/password/reset (success path, step 4 of 4)
     *    After password update, all sessions must be revoked. Someone
     *    who initiated a password reset because their account was
     *    compromised needs every existing session invalidated immediately.
     *    This DELETE runs inside the same transaction as the password_hash
     *    UPDATE on the users table — all or nothing.
     *
     * Generated SQL:
     *   DELETE FROM refresh_tokens WHERE user_id = $1
     *
     * Index used: idx_refresh_tokens_user_id (B-tree, non-unique).
     * Without this index, the DELETE is a sequential scan of the entire
     * refresh_tokens table — catastrophic at scale when millions of
     * users have active sessions.
     *
     * Why NOT Spring Data's derived deleteAllByUser_Id:
     * Spring Data executes this as:
     *   SELECT id, user_id, token_hash, expires_at, created_at
     *   FROM refresh_tokens WHERE user_id = $1
     * then for EACH row:
     *   DELETE FROM refresh_tokens WHERE id = $2
     * A user with 10 active sessions = 11 DB round-trips.
     * Our JPQL DELETE = 1 round-trip regardless of session count.
     *
     * Lock contention note:
     * This DELETE acquires exclusive locks on all matching rows.
     * If any of those rows are currently locked by a concurrent
     * findByTokenHashForUpdate (a refresh in progress), this DELETE
     * blocks until those transactions commit or roll back.
     * This is expected behavior — not a bug. The lock_timeout set
     * on the session via PostgreSQL's SET statement provides the
     * ceiling. If contention exceeds 5 seconds, CannotAcquireLockException
     * surfaces and AuthService handles it with a retry or 503.
     *
     * Returns int: number of rows deleted.
     * Useful for audit logging: "revoked N sessions on password reset."
     * Not used for error determination — 0 deleted sessions is valid
     * (user had no active sessions).
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("DELETE FROM RefreshToken rt WHERE rt.userId = :userId")
    int deleteAllByUserId(@Param("userId") String userId);

    // =========================================================================
    // COUNT — SESSION GUARD
    // =========================================================================

    /**
     * Counts active sessions for a given user.
     *
     * Used by: AuthService before issuing a new refresh token on login.
     * If a user already has MAX_SESSIONS (default: 5) active sessions,
     * the oldest session is revoked before the new one is created.
     * This prevents unbounded growth of the refresh_tokens table for
     * a single user (e.g., a bot repeatedly logging in without logging out).
     *
     * Generated SQL:
     *   SELECT COUNT(rt.id) FROM refresh_tokens rt WHERE rt.user_id = $1
     *
     * Index used: idx_refresh_tokens_user_id.
     * This is a fast COUNT on an indexed column — not a sequential scan.
     *
     * Note: expired tokens are included in this count. The cleanup job
     * (added in a future step) purges expired tokens periodically.
     * The session guard works correctly even with stale expired rows —
     * worst case, a user is asked to re-login slightly earlier than
     * their oldest non-expired session would have required. Acceptable.
     */
    long countByUserId(String userId);
}