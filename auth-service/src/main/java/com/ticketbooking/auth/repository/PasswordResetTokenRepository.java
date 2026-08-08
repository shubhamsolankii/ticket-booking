package com.ticketbooking.auth.repository;

import com.ticketbooking.auth.entity.PasswordResetToken;
import jakarta.persistence.LockModeType;
import jakarta.persistence.QueryHint;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Data access layer for the password_reset_tokens table.
 *
 * All queries execute against the PRIMARY PostgreSQL node.
 *
 * Access patterns:
 *   findByTokenHashForUpdate → POST /auth/password/reset (locked lookup)
 *   deleteByUserId           → resend flow (clear old token before new one)
 *
 * Token deletion on successful reset uses the inherited delete(entity)
 * from JpaRepository — entity is already managed from the
 * findByTokenHashForUpdate call. Deletes by PK in a single statement.
 *
 * The full four-step reset transaction (written in AuthService):
 *   1. findByTokenHashForUpdate  → acquire row lock on this token
 *   2. delete(token)             → DELETE FROM password_reset_tokens WHERE id = ?
 *   3. user.changePassword(hash) → UPDATE users SET password_hash = ?
 *   4. deleteAllByUserId(userId) → DELETE FROM refresh_tokens WHERE user_id = ?
 *   All four steps inside one @Transactional boundary. All or nothing.
 */
@Repository
public interface PasswordResetTokenRepository
        extends JpaRepository<PasswordResetToken, String> {

    // =========================================================================
    // READ WITH LOCK — PASSWORD RESET PATH
    // =========================================================================

    /**
     * Fetches a password reset token by its SHA-256 hash and acquires
     * an exclusive row-level lock (SELECT FOR UPDATE).
     *
     * Used by: POST /auth/password/reset.
     * Index used: uq_password_reset_tokens_token_hash (B-tree, unique).
     *
     * Generated SQL:
     *   SELECT * FROM password_reset_tokens WHERE token_hash = $1 FOR UPDATE
     *
     * Why FOR UPDATE is mandatory here — the concurrent reset scenario:
     *
     * Without FOR UPDATE (READ COMMITTED, two concurrent requests):
     *   T1 reads token row → valid, not expired
     *   T2 reads token row → valid, not expired (same row, both readers)
     *   T1 updates password to "Alpha1!" → deletes token → deletes sessions → commits
     *   T2 updates password to "Beta2@"  → deletes token (no-op) → deletes sessions → commits
     *   Result: password is "Beta2@" but user received "Alpha1!" confirmation.
     *           User cannot log in with either password reliably.
     *           Security incident.
     *
     * With FOR UPDATE:
     *   T1 reads row → acquires exclusive lock → validates → proceeds
     *   T2 reads row → BLOCKS (waits for T1's lock)
     *   T1 updates password → deletes token → commits → lock released
     *   T2 unblocks → row is gone → returns Optional.empty()
     *   T2 service layer → throws TokenInvalidException → 400
     *   Result: exactly one password update. Correct.
     *
     * Lock timeout: 3000ms (3 seconds).
     * Password reset is a very low-volume path — concurrent resets with
     * the same token are an extreme edge case. The 3-second timeout is
     * generous. If exceeded, CannotAcquireLockException surfaces and
     * AuthService returns 503. Client retries.
     *
     * This is shorter than the RefreshToken timeout (5 seconds) because:
     * RefreshToken contention is expected at 60K RPS — the timeout must
     * account for real sustained queue depth. Password reset contention
     * is an edge case — a shorter timeout fails fast appropriately.
     *
     * MUST be called within an active @Transactional boundary.
     * The lock is held until the transaction commits or rolls back.
     * The four-step reset transaction in AuthService provides this boundary.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @QueryHints(
            @QueryHint(
                    name = "jakarta.persistence.lock.timeout",
                    value = "3000"
            )
    )
    @Query("""
        SELECT prt FROM PasswordResetToken prt
        WHERE prt.tokenHash = :tokenHash
        """)
    Optional<PasswordResetToken> findByTokenHashForUpdate(
            @Param("tokenHash") String tokenHash
    );

    // =========================================================================
    // DELETE — RESEND FLOW
    // =========================================================================

    /**
     * Deletes the existing reset token for a user.
     *
     * Used by: POST /auth/password/forgot when user already has an
     * active (possibly unexpired) reset token. We delete the old one
     * and issue a fresh token with a new 1-hour window. This prevents
     * a user from accumulating multiple valid reset links if they
     * click "forgot password" repeatedly.
     *
     * Generated SQL:
     *   DELETE FROM password_reset_tokens WHERE user_id = $1
     *
     * Returns int: rows deleted (0 or 1 — UNIQUE(user_id) guarantees at most 1).
     * Service layer ignores the count. This call is safe to make even if
     * no prior token exists — 0 deleted rows is not an error.
     *
     * Runs within the same @Transactional boundary as the subsequent
     * PasswordResetToken.create() + save() call. The delete-then-insert
     * is atomic. The UNIQUE(user_id) constraint at the DB level is the
     * last line of defense if the application transaction boundary has
     * a bug — the constraint violation surfaces before a duplicate row
     * can be committed.
     *
     * Consistency: STRONG. PRIMARY node only.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
        DELETE FROM PasswordResetToken prt
        WHERE prt.userId = :userId
        """)
    int deleteByUserId(@Param("userId") String userId);
}