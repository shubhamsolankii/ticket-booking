package com.ticketbooking.auth.repository;

import com.ticketbooking.auth.entity.EmailVerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Data access layer for the email_verification_tokens table.
 *
 * All queries execute against the PRIMARY PostgreSQL node.
 *
 * Access patterns:
 *   findByTokenHash  → POST /auth/verify-email lookup
 *   deleteByUserId   → resend flow (clear old token before inserting new one)
 *
 * Token deletion on successful verification uses the inherited
 * delete(entity) from JpaRepository — the entity is already in the
 * persistence context from the findByTokenHash call, so delete(entity)
 * issues a single DELETE WHERE id = ? with no extra SELECT round-trip.
 */
@Repository
public interface EmailVerificationTokenRepository
        extends JpaRepository<EmailVerificationToken, String> {

    // =========================================================================
    // READ — VERIFICATION PATH
    // =========================================================================

    /**
     * Fetches an email verification token by its SHA-256 hash.
     *
     * Used by: POST /auth/verify-email.
     * Index used: uq_email_verification_tokens_token_hash (B-tree, unique).
     *
     * Generated SQL:
     *   SELECT * FROM email_verification_tokens WHERE token_hash = $1
     *
     * No FOR UPDATE on this method. See class-level comment for reasoning:
     * concurrent verification with the same token is idempotent —
     * both requests produce the same outcome (user verified), and the
     * duplicate token deletion is a harmless no-op. Adding FOR UPDATE
     * would add row lock acquisition latency on a low-volume path
     * with zero security benefit.
     *
     * Service layer flow after this call:
     *   1. Optional.empty() → throw TokenInvalidException → 400
     *   2. token.isExpired() → throw TokenExpiredException → 410
     *   3. user.verifyEmail() → mutate User entity
     *   4. emailVerificationTokenRepository.delete(token) → DELETE by PK
     *   5. userRepository.save(user) → UPDATE users SET email_verified = true
     *   6. Commit — steps 3, 4, 5 are in one @Transactional boundary
     */
    Optional<EmailVerificationToken> findByTokenHash(String tokenHash);

    // =========================================================================
    // DELETE — RESEND FLOW
    // =========================================================================

    /**
     * Deletes the existing verification token for a user.
     *
     * Used by: resend verification email flow (future endpoint).
     * Also called defensively at registration if a prior token exists
     * for the same email due to a previous abandoned registration attempt.
     *
     * Generated SQL:
     *   DELETE FROM email_verification_tokens WHERE user_id = $1
     *
     * Why direct JPQL DELETE over Spring Data derived deleteByUser_Id:
     * Derived deleteBy loads the entity first (SELECT), then deletes by PK.
     * Two round-trips for a table bounded to one row per user by the
     * UNIQUE(user_id) constraint. Our JPQL is always one round-trip.
     *
     * Returns int: rows deleted (0 if no existing token, 1 if one existed).
     * Service layer ignores the count — this call is always safe to make
     * regardless of whether a prior token exists.
     *
     * flushAutomatically = true: flushes any pending INSERT for a new
     * EmailVerificationToken before this DELETE executes. Prevents the
     * ordering inversion where the DELETE fires before the INSERT it
     * was supposed to precede.
     *
     * clearAutomatically = true: evicts any stale EmailVerificationToken
     * entity from the persistence context after the DELETE. Ensures a
     * subsequent findByTokenHash in the same transaction hits the DB.
     *
     * Consistency: STRONG. Runs on PRIMARY node within the same
     * @Transactional boundary as the subsequent INSERT of the new token.
     * The delete-then-insert is atomic — partial state is impossible.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
        DELETE FROM EmailVerificationToken evt
        WHERE evt.userId = :userId
        """)
    int deleteByUserId(@Param("userId") String userId);
}