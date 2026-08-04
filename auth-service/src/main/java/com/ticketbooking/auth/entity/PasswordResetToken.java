package com.ticketbooking.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.OffsetDateTime;

/**
 * Represents one active password reset request.
 *
 * Lifecycle: INSERT on POST /auth/password/forgot (if email exists).
 *            INSERT on resend — old row deleted first, same transaction.
 *            DELETE on POST /auth/password/reset (success path only).
 *            Expired tokens are NOT proactively deleted — a background
 *            cleanup job (added in a future step) handles that via
 *            DELETE WHERE expires_at < NOW(). The cleanup job uses
 *            CREATE INDEX CONCURRENTLY on expires_at — not added now
 *            because the index does not serve the hot path, only the
 *            cleanup batch. We add indexes when the query exists.
 *
 * DB invariants:
 *   UNIQUE(token_hash)  — one lookup path, no hash collisions possible
 *   UNIQUE(user_id)     — one active reset token per user at a time
 *
 * Token security model:
 *   Client receives: raw 256-bit SecureRandom token (64 hex chars) embedded
 *                    in a password reset URL sent via email
 *   We store:        SHA-256(raw token)
 *   Reset path:      hash incoming token → WHERE token_hash = hash →
 *                    validate expiry → execute four-step transaction
 *
 * The four-step reset transaction (written in AuthService, not here):
 *   1. Lock this token row (SELECT FOR UPDATE)
 *   2. Delete this token row
 *   3. Update users.password_hash
 *   4. Delete ALL refresh_tokens WHERE user_id = ?  ← revoke all sessions
 *
 * Step 4 contends with concurrent refresh transactions. See AuthService
 * for lock ordering strategy and CannotAcquireLockException handling.
 */
@Entity
@Table(
        name = "password_reset_tokens",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uq_password_reset_tokens_token_hash",
                        columnNames = "token_hash"
                ),
                // One active reset token per user at a time.
                // If a second forgot-password request arrives before the first
                // token is used, the service deletes the old token and inserts
                // a new one — same transaction. The constraint enforces this
                // invariant at the DB level regardless of service behavior.
                @UniqueConstraint(
                        name = "uq_password_reset_tokens_user_id",
                        columnNames = "user_id"
                )
        }
)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class PasswordResetToken {

    @Id
    @Column(name = "id", length = 26, nullable = false, updatable = false)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(
            name = "user_id",
            nullable = false,
            updatable = false,
            foreignKey = @ForeignKey(name = "fk_password_reset_tokens_user")
    )
    // LAZY for the same reason as every other token entity: we never
    // need the full User object from this association. The User is
    // loaded separately in AuthService by userId before this token
    // is queried. An EAGER join here would add an unnecessary JOIN
    // to users on every token lookup — wasteful and incorrect.
    private User user;

    @Column(name = "user_id", insertable = false, updatable = false)
    // Read-only FK projection. Avoids lazy load for userId reads.
    // insertable=false, updatable=false: @JoinColumn owns the write path.
    private String userId;

    @Column(name = "token_hash", length = 64, nullable = false, updatable = false)
    // SHA-256 of the raw token embedded in the reset URL.
    // Always exactly 64 hex chars.
    // The UNIQUE constraint creates the B-tree index used by:
    // WHERE token_hash = SHA256(incomingToken)
    // updatable=false: a reset token hash never changes after creation.
    private String tokenHash;

    @Column(name = "expires_at", nullable = false, updatable = false)
    // Application sets this: OffsetDateTime.now().plusHours(1).
    // 1-hour window — tighter than email verification (24 hours) because
    // password reset is a higher-risk operation. A stolen reset link
    // has a smaller window to be exploited.
    // The expiry duration lives in application config:
    //   auth.password-reset-expiry-hours: 1
    // Not hardcoded here. If security policy changes the window to
    // 30 minutes, it's a config change, not a code change.
    private OffsetDateTime expiresAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    // No updatedAt. No @PreUpdate. No DB trigger on this table.
    // Append-only. The absence communicates the invariant.

    // ==========================================================================
    // FACTORY METHOD
    // ==========================================================================

    /**
     * Creates a new password reset token record.
     *
     * Called by AuthService in two scenarios:
     * 1. First forgot-password request — user has no active reset token.
     * 2. Repeat forgot-password request — old token deleted first in the
     *    same transaction, then this factory is called. The UNIQUE(user_id)
     *    constraint ensures the delete must succeed before the insert
     *    can proceed. If both are in the same transaction and the delete
     *    hasn't flushed yet when the insert fires, Hibernate flush ordering
     *    handles it: deletes before inserts within the same transaction.
     *
     * AuthService always returns HTTP 200 from POST /auth/password/forgot
     * regardless of whether the email exists. This method is only called
     * when the user IS found — the 200 response is sent before or
     * regardless of what happens here, preventing email enumeration.
     *
     * @param id         ULID generated in service layer before this call
     * @param user       The User entity whose password is being reset
     * @param tokenHash  SHA-256(rawToken) — computed in HashUtil
     * @param expiresAt  NOW() + 1 hour — computed in service layer
     */
    public static PasswordResetToken create(
            String id,
            User user,
            String tokenHash,
            OffsetDateTime expiresAt
    ) {
        PasswordResetToken token = new PasswordResetToken();
        token.id = id;
        token.user = user;
        token.tokenHash = tokenHash;
        token.expiresAt = expiresAt;
        return token;
    }

    // ==========================================================================
    // DOMAIN METHODS
    // ==========================================================================

    /**
     * Returns true if this token has passed its 1-hour expiry window.
     *
     * Checked in AuthService before executing the four-step reset transaction.
     * An expired token returns HTTP 400 — not 410. Why not 410 like email
     * verification? Because password reset links are delivered by email
     * and bookmarked by users. Returning 410 Gone implies the resource is
     * permanently gone — which is correct semantically but confusing in UX.
     * 400 with message "Reset link has expired. Please request a new one."
     * is clearer for this specific user journey.
     */
    public boolean isExpired() {
        return OffsetDateTime.now().isAfter(this.expiresAt);
    }

    // ==========================================================================
    // JPA LIFECYCLE CALLBACK
    // ==========================================================================

    @PrePersist
    protected void onPersist() {
        this.createdAt = OffsetDateTime.now();
    }
}