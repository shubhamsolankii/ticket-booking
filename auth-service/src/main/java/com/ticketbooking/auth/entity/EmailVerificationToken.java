package com.ticketbooking.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
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
 * Represents one pending email verification request.
 *
 * Lifecycle: INSERT on registration (POST /auth/register).
 *            INSERT on resend (old row deleted first — same transaction).
 *            DELETE on successful verification (POST /auth/verify-email).
 *            Never UPDATEd. Append-only.
 *
 * DB invariant: UNIQUE(user_id) — at most one active token per user at
 * any point in time. Enforced at PostgreSQL level, not only in service code.
 * If service code has a bug and attempts two inserts for the same user,
 * the constraint catches it. DB constraints are the last line of defense.
 *
 * Token security model:
 *   Client receives: raw 256-bit SecureRandom token (64 hex chars)
 *   We store:        SHA-256(raw token)
 *   Verification:    hash incoming token → compare against stored hash → match or reject
 */
@Entity
@Table(
        name = "email_verification_tokens",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uq_email_verification_tokens_token_hash",
                        columnNames = "token_hash"
                ),
                // This is the critical constraint. One active verification token
                // per user at a time. Maps to the DB-level UNIQUE(user_id) in
                // V3__create_email_verification_tokens_table.sql.
                // Hibernate ddl-auto=validate checks this constraint name on startup.
                @UniqueConstraint(
                        name = "uq_email_verification_tokens_user_id",
                        columnNames = "user_id"
                )
        }
)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class EmailVerificationToken {

    @Id
    @Column(name = "id", length = 26, nullable = false, updatable = false)
    // ULID of the token record — not the token itself.
    // Generated in service layer before insert.
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(
            name = "user_id",
            nullable = false,
            updatable = false,
            foreignKey = @ForeignKey(name = "fk_email_verification_tokens_user")
            // Name matches V3 migration constraint name exactly.
    )
    // FetchType.LAZY: verification flow never needs the full User object
    // from this side of the association. We access the User entity
    // directly in AuthService — loaded separately by userId before
    // this token is queried.
    private User user;

    @Column(name = "user_id", insertable = false, updatable = false)
    // Read-only projection of the FK. Lets service code read userId
    // for logging and audit without triggering a lazy load of User.
    // insertable=false, updatable=false: @JoinColumn owns the write path.
    private String userId;

    @Column(name = "token_hash", length = 64, nullable = false, updatable = false)
    // SHA-256 of the raw token sent to the client in the verification email.
    // Always exactly 64 hex chars — CHAR(64) at DB level.
    // updatable=false: a verification token hash never changes.
    // The UNIQUE constraint above creates the B-tree index used by
    // the lookup: WHERE token_hash = SHA256(incomingToken).
    private String tokenHash;

    @Column(name = "expires_at", nullable = false, updatable = false)
    // Application sets this: OffsetDateTime.now().plusHours(24).
    // 24-hour window is a business rule — lives in application config,
    // not hardcoded in this class.
    // updatable=false: expiry is fixed at creation, never extended.
    // If the user requests a resend, this row is deleted and a new
    // one is created with a fresh 24-hour window.
    private OffsetDateTime expiresAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    // No updatedAt. No @PreUpdate. No DB trigger on this table.
    // Append-only design. The absence is intentional and communicates
    // the invariant: this row is never modified after creation.

    // ==========================================================================
    // FACTORY METHOD
    // ==========================================================================

    /**
     * Creates a new email verification token record.
     *
     * Called by AuthService in two scenarios:
     * 1. New registration — directly after User row is created, same transaction.
     * 2. Resend request — after the old token row is deleted, same transaction.
     *
     * The delete-then-insert sequence for resend is atomic: both operations
     * happen inside a single @Transactional boundary in AuthService.
     * If the insert fails (e.g., unique violation due to a race), the
     * entire transaction rolls back and the old token remains intact.
     *
     * @param id         ULID generated in service layer before this call
     * @param user       The User entity whose email needs verification
     * @param tokenHash  SHA-256(rawToken) — computed in HashUtil before this call
     * @param expiresAt  NOW() + 24 hours — computed in service layer using
     *                   the configured expiry duration, not hardcoded here
     */
    public static EmailVerificationToken create(
            String id,
            User user,
            String tokenHash,
            OffsetDateTime expiresAt
    ) {
        EmailVerificationToken token = new EmailVerificationToken();
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
     * Returns true if this token has passed its 24-hour expiry window.
     *
     * Checked in AuthService before proceeding with verification.
     * Expired tokens return HTTP 410 Gone — distinct from 400 Bad Request
     * (token not found), giving the client actionable information:
     * "your link expired, request a new one."
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