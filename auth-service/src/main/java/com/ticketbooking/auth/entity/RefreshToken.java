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
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.OffsetDateTime;

/**
 * Represents one active refresh token session.
 *
 * Lifecycle: INSERT on login/OTP verify/OAuth2 exchange.
 *            DELETE on logout, token rotation, password reset.
 *            Never UPDATEd. Append-only.
 *
 * The client holds the raw 256-bit token (64 hex chars).
 * We store SHA-256(raw token). If this table is breached,
 * the attacker has hashes — not usable tokens.
 *
 * Concurrent refresh protection: RefreshTokenRepository uses
 * SELECT FOR UPDATE on the token_hash lookup. Two simultaneous
 * requests with the same token — one wins the row lock,
 * the other gets 401 after the first commits and deletes the row.
 */
@Entity
@Table(
        name = "refresh_tokens",
        indexes = {
                // Explicit index declaration here mirrors V2__create_refresh_tokens_table.sql.
                // The UNIQUE constraint on token_hash creates its own implicit index.
                // We declare idx_refresh_tokens_user_id explicitly — used by
                // DELETE WHERE user_id = ? on logout-all and password reset.
                @Index(name = "idx_refresh_tokens_user_id", columnList = "user_id")
        }
)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshToken {

    @Id
    @Column(name = "id", length = 26, nullable = false, updatable = false)
    // ULID of the token RECORD — not the token itself.
    // Generated in the service layer before insert.
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(
            name = "user_id",
            nullable = false,
            updatable = false,
            foreignKey = @ForeignKey(name = "fk_refresh_tokens_user")
            // Name matches V2 migration. Hibernate ddl-auto=validate
            // checks FK constraint names. A mismatch causes startup failure.
    )
    // FetchType.LAZY: we never need the full User object when working
    // with a refresh token. EAGER would join the users table on every
    // token lookup — wasteful at 60K RPS. If we need the userId,
    // we access it via the userId field below.
    private User user;

    @Column(name = "user_id", insertable = false, updatable = false)
    // Read-only projection of the FK column. Allows us to read userId
    // without triggering a lazy load of the User entity.
    // insertable = false, updatable = false: this column is managed
    // by the @JoinColumn above. Declaring it here as read-only
    // avoids the "column mapped twice" exception from Hibernate.
    private String userId;

    @Column(name = "token_hash", length = 64, nullable = false, updatable = false,
            unique = true)
    // SHA-256 of the raw token sent to the client.
    // Always exactly 64 hex chars. CHAR(64) in the DB.
    // unique = true mirrors the uq_refresh_tokens_token_hash constraint
    // in V2 migration and creates the B-tree index used by
    // SELECT FOR UPDATE on the refresh path at 60K RPS.
    // updatable = false: a token hash never changes. If it could,
    // the rotation invariant breaks.
    private String tokenHash;

    @Column(name = "expires_at", nullable = false, updatable = false)
    // Application sets this: OffsetDateTime.now().plusDays(7).
    // Not a DB DEFAULT — TTL is a business rule (7 days), managed
    // in application config (jwt.refresh-token-expiry-days).
    // Checked in service layer on every refresh: if NOW() > expiresAt → 401.
    // updatable = false: expiry is fixed at creation. We never extend a token.
    private OffsetDateTime expiresAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    // Audit trail. When was this session created?
    // Useful for "show active sessions" feature (future endpoint).
    // updatable = false: creation time is immutable.
    private OffsetDateTime createdAt;

    // No updatedAt. No @PreUpdate. No DB trigger on this table.
    // Append-only design: the absence of updatedAt is intentional
    // and communicates the invariant clearly to every future developer.

    // ==========================================================================
    // FACTORY METHOD
    // One creation path. Enforces all invariants at construction time.
    // ==========================================================================

    /**
     * Creates a new refresh token record.
     *
     * Called by AuthService immediately after:
     * - Successful email+password login
     * - Successful OTP verification
     * - Successful OAuth2 token exchange
     * - Successful token rotation (old token deleted, new one created)
     *
     * @param id            ULID generated in service layer before this call
     * @param user          The authenticated User entity (managed by JPA context)
     * @param tokenHash     SHA-256(rawToken) — computed in HashUtil before this call
     * @param expiresAt     NOW() + 7 days — computed in service layer
     */
    public static RefreshToken create(
            String id,
            User user,
            String tokenHash,
            OffsetDateTime expiresAt
    ) {
        RefreshToken token = new RefreshToken();
        token.id = id;
        token.user = user;
        token.tokenHash = tokenHash;
        token.expiresAt = expiresAt;
        return token;
        // createdAt is set in @PrePersist below.
        // We do not set it here — single responsibility:
        // the factory builds the domain object,
        // @PrePersist handles the persistence concern.
    }

    // ==========================================================================
    // DOMAIN METHOD
    // ==========================================================================

    /**
     * Returns true if this token has passed its expiry time.
     * Called in AuthService.refreshToken() before issuing new tokens.
     *
     * Checking expiry in the service layer (not only at the DB query level)
     * gives us a clear 401 reason: "token expired" vs "token not found".
     * The DB query finds the row; this method determines why it's invalid.
     */
    public boolean isExpired() {
        return OffsetDateTime.now().isAfter(this.expiresAt);
    }

    // ==========================================================================
    // JPA LIFECYCLE CALLBACK
    // ==========================================================================

    /**
     * Sets createdAt immediately before the INSERT statement.
     * Keeps the in-memory entity consistent after save() —
     * no DB reload required to see the persisted timestamp.
     */
    @PrePersist
    protected void onPersist() {
        this.createdAt = OffsetDateTime.now();
    }
}