package com.ticketbooking.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.OffsetDateTime;

/**
 * Owns identity and credential state for the Auth Service.
 *
 * Does NOT own:
 *   - User profile data (name, preferences) → User Service
 *   - OTP state                              → Redis (TTL-managed, no table)
 *   - Booking history references             → Booking Orchestration Service
 *
 * Instantiation: factory methods only. No public constructor. No Lombok @Builder.
 * Mutation: domain methods only. No public setters.
 */
@Entity
@Table(
        name = "users",
        uniqueConstraints = {
                // Names match exactly the constraint names in V1__create_users_table.sql.
                // Hibernate ddl-auto=validate checks these on startup.
                // Any divergence between entity and Flyway migration = startup failure.
                @UniqueConstraint(name = "uq_users_email", columnNames = "email"),
                @UniqueConstraint(name = "uq_users_phone", columnNames = "phone")
        }
)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
// PROTECTED, not PRIVATE: JPA spec requires a no-arg constructor accessible
// to the persistence provider (Hibernate uses reflection to instantiate entities
// when loading from DB). Private breaks some JPA providers. Protected is the
// correct minimum access level for JPA entities.
public class User {

    @Id
    @Column(name = "id", length = 26, nullable = false, updatable = false)
    // CHAR(26) in SQL. length = 26 tells Hibernate to map to CHAR-like semantics.
    // updatable = false: once set, this column is excluded from all UPDATE
    // statements Hibernate generates. Primary keys must never change.
    // No @GeneratedValue — ULID is generated in the service layer before insert.
    private String id;

    @Column(name = "email", length = 255, updatable = false)
    // Nullable at DB level (phone-only users have no email).
    // updatable = false: email is an immutable identity credential in our system.
    // Changing email requires a full re-verification flow — that's a future
    // Flyway migration + new endpoint, not a field update on this entity.
    // Stored and compared as lowercase (normalized in factory methods).
    private String email;

    @Column(name = "phone", length = 20, updatable = false)
    // Nullable at DB level (email/password users may have no phone initially).
    // updatable = false: phone number changes are not in our current API contract.
    // When that endpoint is added, we remove this flag via a deliberate decision,
    // not by accident.
    private String phone;

    @Column(name = "password_hash", length = 60)
    // Nullable: OTP-only and OAuth2 users have no password.
    // Length 60: BCrypt output with $2a$12$ prefix is always exactly 60 chars.
    // No updatable = false: password reset updates this column.
    // No @Setter from Lombok — mutated only via changePassword() domain method.
    private String passwordHash;

    @Column(name = "email_verified", nullable = false)
    // Not nullable. Default set in factory methods, not as @Column(columnDefinition).
    // We manage defaults in the application layer, not via DDL defaults in JPA.
    // Flyway migration has DEFAULT FALSE at the DB level as a safety net.
    // Domain method verifyEmail() is the only mutation path — enforces
    // the invariant that this value only moves false → true, never backward.
    private boolean emailVerified;

    @Column(name = "is_active", nullable = false)
    // Controlled by deactivate() and activate() domain methods.
    // No @Setter: callers cannot arbitrarily toggle active state.
    private boolean active;

    @Column(name = "created_at", nullable = false, updatable = false)
    // OffsetDateTime maps to TIMESTAMPTZ in PostgreSQL.
    // Never use LocalDateTime — it is timezone-naive. In a distributed system
    // where service instances may run in different JVM timezones, LocalDateTime
    // silently corrupts timestamps. OffsetDateTime carries the UTC offset
    // and maps to TIMESTAMPTZ correctly via the PostgreSQL JDBC driver.
    // updatable = false: creation timestamp never changes.
    // Set in @PrePersist — NOT via DB DEFAULT NOW(). The DB default is a
    // safety net only. We set it in JPA so the in-memory entity reflects
    // the correct value immediately after save() — without needing a reload.
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    // Set in both @PrePersist and @PreUpdate.
    // The DB trigger (trg_users_updated_at) also updates this column — that
    // handles updates that bypass JPA (admin scripts, Flyway data migrations).
    // Both are needed: JPA callback keeps the in-memory entity consistent,
    // DB trigger catches everything else.
    private OffsetDateTime updatedAt;

    // ==========================================================================
    // FACTORY METHODS
    // The ONLY way to create User instances. Three creation paths exist —
    // one for each entry point in the registration flow.
    // ==========================================================================

    /**
     * Creates a user who registered with email + password.
     * emailVerified starts false — must complete email verification before login.
     *
     * @param id           ULID generated in the service layer before this call
     * @param email        Raw email from request — normalized to lowercase here
     * @param passwordHash BCrypt hash already computed by the service layer
     */
    public static User createEmailPasswordUser(
            String id,
            String email,
            String passwordHash
    ) {
        User user = new User();
        user.id = id;
        user.email = email.toLowerCase().trim();
        // Normalize here, in the entity constructor, so normalization
        // is guaranteed regardless of which service method calls this factory.
        // Belt-and-suspenders: service layer also normalizes before calling.
        user.passwordHash = passwordHash;
        user.emailVerified = false;
        user.active = true;
        return user;
    }

    /**
     * Creates a user who registered via OTP (phone number only).
     * emailVerified is set true — there is no email to verify.
     * The boolean name is a slight misnomer for phone users, but the semantic
     * intent is: "has this user completed identity verification?" → yes.
     *
     * @param id    ULID generated in the service layer
     * @param phone E.164 format phone number, already validated by service layer
     */
    public static User createPhoneUser(String id, String phone) {
        User user = new User();
        user.id = id;
        user.phone = phone;
        user.emailVerified = true;
        user.active = true;
        return user;
    }

    /**
     * Creates a user who authenticated via OAuth2 (Google/GitHub through Keycloak).
     * emailVerified is set true — the OAuth2 provider has already verified the email.
     * No password — OAuth2 users authenticate exclusively through the provider.
     *
     * @param id    ULID generated in the service layer
     * @param email Email from OAuth2 provider — normalized to lowercase here
     */
    public static User createOAuth2User(String id, String email) {
        User user = new User();
        user.id = id;
        user.email = email.toLowerCase().trim();
        user.emailVerified = true;
        user.active = true;
        return user;
    }

    // ==========================================================================
    // DOMAIN METHODS
    // Named after the business operation, not the field being changed.
    // Each enforces its own invariants.
    // ==========================================================================

    /**
     * Marks this user's email as verified. Called by AuthService after
     * the verification token is validated and deleted in the same transaction.
     *
     * One-way transition: false → true. There is no unverifyEmail() because
     * no business operation in our system requires it.
     */
    public void verifyEmail() {
        this.emailVerified = true;
    }

    /**
     * Replaces the stored password hash. Called by AuthService after:
     * 1. The password reset token is validated
     * 2. The new password passes strength rules
     * 3. BCrypt hash is computed
     * 4. All refresh tokens for this user are queued for deletion
     *
     * This method only sets the hash — the surrounding transaction in
     * AuthService handles token deletion and session revocation.
     *
     * @param newPasswordHash BCrypt hash of the new password, cost=12
     */
    public void changePassword(String newPasswordHash) {
        this.passwordHash = newPasswordHash;
    }

    /**
     * Deactivates the account. All login paths return 403 for inactive users.
     * Refresh tokens are NOT automatically revoked here — service layer handles
     * that if required by the operation (e.g., admin-initiated suspension).
     */
    public void deactivate() {
        this.active = false;
    }

    /**
     * Reactivates a previously deactivated account.
     */
    public void activate() {
        this.active = true;
    }

    // ==========================================================================
    // JPA LIFECYCLE CALLBACKS
    // ==========================================================================

    /**
     * Fires immediately before Hibernate executes the INSERT statement.
     * Sets both timestamps on the in-memory entity so the caller has
     * the correct values after save() returns — without a DB round-trip.
     *
     * OffsetDateTime.now() uses the JVM default zone. In production (Docker/K8s),
     * always set JVM timezone to UTC via -Duser.timezone=UTC or TZ=UTC env var.
     * We enforce this in the Dockerfile in the Dockerize phase.
     */
    @PrePersist
    protected void onPersist() {
        OffsetDateTime now = OffsetDateTime.now();
        this.createdAt = now;
        this.updatedAt = now;
    }

    /**
     * Fires immediately before Hibernate executes any UPDATE statement
     * for this entity. The DB trigger (trg_users_updated_at) is a parallel
     * safety net — this callback keeps the in-memory entity consistent.
     *
     * If only the DB trigger existed and no @PreUpdate, the caller would
     * see a stale updatedAt on the entity object until the next reload.
     * At 100K RPS, unnecessary reloads are expensive.
     */
    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = OffsetDateTime.now();
    }
}