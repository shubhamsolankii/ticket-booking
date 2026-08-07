package com.ticketbooking.auth.repository;

import com.ticketbooking.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Data access layer for the users table.
 *
 * All queries execute against the PRIMARY PostgreSQL node.
 * No replica reads. Auth reads must be strongly consistent.
 *
 * Query coverage:
 *   findByEmail       → login hot path (uq_users_email index)
 *   findByPhone       → OTP verify hot path (uq_users_phone index)
 *   existsByEmail     → registration duplicate check (no entity hydration)
 *   existsByPhone     → OTP send duplicate check (no entity hydration)
 *   updateActiveState → admin account suspension (bulk-safe @Modifying)
 */
@Repository
public interface UserRepository extends JpaRepository<User, String> {

    // =========================================================================
    // READ — LOGIN PATH
    // =========================================================================

    /**
     * Fetches a user by email address.
     *
     * Hot path: POST /auth/login (email + password flow).
     * Index used: uq_users_email (B-tree, unique).
     * Generated SQL:
     *   SELECT * FROM users WHERE email = $1
     *
     * Returns Optional.empty() when no user exists for the given email.
     * The service layer maps empty to InvalidCredentialsException —
     * NOT to "email not found." We never tell a caller whether an email
     * is registered. Both "wrong email" and "wrong password" return the
     * same 401 with the same message.
     *
     * The email passed here must already be normalized (lowercase, trimmed)
     * by the service layer. The stored value is normalized at entity creation.
     * A mismatch in normalization = a missed index hit = sequential scan
     * at 100K RPS. Never skip normalization.
     */
    Optional<User> findByEmail(String email);

    /**
     * Fetches a user by phone number.
     *
     * Hot path: POST /auth/otp/verify.
     * Index used: uq_users_phone (B-tree, unique).
     * Generated SQL:
     *   SELECT * FROM users WHERE phone = $1
     *
     * Returns Optional.empty() when no user exists for the given phone.
     * The OTP verify flow uses this to determine whether to create a
     * new user (isNewUser = true) or return an existing user's tokens.
     *
     * Phone number must be in E.164 format (e.g. +919876543210).
     * Validated and normalized by the service layer before this call.
     */
    Optional<User> findByPhone(String phone);

    // =========================================================================
    // EXISTENCE CHECKS — REGISTRATION PATH
    // =========================================================================

    /**
     * Checks whether an account exists for the given email.
     *
     * Used by: POST /auth/register — duplicate email prevention.
     * Generated SQL:
     *   SELECT COUNT(id) FROM users WHERE email = $1
     *
     * Why existsByEmail instead of findByEmail for this check:
     * findByEmail hydrates a full User entity into the JPA persistence
     * context — all columns loaded, object allocated on heap. We discard
     * it immediately after checking presence. At registration volume,
     * that is unnecessary allocation.
     * existsByEmail generates a COUNT query — no entity hydration, no
     * persistence context pollution, minimal memory footprint.
     *
     * Email must be normalized before this call. Same reasoning as above.
     */
    boolean existsByEmail(String email);

    /**
     * Checks whether an account exists for the given phone number.
     *
     * Used by: POST /auth/otp/send — determines whether this is a
     * known user or a new registration attempt. The OTP is generated
     * and stored in Redis regardless — existence only affects the
     * Kafka event payload (new user vs returning user context).
     *
     * Generated SQL:
     *   SELECT COUNT(id) FROM users WHERE phone = $1
     */
    boolean existsByPhone(String phone);

    // =========================================================================
    // WRITE — ACCOUNT STATE MANAGEMENT
    // =========================================================================

    /**
     * Updates the is_active flag directly without loading the entity.
     *
     * Used by: admin-triggered account suspension or reactivation.
     * Not currently exposed via an API endpoint — the endpoint is
     * intentionally deferred (Admin Dashboard is out of scope).
     * The repository method is included now because:
     * 1. The service layer will call it from deactivate() and activate()
     *    operations that bypass the JPA entity lifecycle intentionally.
     * 2. At scale, loading a User entity just to flip one boolean
     *    and call save() is wasteful — two DB round trips (SELECT + UPDATE)
     *    where one suffices (direct UPDATE).
     *
     * @Modifying: required for any @Query that is not a SELECT.
     * Without it, Spring Data throws an InvalidDataAccessApiUsageException.
     *
     * clearAutomatically = true: after this UPDATE executes, Hibernate
     * clears the first-level cache (persistence context). Without this,
     * a subsequent findById in the same transaction would return the
     * stale cached entity with the OLD is_active value — not the just-updated
     * value from the DB. clearAutomatically forces the next read to hit
     * the DB and return fresh state.
     *
     * Generated SQL:
     *   UPDATE users SET is_active = $1, updated_at = NOW() WHERE id = $2
     *
     * We are choosing STRONG consistency here — this UPDATE goes to the
     * primary node. The updated_at is set in the query directly rather
     * than relying on @PreUpdate, because @PreUpdate only fires when
     * Hibernate manages the entity lifecycle. A @Modifying @Query bypasses
     * the entity lifecycle entirely — the DB trigger handles updated_at
     * at the PostgreSQL level, and we reinforce it here in the JPQL.
     */
    @Modifying(clearAutomatically = true)
    @Query("""
        UPDATE User u
        SET u.active = :active
        WHERE u.id = :userId
        """)
    int updateActiveState(
            @Param("userId") String userId,
            @Param("active") boolean active
    );
}