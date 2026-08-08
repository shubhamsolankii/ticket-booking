package com.ticketbooking.auth.util;

import com.github.f4b6a3.ulid.UlidCreator;
import org.springframework.stereotype.Component;

/**
 * Spring-managed ULID generator.
 *
 * Wraps UlidCreator rather than calling it directly in service methods.
 *
 * Why a @Component instead of a static utility:
 * Service classes that call UlidCreator.getMonotonicUlid() directly
 * cannot have their ID generation mocked in unit tests. A @Component
 * injected via constructor can be replaced with a mock that returns
 * a fixed, assertable ULID — making unit tests deterministic.
 *
 * Why getMonotonicUlid() over getUlid():
 * Standard ULID (getUlid) has millisecond precision on the timestamp
 * component. Within the same millisecond, two ULIDs are random relative
 * to each other — not monotonically increasing.
 * Monotonic ULID (getMonotonicUlid) increments a random suffix when
 * two ULIDs are generated within the same millisecond, guaranteeing
 * strict monotonic ordering within that millisecond window.
 * Result: even at 100K RPS (100 IDs per millisecond), all IDs are
 * strictly ordered — B-tree inserts are always sequential, never random.
 * Zero page splits. Zero index fragmentation. Optimal write throughput.
 *
 * Thread safety: UlidCreator.getMonotonicUlid() is thread-safe.
 * Multiple service instances calling generate() concurrently is safe.
 */
@Component
public class UlidGenerator {

    /**
     * Generates a new monotonically increasing ULID.
     *
     * @return 26-character ULID string, e.g. "01HX7MWKP0000000000000000"
     *         Always 26 characters. Always URL-safe. Always lexicographically
     *         sortable by generation time.
     *         Store as CHAR(26) in PostgreSQL — never as UUID type.
     */
    public String generate() {
        return UlidCreator.getMonotonicUlid().toString();
    }
}