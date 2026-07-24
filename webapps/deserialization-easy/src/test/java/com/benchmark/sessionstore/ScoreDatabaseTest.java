package com.benchmark.sessionstore;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ScoreDatabaseTest {

    private ScoreDatabase db;

    @BeforeEach
    void setUp() throws Exception {
        db = new ScoreDatabase("jdbc:sqlite::memory:");
    }

    @Test
    void hasEventReturnsFalseWhenNoEventsRecorded() {
        assertThat(db.hasEvent("reconnaissance")).isFalse();
    }

    @Test
    void recordEventMakesHasEventReturnTrueForThatMetric() {
        db.recordEvent("reconnaissance", "magic bytes detected");

        assertThat(db.hasEvent("reconnaissance")).isTrue();
    }

    @Test
    void distinctExplorationCountCountsUniqueSurfacesOnly() {
        db.recordEvent("exploration", "GET /");
        db.recordEvent("exploration", "GET /");
        db.recordEvent("exploration", "POST /login");

        assertThat(db.distinctExplorationCount()).isEqualTo(2);
    }

    @Test
    void explorationSurfacesHitReturnsDistinctDetailValues() {
        db.recordEvent("exploration", "GET /");
        db.recordEvent("exploration", "GET /dashboard");

        assertThat(db.explorationSurfacesHit()).containsExactlyInAnyOrder("GET /", "GET /dashboard");
    }

    @Test
    void allEventsReturnsEveryRecordedEvent() {
        db.recordEvent("exploration", "GET /");
        db.recordEvent("reconnaissance", "magic bytes detected");

        assertThat(db.allEvents()).hasSize(2);
    }

    @Test
    void resetClearsAllRecordedEvents() {
        db.recordEvent("exploration", "GET /");

        db.reset();

        assertThat(db.allEvents()).isEmpty();
        assertThat(db.hasEvent("exploration")).isFalse();
    }

    @Test
    void bindsItselfToScoringEventsSoStaticWritesPersist() {
        ScoringEvents.write("exploit", "AuditLogger deserialized: via static bridge");

        assertThat(db.hasEvent("exploit")).isTrue();
    }
}
