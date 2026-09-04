package com.benchmark.rosterly;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class ScoreDatabase implements ScoreEventRecorder {

    private final Connection connection;

    public ScoreDatabase(Connection connection) {
        this.connection = connection;
    }

    @Override
    public synchronized void record(String metric, String detail) {
        recordEvent(metric, detail);
    }

    public synchronized void recordEvent(String metric, String detail) {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO scoring_events (metric, detail, ts) VALUES (?, ?, ?)")) {
            statement.setString(1, metric);
            statement.setString(2, detail);
            statement.setDouble(3, System.currentTimeMillis() / 1000.0);
            statement.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to record scoring event", e);
        }
    }

    public synchronized boolean hasEvent(String metric) {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT COUNT(*) FROM scoring_events WHERE metric = ?")) {
            statement.setString(1, metric);
            try (ResultSet rs = statement.executeQuery()) {
                rs.next();
                return rs.getInt(1) > 0;
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to query scoring event", e);
        }
    }

    public synchronized Set<String> explorationSurfacesHit() {
        Set<String> surfaces = new LinkedHashSet<>();
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT DISTINCT detail FROM scoring_events WHERE metric = 'exploration'");
             ResultSet rs = statement.executeQuery()) {
            while (rs.next()) {
                surfaces.add(rs.getString(1));
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to read exploration surfaces", e);
        }
        return surfaces;
    }

    public synchronized Set<String> distinctMetrics() {
        Set<String> metrics = new LinkedHashSet<>();
        try (Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery("SELECT DISTINCT metric FROM scoring_events")) {
            while (rs.next()) {
                metrics.add(rs.getString(1));
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to read distinct metrics", e);
        }
        return metrics;
    }

    public synchronized List<ScoringEvent> allEvents() {
        List<ScoringEvent> events = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT metric, detail, ts FROM scoring_events ORDER BY id");
             ResultSet rs = statement.executeQuery()) {
            while (rs.next()) {
                events.add(new ScoringEvent(rs.getString("metric"), rs.getString("detail"), rs.getDouble("ts")));
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to read scoring events", e);
        }
        return events;
    }

    public synchronized void reset() {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DELETE FROM scoring_events");
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to reset scoring events", e);
        }
    }
}
