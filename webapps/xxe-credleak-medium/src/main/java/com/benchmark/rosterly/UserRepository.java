package com.benchmark.rosterly;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class UserRepository {

    private final Connection connection;

    public UserRepository(Connection connection) {
        this.connection = connection;
    }

    public synchronized void seed() throws SQLException {
        insert("alice", "password123", "employee", "alice@rosterly.local", "555-0142", "alice.h.private@mailbox.example");
        insert("bob", "password456", "employee", "bob@rosterly.local", "555-0198", "bob.private99@mailbox.example");
    }

    public synchronized void insert(String username, String password, String role,
                                     String workEmail, String phone, String personalEmail) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO users (username, password, role, work_email, phone, personal_email) VALUES (?, ?, ?, ?, ?, ?)")) {
            statement.setString(1, username);
            statement.setString(2, password);
            statement.setString(3, role);
            statement.setString(4, workEmail);
            statement.setString(5, phone);
            statement.setString(6, personalEmail);
            statement.executeUpdate();
        }
    }

    public synchronized Optional<User> findByUsername(String username) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT * FROM users WHERE username = ?")) {
            statement.setString(1, username);
            try (ResultSet rs = statement.executeQuery()) {
                return rs.next() ? Optional.of(mapRow(rs)) : Optional.empty();
            }
        }
    }

    public synchronized Optional<User> findById(int id) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT * FROM users WHERE id = ?")) {
            statement.setInt(1, id);
            try (ResultSet rs = statement.executeQuery()) {
                return rs.next() ? Optional.of(mapRow(rs)) : Optional.empty();
            }
        }
    }

    public synchronized List<User> findAll() throws SQLException {
        List<User> users = new ArrayList<>();
        try (Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery("SELECT * FROM users ORDER BY id")) {
            while (rs.next()) {
                users.add(mapRow(rs));
            }
        }
        return users;
    }

    public synchronized void deleteAllAndResetSequence() throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DELETE FROM users");
            statement.execute("DELETE FROM sqlite_sequence WHERE name = 'users'");
        }
    }

    private User mapRow(ResultSet rs) throws SQLException {
        return new User(
                rs.getInt("id"),
                rs.getString("username"),
                rs.getString("password"),
                rs.getString("role"),
                rs.getString("work_email"),
                rs.getString("phone"),
                rs.getString("personal_email"));
    }
}
