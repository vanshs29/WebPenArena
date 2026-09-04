package com.benchmark.rosterly;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class ContactRepository {

    private final Connection connection;

    public ContactRepository(Connection connection) {
        this.connection = connection;
    }

    public synchronized void insert(int ownerId, String name, String email) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO contacts (owner_id, name, email, imported_at) VALUES (?, ?, ?, ?)")) {
            statement.setInt(1, ownerId);
            statement.setString(2, name);
            statement.setString(3, email);
            statement.setDouble(4, System.currentTimeMillis() / 1000.0);
            statement.executeUpdate();
        }
    }

    public synchronized List<Contact> findByOwner(int ownerId) throws SQLException {
        List<Contact> contacts = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT * FROM contacts WHERE owner_id = ? ORDER BY id")) {
            statement.setInt(1, ownerId);
            try (ResultSet rs = statement.executeQuery()) {
                while (rs.next()) {
                    contacts.add(new Contact(
                            rs.getInt("id"),
                            rs.getInt("owner_id"),
                            rs.getString("name"),
                            rs.getString("email")));
                }
            }
        }
        return contacts;
    }

    public synchronized void deleteAll() throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DELETE FROM contacts");
        }
    }
}
