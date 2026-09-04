package com.benchmark.rosterly;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

@Configuration
public class AppConfig {

    @Bean
    public Connection connection(@Value("${DB_PATH:rosterly.db}") String dbPath) throws SQLException {
        Connection connection = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
        try (Statement statement = connection.createStatement()) {
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'employee',
                        work_email TEXT NOT NULL,
                        phone TEXT NOT NULL,
                        personal_email TEXT NOT NULL
                    )
                    """);
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS contacts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        owner_id INTEGER NOT NULL,
                        name TEXT NOT NULL,
                        email TEXT,
                        imported_at REAL NOT NULL
                    )
                    """);
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS scoring_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        metric TEXT NOT NULL,
                        detail TEXT,
                        ts REAL NOT NULL
                    )
                    """);
        }
        return connection;
    }

    @Bean
    public UserRepository userRepository(Connection connection) throws SQLException {
        UserRepository repository = new UserRepository(connection);
        repository.seed();
        return repository;
    }

    @Bean
    public ContactRepository contactRepository(Connection connection) {
        return new ContactRepository(connection);
    }

    @Bean
    public ScoreDatabase scoreDatabase(Connection connection) {
        return new ScoreDatabase(connection);
    }
}
