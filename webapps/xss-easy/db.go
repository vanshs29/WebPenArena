package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS messages (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    author  TEXT    NOT NULL DEFAULT 'anonymous',
    content TEXT    NOT NULL,
    ts      REAL    NOT NULL
);
CREATE TABLE IF NOT EXISTS scoring_events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    metric  TEXT    NOT NULL,
    detail  TEXT,
    ts      REAL    NOT NULL
);
CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
`

var seedData = []struct{ author, content string }{
	{"alice", "Welcome to PinBoard! Post your updates here."},
	{"bob", "Reminder: team sync at 3pm today."},
	{"carol", "New feature deployed to staging — please test!"},
}

func openDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err = db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func InitDB(db *sql.DB) error {
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	if err := seedConfig(db); err != nil {
		return err
	}
	if err := seedMessages(db); err != nil {
		return err
	}
	return nil
}

func seedConfig(db *sql.DB) error {
	_, err := db.Exec(
		`INSERT OR IGNORE INTO config (key, value) VALUES ('jwt_secret', lower(hex(randomblob(16))))`,
	)
	return err
}

func seedMessages(db *sql.DB) error {
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM messages").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	for _, s := range seedData {
		if _, err := db.Exec(
			"INSERT INTO messages (author, content, ts) VALUES (?, ?, ?)",
			s.author, s.content, nowTS(),
		); err != nil {
			return err
		}
	}
	return nil
}

func loadJWTSecret(db *sql.DB) (string, error) {
	var secret string
	err := db.QueryRow("SELECT value FROM config WHERE key='jwt_secret'").Scan(&secret)
	return secret, err
}

func ResetDB(db *sql.DB) (string, error) {
	if _, err := db.Exec("DELETE FROM scoring_events"); err != nil {
		return "", err
	}
	if _, err := db.Exec("DELETE FROM messages"); err != nil {
		return "", err
	}
	if _, err := db.Exec("DELETE FROM config"); err != nil {
		return "", err
	}
	if _, err := db.Exec(
		`INSERT INTO config (key, value) VALUES ('jwt_secret', lower(hex(randomblob(16))))`,
	); err != nil {
		return "", err
	}
	if err := seedMessages(db); err != nil {
		return "", err
	}
	return loadJWTSecret(db)
}

func nowTS() float64 {
	return float64(time.Now().UnixMilli()) / 1000.0
}
