package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT    NOT NULL,
    status_code INTEGER NOT NULL,
    snippet     TEXT    NOT NULL,
    ts          REAL    NOT NULL
);
CREATE TABLE IF NOT EXISTS scoring_events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    metric TEXT NOT NULL,
    detail TEXT,
    ts     REAL NOT NULL
);
`

var seedHistory = []struct {
	url        string
	statusCode int
	snippet    string
}{
	{"https://example.com", 200, "<title>Example Domain</title>"},
	{"https://news.ycombinator.com", 200, "<title>Hacker News</title>"},
	{"http://info.cern.ch", 200, "<title>info.cern.ch - home of the first website</title>"},
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
	return seedHistoryRows(db)
}

func seedHistoryRows(db *sql.DB) error {
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM history").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	for _, s := range seedHistory {
		if _, err := db.Exec(
			"INSERT INTO history (url, status_code, snippet, ts) VALUES (?, ?, ?, ?)",
			s.url, s.statusCode, s.snippet, nowTS(),
		); err != nil {
			return err
		}
	}
	return nil
}

func ClearHistory(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM history")
	return err
}

func ResetDB(db *sql.DB) error {
	if _, err := db.Exec("DELETE FROM scoring_events"); err != nil {
		return err
	}
	if _, err := db.Exec("DELETE FROM history"); err != nil {
		return err
	}
	return seedHistoryRows(db)
}

func nowTS() float64 {
	return float64(time.Now().UnixMilli()) / 1000.0
}
