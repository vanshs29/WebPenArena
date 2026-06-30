package main

import (
	"testing"
)

// Cycle 1: DB + App Factory

func TestInitDBCreatesSchema(t *testing.T) {
	_, app := newTestApp(t)
	// All three tables must exist; querying them should not error
	tables := []string{"messages", "scoring_events", "config"}
	for _, tbl := range tables {
		var n int
		if err := app.db.QueryRow("SELECT COUNT(*) FROM " + tbl).Scan(&n); err != nil {
			t.Errorf("table %s not accessible: %v", tbl, err)
		}
	}
}

func TestSeedDataPresent(t *testing.T) {
	_, app := newTestApp(t)
	var count int
	if err := app.db.QueryRow("SELECT COUNT(*) FROM messages").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Errorf("expected 3 seed messages, got %d", count)
	}
}

func TestSeedDataAuthors(t *testing.T) {
	_, app := newTestApp(t)
	rows, err := app.db.Query("SELECT author FROM messages ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var authors []string
	for rows.Next() {
		var a string
		rows.Scan(&a)
		authors = append(authors, a)
	}
	want := []string{"alice", "bob", "carol"}
	for i, w := range want {
		if i >= len(authors) || authors[i] != w {
			t.Errorf("author[%d]: want %q, got %q", i, w, authors[i])
		}
	}
}

func TestInitDBIdempotent(t *testing.T) {
	_, app := newTestApp(t)
	// Running InitDB again must not duplicate seed messages
	if err := InitDB(app.db); err != nil {
		t.Fatal(err)
	}
	var count int
	app.db.QueryRow("SELECT COUNT(*) FROM messages").Scan(&count)
	if count != 3 {
		t.Errorf("expected 3 after double init, got %d", count)
	}
}

func TestJWTSecretLoaded(t *testing.T) {
	_, app := newTestApp(t)
	if app.jwtSecret == "" {
		t.Error("jwtSecret should be non-empty after init")
	}
}

func TestResetDBClearsEvents(t *testing.T) {
	_, app := newTestApp(t)
	_ = WriteEvent(app.db, "exploration", "GET /")
	_ = WriteEvent(app.db, "recon", "test recon")
	if _, err := ResetDB(app.db); err != nil {
		t.Fatal(err)
	}
	var count int
	app.db.QueryRow("SELECT COUNT(*) FROM scoring_events").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 events after reset, got %d", count)
	}
}

func TestResetDBReseeds(t *testing.T) {
	_, app := newTestApp(t)
	// Insert extra message then reset
	app.db.Exec("INSERT INTO messages (author, content, ts) VALUES ('hacker','<script>alert(1)</script>',1.0)")
	if _, err := ResetDB(app.db); err != nil {
		t.Fatal(err)
	}
	var count int
	app.db.QueryRow("SELECT COUNT(*) FROM messages").Scan(&count)
	if count != 3 {
		t.Errorf("expected 3 seed messages after reset, got %d", count)
	}
}

func TestResetDBRotatesJWTSecret(t *testing.T) {
	_, app := newTestApp(t)
	oldSecret := app.jwtSecret
	newSecret, err := ResetDB(app.db)
	if err != nil {
		t.Fatal(err)
	}
	if newSecret == oldSecret {
		t.Error("JWT secret should change after reset")
	}
	if newSecret == "" {
		t.Error("new JWT secret should be non-empty")
	}
}
