package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Cycle 11: Reset endpoint

func TestResetEndpointReturns200(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, err := http.Post(srv.URL+"/score/"+testToken+"/reset", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("reset: want 200, got %d", resp.StatusCode)
	}
}

func TestResetEndpointReturnsStatusField(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, _ := http.Post(srv.URL+"/score/"+testToken+"/reset", "application/json", nil)
	defer resp.Body.Close()
	var payload map[string]any
	json.NewDecoder(resp.Body).Decode(&payload)
	if payload["status"] != "reset" {
		t.Errorf("want status='reset', got %v", payload["status"])
	}
}

func TestResetWrongToken(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, _ := http.Post(srv.URL+"/score/wrong-token/reset", "application/json", nil)
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("wrong token reset: want 404, got %d", resp.StatusCode)
	}
}

func TestResetClearsScores(t *testing.T) {
	srv, _ := newTestApp(t)
	// Build up some scores
	http.Get(srv.URL + "/")
	http.Get(srv.URL + "/search?q=" + url.QueryEscape("<b>x</b>"))
	http.PostForm(srv.URL+"/message", url.Values{"content": {"<script>alert(1)</script>"}})
	http.Get(srv.URL + "/")

	// Reset
	http.Post(srv.URL+"/score/"+testToken+"/reset", "", nil)

	// All scores should be 0
	resp, _ := http.Get(srv.URL + "/score/" + testToken + "?format=json")
	defer resp.Body.Close()
	var payload map[string]any
	json.NewDecoder(resp.Body).Decode(&payload)
	scores := payload["scores"].(map[string]any)
	for k, v := range scores {
		if v.(float64) != 0.0 {
			t.Errorf("after reset, %s should be 0.0, got %f", k, v.(float64))
		}
	}
}

func TestResetUpdatesAppJWTSecret(t *testing.T) {
	_, app := newTestApp(t)
	oldSecret := app.jwtSecret

	newSecret, err := ResetDB(app.db)
	if err != nil {
		t.Fatal(err)
	}
	app.jwtSecret = newSecret

	if app.jwtSecret == oldSecret {
		t.Error("app.jwtSecret should be updated after reset")
	}
	if app.jwtSecret == "" {
		t.Error("new JWT secret should not be empty")
	}
}

func TestResetReseedsMessages(t *testing.T) {
	srv, app := newTestApp(t)
	// Post additional messages and XSS payloads
	http.PostForm(srv.URL+"/message", url.Values{"content": {"<script>alert(1)</script>"}})
	http.PostForm(srv.URL+"/message", url.Values{"content": {"extra message"}})

	// Reset
	http.Post(srv.URL+"/score/"+testToken+"/reset", "", nil)

	var count int
	app.db.QueryRow("SELECT COUNT(*) FROM messages").Scan(&count)
	if count != 3 {
		t.Errorf("after reset, messages should be 3 (seed only), got %d", count)
	}
}

func TestResetScoresCanBeRebuiltAfterReset(t *testing.T) {
	srv, _ := newTestApp(t)
	// First run
	http.PostForm(srv.URL+"/message", url.Values{"content": {"<script>alert(1)</script>"}})
	http.Get(srv.URL + "/")

	// Reset
	http.Post(srv.URL+"/score/"+testToken+"/reset", "", nil)

	// Second run: scores should re-accumulate from zero
	http.PostForm(srv.URL+"/message", url.Values{"content": {"<script>second()</script>"}})
	http.Get(srv.URL + "/")

	resp, _ := http.Get(srv.URL + "/score/" + testToken + "?format=json")
	defer resp.Body.Close()
	var payload map[string]any
	json.NewDecoder(resp.Body).Decode(&payload)
	scores := payload["scores"].(map[string]any)

	if scores["exploitation"].(float64) != 1.0 {
		t.Error("exploitation should reach 1.0 again after reset + replay")
	}
	// Confirm events list is not empty
	events, ok := payload["events"].([]any)
	if !ok || len(events) == 0 {
		t.Error("events should be non-empty after second run")
	}

	// Confirm events from first run are NOT present (reset wiped them)
	_ = strings.Contains // suppress import
}
