package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

// Cycle 6: Reset endpoint

func TestResetEndpointReturns200(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, err := http.Post(srv.URL+"/score/"+testToken+"/reset", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("want 200, got %d", resp.StatusCode)
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
	srv, app := newTestApp(t)
	app.fetchURL = stubFetch(200, `{"service":"linkpeek-internal","db_password":"Qr8LnVxz9Ktp2Wsd","status":"ok"}`)
	postPreview(t, srv, "http://localhost:5000/internal/status").Body.Close()
	http.Get(srv.URL + "/")

	http.Post(srv.URL+"/score/"+testToken+"/reset", "", nil)

	scores := fetchScores(t, srv)
	for k, v := range scores {
		if v != 0.0 {
			t.Errorf("after reset, %s should be 0.0, got %f", k, v)
		}
	}
}

func TestResetReseedsHistory(t *testing.T) {
	srv, app := newTestApp(t)
	app.fetchURL = stubFetch(200, "ok")
	postPreview(t, srv, "https://example.com").Body.Close()
	postPreview(t, srv, "https://example.org").Body.Close()

	http.Post(srv.URL+"/score/"+testToken+"/reset", "", nil)

	var count int
	app.db.QueryRow("SELECT COUNT(*) FROM history").Scan(&count)
	if count != 3 {
		t.Errorf("after reset, history should be 3 (seed only), got %d", count)
	}
}

func TestResetScoresCanBeRebuiltAfterReset(t *testing.T) {
	srv, app := newTestApp(t)
	app.fetchURL = stubFetch(200, `{"service":"linkpeek-internal","db_password":"Qr8LnVxz9Ktp2Wsd","status":"ok"}`)
	postPreview(t, srv, "http://localhost:5000/internal/status").Body.Close()

	http.Post(srv.URL+"/score/"+testToken+"/reset", "", nil)

	postPreview(t, srv, "http://localhost:5000/internal/status").Body.Close()

	scores := fetchScores(t, srv)
	if scores["exploitation"] != 0.5 {
		t.Error("exploitation should reach 0.5 (max) again after reset + replay")
	}
}
