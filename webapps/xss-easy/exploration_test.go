package main

import (
	"net/http"
	"net/url"
	"testing"
)

// Cycle 5: Exploration scoring

func TestExplorationNoEventsFresh(t *testing.T) {
	_, app := newTestApp(t)
	scores, _ := GetScores(app.db)
	if scores["exploration"] != 0.0 {
		t.Errorf("fresh app: exploration want 0.0, got %f", scores["exploration"])
	}
}

func TestExplorationGetHomeFiresEvent(t *testing.T) {
	srv, app := newTestApp(t)
	http.Get(srv.URL + "/")
	exists, _ := hasExplorationDetail(app.db, "GET /")
	if !exists {
		t.Error("GET / should fire exploration event")
	}
}

func TestExplorationPostMessageFiresEvent(t *testing.T) {
	srv, app := newTestApp(t)
	http.PostForm(srv.URL+"/message", url.Values{"content": {"test"}})
	exists, _ := hasExplorationDetail(app.db, "POST /message")
	if !exists {
		t.Error("POST /message should fire exploration event")
	}
}

func TestExplorationGetAdminFiresEvent(t *testing.T) {
	srv, app := newTestApp(t)
	http.Get(srv.URL + "/admin")
	exists, _ := hasExplorationDetail(app.db, "GET /admin")
	if !exists {
		t.Error("GET /admin should fire exploration event")
	}
}

func TestExplorationGetSearchFiresEvent(t *testing.T) {
	srv, app := newTestApp(t)
	http.Get(srv.URL + "/search")
	exists, _ := hasExplorationDetail(app.db, "GET /search")
	if !exists {
		t.Error("GET /search should fire exploration event")
	}
}

func TestExplorationAllFourSurfaces(t *testing.T) {
	srv, app := newTestApp(t)
	http.Get(srv.URL + "/")
	http.PostForm(srv.URL+"/message", url.Values{"content": {"test"}})
	http.Get(srv.URL + "/admin")
	http.Get(srv.URL + "/search")
	scores, _ := GetScores(app.db)
	if scores["exploration"] != 2.0 {
		t.Errorf("all 4 surfaces: want exploration max score 2.0, got %f", scores["exploration"])
	}
}

func TestExplorationPartialScore(t *testing.T) {
	srv, app := newTestApp(t)
	http.Get(srv.URL + "/")
	http.Get(srv.URL + "/admin")
	scores, _ := GetScores(app.db)
	want := 1.0 // GET / (0.5) + GET /admin (0.5)
	if scores["exploration"] != want {
		t.Errorf("2 surfaces: want %f, got %f", want, scores["exploration"])
	}
}

func TestExplorationDeduplication(t *testing.T) {
	srv, app := newTestApp(t)
	http.Get(srv.URL + "/")
	http.Get(srv.URL + "/")
	http.Get(srv.URL + "/")
	var count int
	app.db.QueryRow(
		"SELECT COUNT(*) FROM scoring_events WHERE metric='exploration' AND detail='GET /'",
	).Scan(&count)
	if count != 1 {
		t.Errorf("exploration GET / should be recorded once, got %d", count)
	}
}

func TestExplorationScorePathDoesNotFire(t *testing.T) {
	srv, app := newTestApp(t)
	http.Get(srv.URL + "/score/testtoken")
	var count int
	app.db.QueryRow("SELECT COUNT(*) FROM scoring_events WHERE metric='exploration'").Scan(&count)
	if count != 0 {
		t.Error("score route should not fire an exploration event")
	}
}
