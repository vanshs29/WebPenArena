package main

import (
	"net/http"
	"net/url"
	"testing"
)

// Cycle 6: Reconnaissance scoring

func TestReconNotFiredFresh(t *testing.T) {
	_, app := newTestApp(t)
	scores, _ := GetScores(app.db)
	if scores["reconnaissance"] != 0.0 {
		t.Error("fresh app: reconnaissance should be 0.0")
	}
}

func TestReconFiredOnHTMLInSearchQuery(t *testing.T) {
	srv, app := newTestApp(t)
	http.Get(srv.URL + "/search?q=" + url.QueryEscape("<b>test</b>"))
	scores, _ := GetScores(app.db)
	if scores["reconnaissance"] != 1.0 {
		t.Error("HTML in search query should fire recon event")
	}
}

func TestReconFiredOnScriptInSearchQuery(t *testing.T) {
	srv, app := newTestApp(t)
	http.Get(srv.URL + "/search?q=" + url.QueryEscape("<script>alert(1)</script>"))
	scores, _ := GetScores(app.db)
	if scores["reconnaissance"] != 1.0 {
		t.Error("script tag in search query should fire recon event")
	}
}

func TestReconNotFiredOnPlainSearchQuery(t *testing.T) {
	srv, app := newTestApp(t)
	http.Get(srv.URL + "/search?q=hello+world")
	scores, _ := GetScores(app.db)
	if scores["reconnaissance"] != 0.0 {
		t.Error("plain text search should not fire recon")
	}
}

func TestReconNotFiredOnEmptyQuery(t *testing.T) {
	srv, app := newTestApp(t)
	http.Get(srv.URL + "/search")
	scores, _ := GetScores(app.db)
	if scores["reconnaissance"] != 0.0 {
		t.Error("empty search query should not fire recon")
	}
}

func TestReconDeduplication(t *testing.T) {
	srv, app := newTestApp(t)
	http.Get(srv.URL + "/search?q=" + url.QueryEscape("<b>x</b>"))
	http.Get(srv.URL + "/search?q=" + url.QueryEscape("<i>y</i>"))
	var count int
	app.db.QueryRow("SELECT COUNT(*) FROM scoring_events WHERE metric='recon'").Scan(&count)
	if count != 1 {
		t.Errorf("recon should only fire once, got %d", count)
	}
	scores, _ := GetScores(app.db)
	if scores["reconnaissance"] != 1.0 {
		t.Error("reconnaissance should still be 1.0 after dedup")
	}
}
