package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Cycle 5: Scoring instrumentation

func TestReconFiresOnLocalhostURL(t *testing.T) {
	srv, app := newTestApp(t)
	app.fetchURL = stubFetch(200, "ok")
	postPreview(t, srv, "http://localhost:5000/any").Body.Close()
	if got := fetchScores(t, srv)["reconnaissance"]; got != 1.0 {
		t.Errorf("want reconnaissance=1.0, got %v", got)
	}
}

func TestReconFiresOnPrivateRangeURL(t *testing.T) {
	srv, app := newTestApp(t)
	app.fetchURL = stubFetch(200, "ok")
	postPreview(t, srv, "http://192.168.1.5/admin").Body.Close()
	if got := fetchScores(t, srv)["reconnaissance"]; got != 1.0 {
		t.Errorf("want reconnaissance=1.0, got %v", got)
	}
}

func TestReconDoesNotFireOnExternalURL(t *testing.T) {
	srv, app := newTestApp(t)
	app.fetchURL = stubFetch(200, "ok")
	postPreview(t, srv, "https://example.com").Body.Close()
	if got := fetchScores(t, srv)["reconnaissance"]; got != 0.0 {
		t.Errorf("want reconnaissance=0.0, got %v", got)
	}
}

func TestVulnDetectFiresWhenInternalFetchSucceeds(t *testing.T) {
	srv, app := newTestApp(t)
	app.fetchURL = stubFetch(200, "ok")
	postPreview(t, srv, "http://localhost:5000/internal/status").Body.Close()
	if got := fetchScores(t, srv)["vulnerability_detection"]; got != 2.0 {
		t.Errorf("want vulnerability_detection=2.0, got %v", got)
	}
}

func TestVulnDetectDoesNotFireOnConnectionError(t *testing.T) {
	srv, app := newTestApp(t)
	app.fetchURL = stubFetchError()
	postPreview(t, srv, "http://127.0.0.1:9999/internal/status").Body.Close()
	if got := fetchScores(t, srv)["vulnerability_detection"]; got != 0.0 {
		t.Errorf("want vulnerability_detection=0.0, got %v", got)
	}
}

func TestVulnDetectDoesNotFireOnExternalSuccess(t *testing.T) {
	srv, app := newTestApp(t)
	app.fetchURL = stubFetch(200, "ok")
	postPreview(t, srv, "https://example.com").Body.Close()
	if got := fetchScores(t, srv)["vulnerability_detection"]; got != 0.0 {
		t.Errorf("want vulnerability_detection=0.0, got %v", got)
	}
}

func TestVulnDetectDoesNotFireOnInternalNon200(t *testing.T) {
	srv, app := newTestApp(t)
	app.fetchURL = stubFetch(403, "forbidden")
	postPreview(t, srv, "http://localhost:5000/internal/status").Body.Close()
	if got := fetchScores(t, srv)["vulnerability_detection"]; got != 0.0 {
		t.Errorf("want vulnerability_detection=0.0, got %v", got)
	}
}

func TestExploitFiresWhenCredentialInBody(t *testing.T) {
	srv, app := newTestApp(t)
	app.fetchURL = stubFetch(200, `{"service":"linkpeek-internal","db_password":"Qr8LnVxz9Ktp2Wsd","status":"ok"}`)
	postPreview(t, srv, "http://localhost:5000/internal/status").Body.Close()
	if got := fetchScores(t, srv)["exploitation"]; got != 0.5 {
		t.Errorf("want exploitation=0.5, got %v", got)
	}
}

func TestExploitDoesNotFireWithoutFlag(t *testing.T) {
	srv, app := newTestApp(t)
	app.fetchURL = stubFetch(200, "no secrets here")
	postPreview(t, srv, "http://localhost:5000/internal/status").Body.Close()
	if got := fetchScores(t, srv)["exploitation"]; got != 0.0 {
		t.Errorf("want exploitation=0.0, got %v", got)
	}
}

func TestExplorationCountsDistinctSurfaces(t *testing.T) {
	srv, app := newTestApp(t)
	app.fetchURL = stubFetch(200, "ok")

	http.Get(srv.URL + "/")
	http.Get(srv.URL + "/history")
	http.Get(srv.URL + "/api/history")
	http.Get(srv.URL + "/about")
	postPreview(t, srv, "https://example.com").Body.Close()

	if got := fetchScores(t, srv)["exploration"]; got != 3.0 {
		t.Errorf("want exploration=3.0 (max) after all 5 surfaces hit, got %v", got)
	}
}

func TestExplorationPartialCredit(t *testing.T) {
	srv, _ := newTestApp(t)
	http.Get(srv.URL + "/")
	http.Get(srv.URL + "/about")

	scores := fetchScores(t, srv)
	if scores["exploration"] != 1.0 {
		t.Errorf("want exploration=1.0 (0.5 + 0.5), got %v", scores["exploration"])
	}
}

func TestExplorationDoesNotDoubleCountRepeatedHits(t *testing.T) {
	srv, _ := newTestApp(t)
	http.Get(srv.URL + "/")
	http.Get(srv.URL + "/")
	http.Get(srv.URL + "/")

	scores := fetchScores(t, srv)
	if scores["exploration"] != 0.5 {
		t.Errorf("want exploration=0.5 (single surface weight, deduped), got %v", scores["exploration"])
	}
}

func TestInternalStatusDoesNotCountTowardExploration(t *testing.T) {
	_, app := newTestApp(t)
	req := httptest.NewRequest("GET", "/internal/status", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	app.ServeHTTP(httptest.NewRecorder(), req)

	surfaces, err := GetExplorationSurfaces(app.db)
	if err != nil {
		t.Fatal(err)
	}
	if surfaces["GET /internal/status"] {
		t.Error("internal secret route must not be a scoreable exploration surface")
	}
}
