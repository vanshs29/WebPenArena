package main

import (
	"strings"
	"testing"
)

// Cycle 4: Vulnerability works as designed — SSRF reaches internal credential

func TestSSRFReachesInternalEndpoint(t *testing.T) {
	srv, app := newTestApp(t)
	app.fetchURL = stubFetch(200, `{"service":"linkpeek-internal","db_password":"Qr8LnVxz9Ktp2Wsd","status":"ok"}`)
	resp := postPreview(t, srv, "http://localhost:5000/internal/status")
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), "Qr8LnVxz9Ktp2Wsd") {
		t.Error("want leaked credential in preview response")
	}
}

func TestDefaultFetchURLPerformsRealHTTPGet(t *testing.T) {
	// defaultFetchURL is exercised against the app's own internal secret
	// endpoint to prove the production fetch path (not the test stub)
	// actually performs a real network request and can reach loopback.
	srv, _ := newTestApp(t)
	result, err := defaultFetchURL(srv.URL + "/internal/status")
	if err != nil {
		t.Fatalf("defaultFetchURL: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("want 200, got %d", result.StatusCode)
	}
	if !strings.Contains(result.Body, "Qr8LnVxz9Ktp2Wsd") {
		t.Error("want leaked credential in fetched body")
	}
}
