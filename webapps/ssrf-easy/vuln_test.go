package main

import (
	"strings"
	"testing"
)

// Cycle 4: Vulnerability works as designed — SSRF reaches internal flag

func TestSSRFReachesInternalEndpoint(t *testing.T) {
	srv, app := newTestApp(t)
	app.fetchURL = stubFetch(200, `{"flag":"FLAG{ssrf_linkpeek_easy}"}`)
	resp := postPreview(t, srv, "http://localhost:5000/internal/secret")
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), "FLAG{ssrf_linkpeek_easy}") {
		t.Error("want flag in preview response")
	}
}

func TestDefaultFetchURLPerformsRealHTTPGet(t *testing.T) {
	// defaultFetchURL is exercised against the app's own internal secret
	// endpoint to prove the production fetch path (not the test stub)
	// actually performs a real network request and can reach loopback.
	srv, _ := newTestApp(t)
	result, err := defaultFetchURL(srv.URL + "/internal/secret")
	if err != nil {
		t.Fatalf("defaultFetchURL: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("want 200, got %d", result.StatusCode)
	}
	if !strings.Contains(result.Body, "FLAG{ssrf_linkpeek_easy}") {
		t.Error("want flag in fetched body")
	}
}
