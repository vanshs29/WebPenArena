package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Cycle 3: Preview route (fetchURL stubbed)

func TestPreviewReturnsContent(t *testing.T) {
	srv, app := newTestApp(t)
	app.fetchURL = stubFetch(200, "<title>Example</title>")
	resp := postPreview(t, srv, "https://example.com")
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
}

func TestPreviewResponseShape(t *testing.T) {
	srv, app := newTestApp(t)
	app.fetchURL = stubFetch(200, "<title>Example</title>")
	resp := postPreview(t, srv, "https://example.com")
	defer resp.Body.Close()
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"status_code", "snippet"} {
		if _, ok := payload[field]; !ok {
			t.Errorf("want field %q in preview response", field)
		}
	}
}

func TestPreviewRejectsMissingURL(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, err := http.Post(srv.URL+"/preview", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("want 400, got %d", resp.StatusCode)
	}
}

func TestPreviewRejectsInvalidJSON(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, err := http.Post(srv.URL+"/preview", "application/json", strings.NewReader(`not json`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("want 400, got %d", resp.StatusCode)
	}
}

func TestPreviewHandlesFetchError(t *testing.T) {
	srv, app := newTestApp(t)
	app.fetchURL = stubFetchError()
	resp := postPreview(t, srv, "https://unreachable.example")
	defer resp.Body.Close()
	if resp.StatusCode != 502 {
		t.Errorf("want 502, got %d", resp.StatusCode)
	}
}

func TestPreviewAddsRowToHistory(t *testing.T) {
	srv, app := newTestApp(t)
	app.fetchURL = stubFetch(200, "<title>Example</title>")
	postPreview(t, srv, "https://example.com").Body.Close()

	resp, _ := http.Get(srv.URL + "/api/history")
	defer resp.Body.Close()
	var result []map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if len(result) != 4 {
		t.Errorf("want 4 history rows (3 seed + 1 new), got %d", len(result))
	}
}
