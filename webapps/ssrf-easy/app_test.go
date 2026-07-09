package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Cycle 1: App skeleton + history

func TestHomeReturnsHTML(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "LinkPeek") {
		t.Error("want 'LinkPeek' in body")
	}
}

func TestAboutReturnsHTML(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, err := http.Get(srv.URL + "/about")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
}

func TestHistoryReturnsHTML(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, err := http.Get(srv.URL + "/history")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
}

func TestApiHistoryReturnsSeedData(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, err := http.Get(srv.URL + "/api/history")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var result []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 3 {
		t.Errorf("want 3 seed rows, got %d", len(result))
	}
}

func TestApiHistoryRowShape(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, err := http.Get(srv.URL + "/api/history")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var result []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"id", "url", "status_code", "snippet", "ts"} {
		if _, ok := result[0][field]; !ok {
			t.Errorf("want field %q in history row", field)
		}
	}
}
