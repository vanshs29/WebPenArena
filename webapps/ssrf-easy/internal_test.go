package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// Cycle 2: Internal secret endpoint

func TestInternalStatusBlocksExternal(t *testing.T) {
	_, app := newTestApp(t)
	req := httptest.NewRequest("GET", "/internal/status", nil)
	req.RemoteAddr = "8.8.8.8:12345"
	w := httptest.NewRecorder()
	app.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Errorf("want 403, got %d", w.Code)
	}
}

func TestInternalStatusServesLoopbackIPv4(t *testing.T) {
	_, app := newTestApp(t)
	req := httptest.NewRequest("GET", "/internal/status", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	app.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "FLAG{ssrf_linkpeek_easy}") {
		t.Error("want flag in response")
	}
}

func TestInternalStatusServesLoopbackIPv6(t *testing.T) {
	_, app := newTestApp(t)
	req := httptest.NewRequest("GET", "/internal/status", nil)
	req.RemoteAddr = "[::1]:12345"
	w := httptest.NewRecorder()
	app.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}
}
