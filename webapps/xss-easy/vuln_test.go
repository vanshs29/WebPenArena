package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Cycle 4: Vulnerability present and working

func TestStoredXSSPreservedInDB(t *testing.T) {
	_, app := newTestApp(t)
	payload := `<script>alert(1)</script>`
	app.db.Exec("INSERT INTO messages (author, content, ts) VALUES (?, ?, ?)", "hacker", payload, nowTS())
	var stored string
	app.db.QueryRow("SELECT content FROM messages WHERE author='hacker'").Scan(&stored)
	if stored != payload {
		t.Errorf("stored content should be raw, got %q", stored)
	}
}

func TestStoredXSSRenderedOnHome(t *testing.T) {
	srv, app := newTestApp(t)
	payload := `<script>alert(1)</script>`
	app.db.Exec("INSERT INTO messages (author, content, ts) VALUES (?, ?, ?)", "hacker", payload, nowTS())
	resp, _ := http.Get(srv.URL + "/")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	bodyStr := string(body)
	if !strings.Contains(bodyStr, payload) {
		t.Error("GET / should render stored XSS payload as raw HTML")
	}
	if strings.Contains(bodyStr, "&lt;script&gt;") {
		t.Error("GET / must NOT escape the XSS payload — vulnerability must be present")
	}
}

func TestStoredXSSRenderedOnAdmin(t *testing.T) {
	srv, app := newTestApp(t)
	payload := `<script>alert(1)</script>`
	app.db.Exec("INSERT INTO messages (author, content, ts) VALUES (?, ?, ?)", "hacker", payload, nowTS())
	resp, _ := http.Get(srv.URL + "/admin")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), payload) {
		t.Error("GET /admin should also render stored XSS payload as raw HTML")
	}
}

func TestReflectedXSSInSearch(t *testing.T) {
	srv, _ := newTestApp(t)
	xssPayload := `<script>alert(1)</script>`
	resp, _ := http.Get(srv.URL + "/search?q=" + url.QueryEscape(xssPayload))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	bodyStr := string(body)
	// The "Results for:" heading must contain the raw, unescaped XSS payload
	if !strings.Contains(bodyStr, "Results for: "+xssPayload) {
		t.Error("search heading should reflect XSS payload as raw HTML (not escaped)")
	}
}

func TestOnerrorXSSStoredAndRendered(t *testing.T) {
	srv, app := newTestApp(t)
	payload := `<img src=x onerror=alert(1)>`
	app.db.Exec("INSERT INTO messages (author, content, ts) VALUES (?, ?, ?)", "hacker", payload, nowTS())
	resp, _ := http.Get(srv.URL + "/")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), payload) {
		t.Error("onerror payload should be rendered unsafely on home page")
	}
}

func TestSafeInputRenderedCorrectly(t *testing.T) {
	srv, app := newTestApp(t)
	plain := "This is a plain message with no HTML"
	app.db.Exec("INSERT INTO messages (author, content, ts) VALUES (?, ?, ?)", "user", plain, nowTS())
	resp, _ := http.Get(srv.URL + "/")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), plain) {
		t.Error("plain text message should appear on home page")
	}
}
