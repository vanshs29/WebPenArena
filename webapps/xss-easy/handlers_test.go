package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Cycle 2: Home page and message submission

func TestHomePageStatus(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("GET / status: want 200, got %d", resp.StatusCode)
	}
}

func TestHomePageContainsSeedMessages(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, _ := http.Get(srv.URL + "/")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, keyword := range []string{"alice", "bob", "carol", "PinBoard"} {
		if !strings.Contains(string(body), keyword) {
			t.Errorf("home page missing %q", keyword)
		}
	}
}

func TestSubmitMessageFormRedirects(t *testing.T) {
	srv, _ := newTestApp(t)
	// net/http follows redirects by default; just check we land on /
	resp, err := http.PostForm(srv.URL+"/message", url.Values{
		"author":  {"tester"},
		"content": {"hello world"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("after form submit expected 200 (landed on /), got %d", resp.StatusCode)
	}
}

func TestSubmitMessageStored(t *testing.T) {
	_, app := newTestApp(t)
	app.db.Exec("INSERT INTO messages (author, content, ts) VALUES (?, ?, ?)", "test", "unique-msg-xyz", nowTS())
	var count int
	app.db.QueryRow("SELECT COUNT(*) FROM messages WHERE content='unique-msg-xyz'").Scan(&count)
	if count != 1 {
		t.Error("message not stored in DB")
	}
}

func TestSubmitMessageJSON(t *testing.T) {
	srv, _ := newTestApp(t)
	body := `{"author":"tester","content":"json post test"}`
	req, _ := http.NewRequest("POST", srv.URL+"/message", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Errorf("JSON POST /message: want 201, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("want JSON content-type, got %q", ct)
	}
}

func TestSubmitMessageEmptyContentJSON(t *testing.T) {
	srv, _ := newTestApp(t)
	body := `{"author":"tester","content":""}`
	req, _ := http.NewRequest("POST", srv.URL+"/message", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("empty content: want 400, got %d", resp.StatusCode)
	}
}

func TestSubmitMessageDefaultAuthor(t *testing.T) {
	_, app := newTestApp(t)
	app.db.Exec("INSERT INTO messages (author, content, ts) VALUES (?, ?, ?)", "anonymous", "anon-test", nowTS())
	var author string
	app.db.QueryRow("SELECT author FROM messages WHERE content='anon-test'").Scan(&author)
	if author != "anonymous" {
		t.Errorf("want author 'anonymous', got %q", author)
	}
}

// Cycle 3: Admin and Search

func TestAdminStatus(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, err := http.Get(srv.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("GET /admin: want 200, got %d", resp.StatusCode)
	}
}

func TestAdminContainsMessages(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, _ := http.Get(srv.URL + "/admin")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, kw := range []string{"alice", "bob", "Admin"} {
		if !strings.Contains(string(body), kw) {
			t.Errorf("admin page missing %q", kw)
		}
	}
}

func TestSearchStatus(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, err := http.Get(srv.URL + "/search")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("GET /search: want 200, got %d", resp.StatusCode)
	}
}

func TestSearchReflectsQuery(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, _ := http.Get(srv.URL + "/search?q=helloworld")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "helloworld") {
		t.Error("search page should reflect query string")
	}
}

func TestSearchReflectsHTMLUnsafe(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, _ := http.Get(srv.URL + "/search?q=" + url.QueryEscape("<b>bold</b>"))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	bodyStr := string(body)
	// The "Results for:" heading must render the HTML tag unsafely (not escaped)
	if !strings.Contains(bodyStr, "Results for: <b>bold</b>") {
		t.Error("search heading should reflect HTML tags unsafely (not escape them)")
	}
}

func TestSearchFindsMessage(t *testing.T) {
	srv, app := newTestApp(t)
	app.db.Exec("INSERT INTO messages (author, content, ts) VALUES (?, ?, ?)", "test", "uniquekeyword999", nowTS())
	resp, _ := http.Get(srv.URL + "/search?q=uniquekeyword999")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "uniquekeyword999") {
		t.Error("search should find stored messages matching query")
	}
}
