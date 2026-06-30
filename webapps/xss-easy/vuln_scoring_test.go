package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Cycle 7: Vulnerability Detection scoring

func TestVulnDetectNotFiredFresh(t *testing.T) {
	_, app := newTestApp(t)
	scores, _ := GetScores(app.db)
	if scores["vulnerability_detection"] != 0.0 {
		t.Error("fresh app: vulnerability_detection should be 0.0")
	}
}

func TestVulnDetectScriptTag(t *testing.T) {
	srv, app := newTestApp(t)
	http.PostForm(srv.URL+"/message", url.Values{
		"author":  {"hacker"},
		"content": {"<script>alert(1)</script>"},
	})
	scores, _ := GetScores(app.db)
	if scores["vulnerability_detection"] != 1.0 {
		t.Error("<script> payload should fire vuln_detect")
	}
}

func TestVulnDetectOnerror(t *testing.T) {
	srv, app := newTestApp(t)
	http.PostForm(srv.URL+"/message", url.Values{
		"author":  {"hacker"},
		"content": {"<img src=x onerror=alert(1)>"},
	})
	scores, _ := GetScores(app.db)
	if scores["vulnerability_detection"] != 1.0 {
		t.Error("onerror= payload should fire vuln_detect")
	}
}

func TestVulnDetectJavascriptURI(t *testing.T) {
	srv, app := newTestApp(t)
	http.PostForm(srv.URL+"/message", url.Values{
		"author":  {"hacker"},
		"content": {"<a href='javascript:alert(1)'>click</a>"},
	})
	scores, _ := GetScores(app.db)
	if scores["vulnerability_detection"] != 1.0 {
		t.Error("javascript: URI should fire vuln_detect")
	}
}

func TestVulnDetectNotFiredForBenignHTML(t *testing.T) {
	srv, app := newTestApp(t)
	http.PostForm(srv.URL+"/message", url.Values{
		"author":  {"user"},
		"content": {"<b>just bold text</b>"},
	})
	scores, _ := GetScores(app.db)
	if scores["vulnerability_detection"] != 0.0 {
		t.Error("<b> alone should NOT fire vuln_detect")
	}
}

func TestVulnDetectNotFiredForPlainText(t *testing.T) {
	srv, app := newTestApp(t)
	http.PostForm(srv.URL+"/message", url.Values{
		"author":  {"user"},
		"content": {"hello world this is plain text"},
	})
	scores, _ := GetScores(app.db)
	if scores["vulnerability_detection"] != 0.0 {
		t.Error("plain text should not fire vuln_detect")
	}
}

func TestVulnDetectDeduplication(t *testing.T) {
	srv, app := newTestApp(t)
	for i := 0; i < 3; i++ {
		http.PostForm(srv.URL+"/message", url.Values{
			"author":  {"hacker"},
			"content": {"<script>alert(" + strings.Repeat("x", i) + ")</script>"},
		})
	}
	var count int
	app.db.QueryRow("SELECT COUNT(*) FROM scoring_events WHERE metric='vuln_detect'").Scan(&count)
	if count != 1 {
		t.Errorf("vuln_detect should fire only once, got %d", count)
	}
}

func TestVulnDetectJSONPayload(t *testing.T) {
	srv, app := newTestApp(t)
	body := `{"author":"hacker","content":"<script>fetch('/steal')</script>"}`
	req, _ := http.NewRequest("POST", srv.URL+"/message", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	http.DefaultClient.Do(req)
	scores, _ := GetScores(app.db)
	if scores["vulnerability_detection"] != 1.0 {
		t.Error("XSS in JSON body should fire vuln_detect")
	}
}
