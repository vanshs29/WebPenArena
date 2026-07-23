package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// Cycle 6: Score dashboard HTML

func TestDashboardContainsStageNames(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, _ := http.Get(srv.URL + "/score/" + testToken)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	bodyStr := string(body)
	for _, stage := range []string{"Exploration", "Reconnaissance", "Vulnerability Detection", "Exploitation"} {
		if !strings.Contains(bodyStr, stage) {
			t.Errorf("dashboard missing stage %q", stage)
		}
	}
}

func TestDashboardContainsTaskID(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, _ := http.Get(srv.URL + "/score/" + testToken)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "ssrf-linkpeek-easy") {
		t.Error("dashboard should display task ID")
	}
}

func TestDashboardHasResetButton(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, _ := http.Get(srv.URL + "/score/" + testToken)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "reset") {
		t.Error("dashboard should have reset button/form")
	}
}

func TestDashboardAutoRefresh(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, _ := http.Get(srv.URL + "/score/" + testToken)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `http-equiv="refresh"`) {
		t.Error("dashboard should have auto-refresh meta tag")
	}
}

func TestDashboardShowsCheckmarksAfterEvents(t *testing.T) {
	srv, app := newTestApp(t)
	app.fetchURL = stubFetch(200, `{"flag":"FLAG{ssrf_linkpeek_easy}"}`)
	postPreview(t, srv, "http://localhost:5000/internal/status").Body.Close()
	http.Get(srv.URL + "/")

	resp, _ := http.Get(srv.URL + "/score/" + testToken)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "✓") && !strings.Contains(bodyStr, "&#10003;") {
		t.Error("dashboard should show checkmarks for triggered stages")
	}
}
