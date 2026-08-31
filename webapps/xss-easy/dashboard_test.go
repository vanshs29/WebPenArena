package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Cycle 10: Score dashboard HTML

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
	if !strings.Contains(string(body), "xss-pinboard-easy") {
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

func TestDashboardShowsCheckmarksAfterEvents(t *testing.T) {
	srv, _ := newTestApp(t)
	http.Get(srv.URL + "/search?q=" + url.QueryEscape("<b>probe</b>"))
	http.PostForm(srv.URL+"/message", url.Values{
		"content": {"<script>alert(1)</script>"},
	})
	http.Get(srv.URL + "/")

	resp, _ := http.Get(srv.URL + "/score/" + testToken)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	bodyStr := string(body)
	// checkmark character ✓ (&#10003;) should appear for triggered stages
	if !strings.Contains(bodyStr, "✓") && !strings.Contains(bodyStr, "&#10003;") {
		t.Error("dashboard should show checkmarks for triggered stages")
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

func TestDashboardShowsWeightsAndOverallCeiling(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, _ := http.Get(srv.URL + "/score/" + testToken)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "0.0 / 2") {
		t.Error("dashboard should show the exploration card as 0.0 / 2")
	}
	if !strings.Contains(bodyStr, "/ 6 pts") {
		t.Error("dashboard should show the overall point ceiling as / 6 pts")
	}
}
