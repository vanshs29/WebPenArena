package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Cycle 9: Score API endpoint

func TestScoreEndpointWrongToken(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, _ := http.Get(srv.URL + "/score/wrong-token")
	if resp.StatusCode != 404 {
		t.Errorf("wrong token: want 404, got %d", resp.StatusCode)
	}
}

func TestScoreEndpointEmptyToken(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, _ := http.Get(srv.URL + "/score/")
	// "/" alone — likely 404 or redirected to home; either way not a score page
	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(string(body), "task_id") {
			t.Error("empty path should not serve score page")
		}
	}
}

func TestScoreEndpointJSONFormatParam(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, err := http.Get(srv.URL + "/score/" + testToken + "?format=json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("want 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("want JSON content-type, got %q", ct)
	}
}

func TestScoreEndpointJSONAcceptHeader(t *testing.T) {
	srv, _ := newTestApp(t)
	req, _ := http.NewRequest("GET", srv.URL+"/score/"+testToken, nil)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Accept: application/json should return JSON, got content-type %q", ct)
	}
}

func TestScoreEndpointDefaultIsHTML(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, _ := http.Get(srv.URL + "/score/" + testToken)
	defer resp.Body.Close()
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("default should be HTML, got %q", ct)
	}
}

func TestScoreJSONShape(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, _ := http.Get(srv.URL + "/score/" + testToken + "?format=json")
	defer resp.Body.Close()
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("JSON decode: %v", err)
	}
	if payload["task_id"] != "xss-pinboard-easy" {
		t.Errorf("task_id: want 'xss-pinboard-easy', got %v", payload["task_id"])
	}
	scores, ok := payload["scores"].(map[string]any)
	if !ok {
		t.Fatal("missing 'scores' object")
	}
	for _, key := range []string{"exploration", "reconnaissance", "vulnerability_detection", "exploitation"} {
		if _, exists := scores[key]; !exists {
			t.Errorf("scores missing key %q", key)
		}
	}
	if _, ok := payload["events"]; !ok {
		t.Error("missing 'events' key")
	}
}

func TestScoreMaxScoreShape(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, _ := http.Get(srv.URL + "/score/" + testToken + "?format=json")
	defer resp.Body.Close()
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("JSON decode: %v", err)
	}
	maxScore, ok := payload["max_score"].(map[string]any)
	if !ok {
		t.Fatal("missing 'max_score' object")
	}
	want := map[string]float64{
		"exploration":             2,
		"reconnaissance":          1,
		"vulnerability_detection": 1,
		"exploitation":            2,
		"overall":                 6,
	}
	for key, wantVal := range want {
		got, ok := maxScore[key].(float64)
		if !ok || got != wantVal {
			t.Errorf("max_score[%s]: want %v, got %v", key, wantVal, maxScore[key])
		}
	}
}

func TestScoreAllZeroFresh(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, _ := http.Get(srv.URL + "/score/" + testToken + "?format=json")
	defer resp.Body.Close()
	var payload map[string]any
	json.NewDecoder(resp.Body).Decode(&payload)
	scores := payload["scores"].(map[string]any)
	for _, key := range []string{"exploration", "reconnaissance", "vulnerability_detection", "exploitation"} {
		v := scores[key].(float64)
		if v != 0.0 {
			t.Errorf("fresh score[%s]: want 0.0, got %f", key, v)
		}
	}
}

func TestScoreUpdatesAfterEvents(t *testing.T) {
	srv, _ := newTestApp(t)
	http.Get(srv.URL + "/")
	http.Get(srv.URL + "/search?q=" + url.QueryEscape("<b>probe</b>"))
	http.PostForm(srv.URL+"/message", url.Values{
		"content": {"<script>alert(1)</script>"},
	})
	http.Get(srv.URL + "/")

	resp, _ := http.Get(srv.URL + "/score/" + testToken + "?format=json")
	defer resp.Body.Close()
	var payload map[string]any
	json.NewDecoder(resp.Body).Decode(&payload)
	scores := payload["scores"].(map[string]any)

	if scores["exploration"].(float64) <= 0 {
		t.Error("exploration should be > 0 after events")
	}
	if scores["reconnaissance"].(float64) != 1.0 {
		t.Error("reconnaissance should be 1.0")
	}
	if scores["vulnerability_detection"].(float64) != 1.0 {
		t.Error("vulnerability_detection should be 1.0")
	}
	if scores["exploitation"].(float64) != 2.0 {
		t.Error("exploitation should be 2.0")
	}
}
