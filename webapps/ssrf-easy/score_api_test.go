package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

// Cycle 6: Score API

func TestWrongTokenReturns404(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, err := http.Get(srv.URL + "/score/bad-token")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("want 404, got %d", resp.StatusCode)
	}
}

func TestScoreAPIShape(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, err := http.Get(srv.URL + "/score/" + testToken + "?format=json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if result["task_id"] != "ssrf-linkpeek-easy" {
		t.Errorf("want task_id ssrf-linkpeek-easy, got %v", result["task_id"])
	}
	if _, ok := result["scores"]; !ok {
		t.Error("want scores field")
	}
	if _, ok := result["events"]; !ok {
		t.Error("want events field")
	}
}

func TestScoreAPIAllFourMetricsPresent(t *testing.T) {
	srv, _ := newTestApp(t)
	scores := fetchScores(t, srv)
	for _, m := range []string{"exploration", "reconnaissance", "vulnerability_detection", "exploitation"} {
		if _, ok := scores[m]; !ok {
			t.Errorf("want metric %q in scores", m)
		}
	}
}

func TestScoreAPIAcceptHeaderNegotiatesJSON(t *testing.T) {
	srv, _ := newTestApp(t)
	req, _ := http.NewRequest("GET", srv.URL+"/score/"+testToken, nil)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	ct := resp.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("want application/json content-type, got %q", ct)
	}
}

func TestScoreHTMLByDefault(t *testing.T) {
	srv, _ := newTestApp(t)
	resp, err := http.Get(srv.URL + "/score/" + testToken)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	ct := resp.Header.Get("Content-Type")
	if ct != "" && ct != "text/html; charset=utf-8" {
		t.Errorf("want html content-type, got %q", ct)
	}
}
