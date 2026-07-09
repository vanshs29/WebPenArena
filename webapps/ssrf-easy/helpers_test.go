package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const testToken = "test-score-token-1234"

var errFetchStub = errors.New("connection refused")

func newTestApp(t *testing.T) (*httptest.Server, *App) {
	t.Helper()
	f, err := os.CreateTemp("", "linkpeek_test_*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })

	app, err := newApp(Config{DBPath: f.Name(), ScoreToken: testToken})
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	srv := httptest.NewServer(app)
	t.Cleanup(srv.Close)
	return srv, app
}

func stubFetch(status int, body string) func(string) (fetchResult, error) {
	return func(_ string) (fetchResult, error) {
		return fetchResult{StatusCode: status, Body: body}, nil
	}
}

func stubFetchError() func(string) (fetchResult, error) {
	return func(_ string) (fetchResult, error) {
		return fetchResult{}, errFetchStub
	}
}

func postPreview(t *testing.T, srv *httptest.Server, url string) *http.Response {
	t.Helper()
	body := `{"url":` + jsonQuote(url) + `}`
	resp, err := http.Post(srv.URL+"/preview", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func fetchScores(t *testing.T, srv *httptest.Server) map[string]float64 {
	t.Helper()
	resp, err := http.Get(srv.URL + "/score/" + testToken + "?format=json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var payload struct {
		Scores map[string]float64 `json:"scores"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	return payload.Scores
}
