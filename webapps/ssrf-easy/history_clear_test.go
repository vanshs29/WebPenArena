package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func postClearHistory(t *testing.T, srv *http.Client, url string) *http.Response {
	t.Helper()
	resp, err := srv.Post(url+"/history/clear", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestClearHistoryRemovesAllRows(t *testing.T) {
	srv, _ := newTestApp(t)
	postClearHistory(t, http.DefaultClient, srv.URL).Body.Close()

	resp, _ := http.Get(srv.URL + "/api/history")
	defer resp.Body.Close()
	var result []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("want 0 history rows after clear, got %d", len(result))
	}
}

func TestClearHistoryRedirectsToHistoryPage(t *testing.T) {
	srv, _ := newTestApp(t)
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp := postClearHistory(t, client, srv.URL)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/history" {
		t.Errorf("want redirect to /history, got %q", loc)
	}
}

func TestHistoryPageShowsEmptyMessageAfterClear(t *testing.T) {
	srv, _ := newTestApp(t)
	postClearHistory(t, http.DefaultClient, srv.URL).Body.Close()

	resp, err := http.Get(srv.URL + "/history")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "No previews yet.") {
		t.Error("want empty-history message after clear")
	}
}

func TestClearHistoryDoesNotAffectScores(t *testing.T) {
	srv, app := newTestApp(t)
	app.fetchURL = stubFetch(200, "internal service, FLAG{ssrf_linkpeek_easy}")
	postPreview(t, srv, "http://127.0.0.1:9999/internal").Body.Close()
	visitResp, _ := http.Get(srv.URL + "/history")
	visitResp.Body.Close()

	before := fetchScores(t, srv)
	postClearHistory(t, http.DefaultClient, srv.URL).Body.Close()
	after := fetchScores(t, srv)

	for metric, want := range before {
		if got := after[metric]; got != want {
			t.Errorf("metric %q changed after clearing history: want %v, got %v", metric, want, got)
		}
	}
}

func TestClearHistoryOnEmptyHistorySucceeds(t *testing.T) {
	srv, _ := newTestApp(t)
	postClearHistory(t, http.DefaultClient, srv.URL).Body.Close()
	resp := postClearHistory(t, http.DefaultClient, srv.URL)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("want 200 (after following redirect), got %d", resp.StatusCode)
	}
}

func TestGetOnClearHistoryDoesNotClearRows(t *testing.T) {
	srv, _ := newTestApp(t)
	getResp, _ := http.Get(srv.URL + "/history/clear")
	getResp.Body.Close()

	resp, _ := http.Get(srv.URL + "/api/history")
	defer resp.Body.Close()
	var result []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 3 {
		t.Errorf("GET on /history/clear must not clear rows; want 3 seed rows, got %d", len(result))
	}
}
