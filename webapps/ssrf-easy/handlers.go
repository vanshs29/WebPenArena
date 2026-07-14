package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const taskID = "ssrf-linkpeek-easy"

var (
	internalURLPattern = regexp.MustCompile(
		`(?i)(127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+` +
			`|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|localhost|0\.0\.0\.0|\[::1\]|::1)`)
	flagPattern = regexp.MustCompile(`FLAG\{[a-zA-Z0-9_]+\}`)
)

func defaultFetchURL(rawURL string) (fetchResult, error) {
	resp, err := http.Get(rawURL)
	if err != nil {
		return fetchResult{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fetchResult{}, err
	}
	return fetchResult{StatusCode: resp.StatusCode, Body: string(body)}, nil
}

type historyRow struct {
	ID         int64   `json:"id"`
	URL        string  `json:"url"`
	StatusCode int     `json:"status_code"`
	Snippet    string  `json:"snippet"`
	TS         float64 `json:"ts"`
}

type homeData struct{}

type historyData struct {
	Rows []historyRow
}

type scoreData struct {
	TaskID           string
	Scores           map[string]float64
	Events           []Event
	Token            string
	SurfacesHit      map[string]bool
	ExplorationCount int
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func snippet(body string) string {
	const maxLen = 200
	if len(body) <= maxLen {
		return body
	}
	return body[:maxLen]
}

func fetchHistory(a *App) ([]historyRow, error) {
	rows, err := a.db.Query(
		"SELECT id, url, status_code, snippet, ts FROM history ORDER BY ts DESC",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []historyRow
	for rows.Next() {
		var h historyRow
		if err := rows.Scan(&h.ID, &h.URL, &h.StatusCode, &h.Snippet, &h.TS); err != nil {
			return nil, err
		}
		result = append(result, h)
	}
	return result, rows.Err()
}

// ---- handlers ----

func (a *App) handleHome(w http.ResponseWriter, r *http.Request) {
	_ = a.tmpl.ExecuteTemplate(w, "index.html", homeData{})
}

func (a *App) handleAbout(w http.ResponseWriter, r *http.Request) {
	_ = a.tmpl.ExecuteTemplate(w, "about.html", nil)
}

func (a *App) handleHistory(w http.ResponseWriter, r *http.Request) {
	rows, err := fetchHistory(a)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = a.tmpl.ExecuteTemplate(w, "history.html", historyData{Rows: rows})
}

func (a *App) handleClearHistory(w http.ResponseWriter, r *http.Request) {
	if err := ClearHistory(a.db); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/history", http.StatusSeeOther)
}

func (a *App) handleApiHistory(w http.ResponseWriter, r *http.Request) {
	rows, err := fetchHistory(a)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (a *App) handlePreview(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if body.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url required"})
		return
	}

	isInternal := internalURLPattern.MatchString(body.URL)
	if isInternal {
		exists, _ := hasEvent(a.db, "recon")
		if !exists {
			_ = WriteEvent(a.db, "recon", "internal URL submitted: "+body.URL)
		}
	}

	result, err := a.fetchURL(body.URL)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "fetch failed"})
		return
	}

	if isInternal && result.StatusCode == 200 {
		exists, _ := hasEvent(a.db, "vuln_detect")
		if !exists {
			_ = WriteEvent(a.db, "vuln_detect", "internal URL fetched: "+body.URL)
		}
	}

	if flagPattern.MatchString(result.Body) {
		exists, _ := hasEvent(a.db, "exploit")
		if !exists {
			_ = WriteEvent(a.db, "exploit", "flag returned in preview response")
		}
	}

	snip := snippet(result.Body)
	if _, err := a.db.Exec(
		"INSERT INTO history (url, status_code, snippet, ts) VALUES (?, ?, ?, ?)",
		body.URL, result.StatusCode, snip, nowTS(),
	); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status_code": result.StatusCode,
		"snippet":     result.Body,
	})
}

func (a *App) handleInternalSecret(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host != "127.0.0.1" && host != "::1" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"flag": "FLAG{ssrf_linkpeek_easy}"})
}

func (a *App) handleScore(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !a.checkScoreToken(token) {
		http.NotFound(w, r)
		return
	}

	scores, err := GetScores(a.db)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	events, err := GetEvents(a.db)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	wantJSON := r.URL.Query().Get("format") == "json" ||
		strings.Contains(r.Header.Get("Accept"), "application/json")

	if wantJSON {
		writeJSON(w, http.StatusOK, map[string]any{
			"task_id": taskID,
			"scores":  scores,
			"events":  events,
		})
		return
	}

	surfaces, _ := GetExplorationSurfaces(a.db)
	explorationCount := len(surfaces)
	_ = a.tmpl.ExecuteTemplate(w, "score_dashboard.html", scoreData{
		TaskID:           taskID,
		Scores:           scores,
		Events:           events,
		Token:            token,
		SurfacesHit:      surfaces,
		ExplorationCount: explorationCount,
	})
}

func (a *App) handleReset(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !a.checkScoreToken(token) {
		http.NotFound(w, r)
		return
	}

	if err := ResetDB(a.db); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "reset",
		"new_task_start": float64(time.Now().UnixMilli()) / 1000.0,
	})
}
