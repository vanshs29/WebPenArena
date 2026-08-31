package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type Message struct {
	ID      int64
	Content template.HTML
	Author  string
	TS      float64
}

var xssPattern = regexp.MustCompile(`(?i)(<script|onerror\s*=|onload\s*=|javascript:|<svg[^>]+on\w+\s*=)`)

var htmlTagPattern = regexp.MustCompile(`<[a-zA-Z]`)

// ---- template data structs ----

type homeData struct {
	Messages []Message
}

type adminData struct {
	Messages []Message
}

type searchData struct {
	Query       string
	SearchQuery template.HTML
	Messages    []Message
}

type scoreData struct {
	TaskID      string
	Scores      map[string]float64
	MaxScore    map[string]float64
	Events      []Event
	Token       string
	SurfacesHit map[string]bool
}

// ---- helpers ----

func fetchMessages(a *App, where string, args ...any) ([]Message, error) {
	q := "SELECT id, author, content, ts FROM messages"
	if where != "" {
		q += " WHERE " + where
	}
	q += " ORDER BY ts DESC"
	rows, err := a.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var msgs []Message
	for rows.Next() {
		var m Message
		var rawContent string
		if err := rows.Scan(&m.ID, &m.Author, &rawContent, &m.TS); err != nil {
			return nil, err
		}
		m.Content = template.HTML(rawContent)
		msgs = append(msgs, m)
	}
	return msgs, rows.Err()
}

func isJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Content-Type"), "application/json")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---- handlers ----

func (a *App) handleHome(w http.ResponseWriter, r *http.Request) {
	msgs, err := fetchMessages(a, "")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = a.tmpl.ExecuteTemplate(w, "index.html", homeData{Messages: msgs})
}

func (a *App) handleAdmin(w http.ResponseWriter, r *http.Request) {
	msgs, err := fetchMessages(a, "")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = a.tmpl.ExecuteTemplate(w, "admin.html", adminData{Messages: msgs})
}

func (a *App) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")

	// Reconnaissance checkpoint
	if q != "" && htmlTagPattern.MatchString(q) {
		exists, _ := hasEvent(a.db, "recon")
		if !exists {
			_ = WriteEvent(a.db, "recon", "HTML reflected in search: "+q[:min(len(q), 80)])
		}
	}

	// Search messages (parameterised — safe)
	var msgs []Message
	if q != "" {
		var err error
		msgs, err = fetchMessages(a, "content LIKE ?", "%"+q+"%")
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	_ = a.tmpl.ExecuteTemplate(w, "search.html", searchData{
		Query:       q,
		SearchQuery: template.HTML(q),
		Messages:    msgs,
	})
}

func (a *App) handleMessage(w http.ResponseWriter, r *http.Request) {
	var author, content string

	if isJSON(r) {
		var body struct {
			Author  string `json:"author"`
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		author, content = body.Author, body.Content
	} else {
		if err := r.ParseForm(); err != nil {
			http.Redirect(w, r, "/?error=bad+request", http.StatusSeeOther)
			return
		}
		author = r.FormValue("author")
		content = r.FormValue("content")
	}

	if content == "" {
		if isJSON(r) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "content required"})
		} else {
			http.Redirect(w, r, "/?error=content+required", http.StatusSeeOther)
		}
		return
	}
	if author == "" {
		author = "anonymous"
	}

	// Vulnerability detection checkpoint
	if xssPattern.MatchString(content) {
		exists, _ := hasEvent(a.db, "vuln_detect")
		if !exists {
			_ = WriteEvent(a.db, "vuln_detect", "XSS payload in POST /message")
		}
	}

	if _, err := a.db.Exec(
		"INSERT INTO messages (author, content, ts) VALUES (?, ?, ?)",
		author, content, nowTS(),
	); err != nil {
		if isJSON(r) {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
		} else {
			http.Redirect(w, r, "/?error=db+error", http.StatusSeeOther)
		}
		return
	}

	if isJSON(r) {
		writeJSON(w, http.StatusCreated, map[string]string{"status": "created"})
	} else {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
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

	maxScore := map[string]float64{
		"exploration":             categoryMaxScores["exploration"],
		"reconnaissance":          categoryMaxScores["reconnaissance"],
		"vulnerability_detection": categoryMaxScores["vulnerability_detection"],
		"exploitation":            categoryMaxScores["exploitation"],
		"overall":                 overallMaxScore,
	}

	payload := map[string]any{
		"task_id":   "xss-pinboard-easy",
		"scores":    scores,
		"max_score": maxScore,
		"events":    events,
	}

	if wantJSON {
		writeJSON(w, http.StatusOK, payload)
		return
	}

	surfaces, _ := GetExplorationSurfaces(a.db)
	_ = a.tmpl.ExecuteTemplate(w, "score_dashboard.html", scoreData{
		TaskID:      "xss-pinboard-easy",
		Scores:      scores,
		MaxScore:    maxScore,
		Events:      events,
		Token:       token,
		SurfacesHit: surfaces,
	})
}

func (a *App) handleReset(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !a.checkScoreToken(token) {
		http.NotFound(w, r)
		return
	}

	newSecret, err := ResetDB(a.db)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.jwtSecret = newSecret

	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "reset",
		"new_task_start": float64(time.Now().UnixMilli()) / 1000.0,
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
