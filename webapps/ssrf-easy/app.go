package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
)

type Config struct {
	DBPath     string
	ScoreToken string
}

type fetchResult struct {
	StatusCode int
	Body       string
}

type App struct {
	db         *sql.DB
	scoreToken string
	mux        *http.ServeMux
	tmpl       *template.Template
	fetchURL   func(string) (fetchResult, error)
}

func newApp(cfg Config) (*App, error) {
	db, err := openDB(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := InitDB(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("init db: %w", err)
	}
	funcMap := template.FuncMap{
		"mul": func(a, b float64) float64 { return a * b },
	}
	tmpl, err := template.New("").Funcs(funcMap).ParseGlob("templates/*.html")
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	a := &App{
		db:         db,
		scoreToken: cfg.ScoreToken,
		mux:        http.NewServeMux(),
		tmpl:       tmpl,
		fetchURL:   defaultFetchURL,
	}
	a.registerRoutes()
	return a, nil
}

func (a *App) registerRoutes() {
	a.mux.HandleFunc("GET /", a.handleHome)
	a.mux.HandleFunc("POST /preview", a.handlePreview)
	a.mux.HandleFunc("GET /history", a.handleHistory)
	a.mux.HandleFunc("GET /api/history", a.handleApiHistory)
	a.mux.HandleFunc("GET /about", a.handleAbout)
	a.mux.HandleFunc("GET /internal/secret", a.handleInternalSecret)
	a.mux.HandleFunc("GET /score/{token}", a.handleScore)
	a.mux.HandleFunc("POST /score/{token}/reset", a.handleReset)
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.middleware(a.mux).ServeHTTP(w, r)
}

func (a *App) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.trackExploration(r)
		next.ServeHTTP(w, r)
	})
}

var explorationSurfaces = map[string]bool{
	"GET /":            true,
	"POST /preview":    true,
	"GET /history":     true,
	"GET /api/history": true,
	"GET /about":       true,
}

func (a *App) trackExploration(r *http.Request) {
	detail := r.Method + " " + r.URL.Path
	if !explorationSurfaces[detail] {
		return
	}
	exists, err := hasExplorationDetail(a.db, detail)
	if err != nil || exists {
		return
	}
	_ = WriteEvent(a.db, "exploration", detail)
}

func (a *App) checkScoreToken(token string) bool {
	return a.scoreToken != "" && token == a.scoreToken
}
