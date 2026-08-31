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

type App struct {
	db         *sql.DB
	scoreToken string
	mux        *http.ServeMux
	jwtSecret  string
	tmpl       *template.Template
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
	secret, err := loadJWTSecret(db)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("load jwt secret: %w", err)
	}
	funcMap := template.FuncMap{
		"add4": func(a, b, c, d float64) float64 { return a + b + c + d },
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
		jwtSecret:  secret,
		tmpl:       tmpl,
	}
	a.registerRoutes()
	return a, nil
}

func (a *App) registerRoutes() {
	a.mux.HandleFunc("GET /", a.handleHome)
	a.mux.HandleFunc("POST /message", a.handleMessage)
	a.mux.HandleFunc("GET /admin", a.handleAdmin)
	a.mux.HandleFunc("GET /search", a.handleSearch)
	a.mux.HandleFunc("GET /score/{token}", a.handleScore)
	a.mux.HandleFunc("POST /score/{token}/reset", a.handleReset)
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.middleware(a.mux).ServeHTTP(w, r)
}

func (a *App) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.trackExploration(r)
		a.checkExploit(r)
		next.ServeHTTP(w, r)
	})
}

var explorationSurfaces = map[string]bool{
	"GET /":          true,
	"POST /message":  true,
	"GET /admin":     true,
	"GET /search":    true,
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

func (a *App) checkExploit(r *http.Request) {
	if r.Method != "GET" {
		return
	}
	if r.URL.Path != "/" && r.URL.Path != "/admin" {
		return
	}
	hasVuln, err := hasEvent(a.db, "vuln_detect")
	if err != nil || !hasVuln {
		return
	}
	hasExploit, err := hasEvent(a.db, "exploit")
	if err != nil || hasExploit {
		return
	}
	_ = WriteEvent(a.db, "exploit", "XSS payload rendered on "+r.URL.Path)
}

func (a *App) checkScoreToken(token string) bool {
	return a.scoreToken != "" && token == a.scoreToken
}
