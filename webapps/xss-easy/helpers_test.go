package main

import (
	"net/http/httptest"
	"os"
	"testing"
)

const testToken = "test-score-token-1234"

func newTestApp(t *testing.T) (*httptest.Server, *App) {
	t.Helper()
	f, err := os.CreateTemp("", "pinboard_test_*.db")
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
