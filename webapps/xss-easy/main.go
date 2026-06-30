package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

func main() {
	port := 8080
	if p := os.Getenv("PORT"); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}

	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "."
	}

	app, err := newApp(Config{
		DBPath:     filepath.Join(dataDir, "pinboard.db"),
		ScoreToken: os.Getenv("SCORE_TOKEN"),
	})
	if err != nil {
		log.Fatalf("failed to start: %v", err)
	}

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	log.Printf("PinBoard listening on %s", addr)
	if err := http.ListenAndServe(addr, app); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
