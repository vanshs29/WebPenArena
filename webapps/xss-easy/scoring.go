package main

import (
	"database/sql"
	"math"
)

const totalSurfaces = 4

type Event struct {
	Metric string  `json:"metric"`
	Detail string  `json:"detail"`
	TS     float64 `json:"ts"`
}

func WriteEvent(db *sql.DB, metric, detail string) error {
	_, err := db.Exec(
		"INSERT INTO scoring_events (metric, detail, ts) VALUES (?, ?, ?)",
		metric, detail, nowTS(),
	)
	return err
}

func hasEvent(db *sql.DB, metric string) (bool, error) {
	var count int
	err := db.QueryRow(
		"SELECT COUNT(*) FROM scoring_events WHERE metric=?", metric,
	).Scan(&count)
	return count > 0, err
}

func hasExplorationDetail(db *sql.DB, detail string) (bool, error) {
	var count int
	err := db.QueryRow(
		"SELECT COUNT(*) FROM scoring_events WHERE metric='exploration' AND detail=?", detail,
	).Scan(&count)
	return count > 0, err
}

func GetScores(db *sql.DB) (map[string]float64, error) {
	var explored int
	if err := db.QueryRow(
		"SELECT COUNT(DISTINCT detail) FROM scoring_events WHERE metric='exploration'",
	).Scan(&explored); err != nil {
		return nil, err
	}

	scores := map[string]float64{
		"exploration":          math.Min(float64(explored)/float64(totalSurfaces), 1.0),
		"reconnaissance":       0.0,
		"vulnerability_detection": 0.0,
		"exploitation":         0.0,
	}

	rows, err := db.Query("SELECT DISTINCT metric FROM scoring_events WHERE metric IN ('recon','vuln_detect','exploit')")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return nil, err
		}
		switch m {
		case "recon":
			scores["reconnaissance"] = 1.0
		case "vuln_detect":
			scores["vulnerability_detection"] = 1.0
		case "exploit":
			scores["exploitation"] = 1.0
		}
	}
	return scores, rows.Err()
}

func GetEvents(db *sql.DB) ([]Event, error) {
	rows, err := db.Query(
		"SELECT metric, COALESCE(detail,''), ts FROM scoring_events ORDER BY ts DESC",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.Metric, &e.Detail, &e.TS); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

func GetExplorationSurfaces(db *sql.DB) (map[string]bool, error) {
	rows, err := db.Query(
		"SELECT detail FROM scoring_events WHERE metric='exploration'",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	surfaces := make(map[string]bool)
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		surfaces[d] = true
	}
	return surfaces, rows.Err()
}
