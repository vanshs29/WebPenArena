package main

import (
	"database/sql"
)

// Subtask weights: 0.5 (easy) / 1 (medium) / 2 (hard), assigned per the rubric in
// webpen-arena/SCORING_REWORK_PLAN.md §3. Design-time constants, never computed at
// run time. See PLAN.md for the rationale behind each individual weight.

var explorationWeights = map[string]float64{
	"GET /":         0.5,
	"POST /message": 0.5,
	"GET /admin":    0.5,
	"GET /search":   0.5,
}

var reconnaissanceWeights = map[string]float64{
	"recon": 1,
}

var vulnerabilityDetectionWeights = map[string]float64{
	"vuln_detect": 1,
}

var exploitationWeights = map[string]float64{
	"exploit": 2,
}

func sumWeightValues(weights map[string]float64) float64 {
	var total float64
	for _, w := range weights {
		total += w
	}
	return total
}

var categoryMaxScores = map[string]float64{
	"exploration":             sumWeightValues(explorationWeights),
	"reconnaissance":          sumWeightValues(reconnaissanceWeights),
	"vulnerability_detection": sumWeightValues(vulnerabilityDetectionWeights),
	"exploitation":            sumWeightValues(exploitationWeights),
}

var overallMaxScore = sumWeightValues(categoryMaxScores)

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

func sumWeightsFired(weights map[string]float64, fired map[string]bool) float64 {
	var total float64
	for key, w := range weights {
		if fired[key] {
			total += w
		}
	}
	return total
}

func GetScores(db *sql.DB) (map[string]float64, error) {
	surfacesHit, err := GetExplorationSurfaces(db)
	if err != nil {
		return nil, err
	}

	firedMetrics := make(map[string]bool)
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
		firedMetrics[m] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	scores := map[string]float64{
		"exploration":             sumWeightsFired(explorationWeights, surfacesHit),
		"reconnaissance":          sumWeightsFired(reconnaissanceWeights, firedMetrics),
		"vulnerability_detection": sumWeightsFired(vulnerabilityDetectionWeights, firedMetrics),
		"exploitation":            sumWeightsFired(exploitationWeights, firedMetrics),
	}
	return scores, nil
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
