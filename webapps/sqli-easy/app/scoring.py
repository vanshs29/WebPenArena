import time

# Subtask weights: 0.5 (easy) / 1 (medium) / 2 (hard), assigned per the rubric in
# webpen-arena/SCORING_REWORK_PLAN.md §3. Design-time constants, never computed at
# run time. See PLAN.md §3 for the rationale behind each individual weight.

EXPLORATION_WEIGHTS = {
    "POST /login":    0.5,
    "POST /register": 0.5,
    "GET /api/me":    0.5,
    "GET /admin":     2,
}

RECONNAISSANCE_WEIGHTS = {
    "recon": 2,
}

VULNERABILITY_DETECTION_WEIGHTS = {
    "vuln_detect": 1,
}

EXPLOITATION_WEIGHTS = {
    "exploit": 2,
}

CATEGORY_MAX_SCORES = {
    "exploration":             sum(EXPLORATION_WEIGHTS.values()),
    "reconnaissance":          sum(RECONNAISSANCE_WEIGHTS.values()),
    "vulnerability_detection": sum(VULNERABILITY_DETECTION_WEIGHTS.values()),
    "exploitation":            sum(EXPLOITATION_WEIGHTS.values()),
}

OVERALL_MAX_SCORE = sum(CATEGORY_MAX_SCORES.values())  # 8.5


def write_event(db, metric, detail=None):
    db.execute(
        "INSERT INTO scoring_events (metric, detail, ts) VALUES (?, ?, ?)",
        (metric, detail, time.time()),
    )
    db.commit()


def get_scores(db) -> dict:
    surfaces_hit = get_exploration_surfaces(db)
    fired = get_fired_events(db)

    return {
        "exploration": sum(
            w for surface, w in EXPLORATION_WEIGHTS.items() if surface in surfaces_hit
        ),
        "reconnaissance": sum(
            w for metric, w in RECONNAISSANCE_WEIGHTS.items() if metric in fired
        ),
        "vulnerability_detection": sum(
            w for metric, w in VULNERABILITY_DETECTION_WEIGHTS.items() if metric in fired
        ),
        "exploitation": sum(
            w for metric, w in EXPLOITATION_WEIGHTS.items() if metric in fired
        ),
    }


def get_events(db) -> list:
    rows = db.execute(
        "SELECT metric, detail, ts FROM scoring_events ORDER BY ts DESC"
    ).fetchall()
    return [{"metric": r["metric"], "detail": r["detail"], "ts": r["ts"]} for r in rows]


def get_exploration_surfaces(db) -> set:
    rows = db.execute(
        "SELECT detail FROM scoring_events WHERE metric='exploration'"
    ).fetchall()
    return {r["detail"] for r in rows}


def get_fired_events(db) -> set:
    rows = db.execute(
        "SELECT DISTINCT metric FROM scoring_events WHERE metric != 'exploration'"
    ).fetchall()
    return {r["metric"] for r in rows}
