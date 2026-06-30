import time

SCOREABLE_SURFACES = 4  # POST /login, POST /register, GET /admin, GET /api/me


def write_event(db, metric, detail=None):
    db.execute(
        "INSERT INTO scoring_events (metric, detail, ts) VALUES (?, ?, ?)",
        (metric, detail, time.time()),
    )
    db.commit()


def get_scores(db) -> dict:
    metrics = {row["metric"] for row in db.execute("SELECT metric FROM scoring_events").fetchall()}
    explored = db.execute(
        "SELECT COUNT(DISTINCT detail) FROM scoring_events WHERE metric='exploration'"
    ).fetchone()[0]
    return {
        "exploration": min(explored / SCOREABLE_SURFACES, 1.0),
        "reconnaissance": 1.0 if "recon" in metrics else 0.0,
        "vulnerability_detection": 1.0 if "vuln_detect" in metrics else 0.0,
        "exploitation": 1.0 if "exploit" in metrics else 0.0,
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
