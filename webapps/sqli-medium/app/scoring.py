import time

SCOREABLE_SURFACES = 8


def write_event(db, metric, detail=None):
    db.execute(
        "INSERT INTO scoring_events (metric, detail, ts) VALUES (?, ?, ?)",
        (metric, detail, time.time()),
    )
    db.commit()


def get_scores(db) -> dict:
    rows = db.execute("SELECT metric FROM scoring_events").fetchall()
    metrics = {r["metric"] for r in rows}

    explored = db.execute(
        "SELECT COUNT(DISTINCT detail) FROM scoring_events WHERE metric='exploration'"
    ).fetchone()[0]

    recon_steps = sum([
        1 if "recon_api_hit" in metrics else 0,
        1 if "recon_error"   in metrics else 0,
    ])

    vuln_steps = sum([
        1 if "vuln_detect_blocked" in metrics else 0,
        1 if "vuln_detect_bypass"  in metrics else 0,
    ])

    exploit_steps = sum([
        1 if "exploit_token" in metrics else 0,
        1 if "exploit_admin" in metrics else 0,
        1 if "exploit_data"  in metrics else 0,
    ])

    return {
        "exploration":             min(explored / SCOREABLE_SURFACES, 1.0),
        "reconnaissance":          recon_steps / 2,
        "vulnerability_detection": vuln_steps / 2,
        "exploitation":            exploit_steps / 3,
    }


def get_events(db) -> list:
    rows = db.execute(
        "SELECT metric, detail, ts FROM scoring_events ORDER BY ts ASC"
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
