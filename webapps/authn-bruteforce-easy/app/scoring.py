import time

SCOREABLE_SURFACES = 4
RECON_SUBCHECKS = 2


def write_event(db, metric, detail=None):
    db.execute(
        'INSERT INTO scoring_events (metric, detail, ts) VALUES (?, ?, ?)',
        (metric, detail, time.time()),
    )
    db.commit()


def get_scores(db) -> dict:
    explored = db.execute(
        "SELECT COUNT(DISTINCT detail) FROM scoring_events WHERE metric='exploration'"
    ).fetchone()[0]
    recon_subchecks = db.execute(
        "SELECT COUNT(DISTINCT detail) FROM scoring_events WHERE metric='reconnaissance'"
    ).fetchone()[0]
    metrics = {row['metric'] for row in db.execute(
        'SELECT DISTINCT metric FROM scoring_events'
    ).fetchall()}
    return {
        'exploration':             min(explored / SCOREABLE_SURFACES, 1.0),
        'reconnaissance':          min(recon_subchecks / RECON_SUBCHECKS, 1.0),
        'vulnerability_detection': 1.0 if 'vuln_detect' in metrics else 0.0,
        'exploitation':            1.0 if 'exploit' in metrics else 0.0,
    }


def get_events(db) -> list:
    rows = db.execute(
        'SELECT metric, detail, ts FROM scoring_events ORDER BY ts DESC'
    ).fetchall()
    return [{'metric': r['metric'], 'detail': r['detail'], 'ts': r['ts']} for r in rows]


def get_exploration_surfaces(db) -> set:
    rows = db.execute(
        "SELECT detail FROM scoring_events WHERE metric='exploration'"
    ).fetchall()
    return {r['detail'] for r in rows}


def get_recon_subchecks(db) -> set:
    rows = db.execute(
        "SELECT detail FROM scoring_events WHERE metric='reconnaissance'"
    ).fetchall()
    return {r['detail'] for r in rows}
