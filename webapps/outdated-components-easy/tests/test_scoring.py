import sqlite3

import pytest

from app.scoring import (
    write_event, get_scores, get_events, get_exploration_surfaces,
    CATEGORY_MAX_SCORES, OVERALL_MAX_SCORE,
)


@pytest.fixture
def db():
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE scoring_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          metric TEXT NOT NULL,
          detail TEXT,
          ts REAL NOT NULL
        );
        """
    )
    yield conn
    conn.close()


def test_scores_start_at_zero(db):
    scores = get_scores(db)
    assert scores == {
        'exploration': 0.0,
        'reconnaissance': 0.0,
        'vulnerability_detection': 0.0,
        'exploitation': 0.0,
    }


def test_write_event_inserts_row(db):
    write_event(db, 'reconnaissance', 'GET /about')
    rows = db.execute('SELECT metric, detail FROM scoring_events').fetchall()
    assert len(rows) == 1
    assert rows[0]['metric'] == 'reconnaissance'
    assert rows[0]['detail'] == 'GET /about'


def test_exploration_score_reflects_distinct_surfaces_hit(db):
    write_event(db, 'exploration', 'GET /')
    write_event(db, 'exploration', 'GET /about')
    scores = get_scores(db)
    assert scores['exploration'] == 1.0  # 0.5 + 0.5


def test_exploration_deduplicates_same_surface(db):
    write_event(db, 'exploration', 'GET /')
    write_event(db, 'exploration', 'GET /')
    scores = get_scores(db)
    assert scores['exploration'] == 0.5


def test_exploration_ignores_unrecognised_surface(db):
    for surface in [
        'GET /', 'GET /upload', 'POST /upload',
        'GET /photos/<int:photo_id>', 'GET /about', 'EXTRA',
    ]:
        write_event(db, 'exploration', surface)
    scores = get_scores(db)
    assert scores['exploration'] == CATEGORY_MAX_SCORES['exploration']  # 2.5, not 3.0


def test_reconnaissance_fires_at_its_weight(db):
    write_event(db, 'recon', 'GET /about')
    assert get_scores(db)['reconnaissance'] == 0.5


def test_vulnerability_detection_fires_at_its_weight(db):
    write_event(db, 'vuln_detect', 'disguised MVG upload')
    assert get_scores(db)['vulnerability_detection'] == 1


def test_exploitation_fires_at_its_weight(db):
    write_event(db, 'exploit', 'marker file found')
    assert get_scores(db)['exploitation'] == 2


def test_get_events_orders_most_recent_first(db):
    write_event(db, 'exploration', 'first')
    write_event(db, 'exploration', 'second')
    events = get_events(db)
    assert [e['detail'] for e in events] == ['second', 'first']


def test_get_exploration_surfaces_returns_distinct_set(db):
    write_event(db, 'exploration', 'GET /')
    write_event(db, 'exploration', 'GET /')
    write_event(db, 'exploration', 'GET /about')
    assert get_exploration_surfaces(db) == {'GET /', 'GET /about'}


def test_overall_max_score_is_sum_of_category_maxes(db):
    assert OVERALL_MAX_SCORE == sum(CATEGORY_MAX_SCORES.values())
