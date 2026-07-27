import os
import sqlite3

import pytest

from app.db import get_db, init_db, reset_db, SEED_FILENAMES

SEEDS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'app', 'seeds')


@pytest.fixture
def db(tmp_path):
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


@pytest.fixture
def upload_dir(tmp_path):
    d = tmp_path / 'uploads'
    d.mkdir()
    return str(d)


def test_init_db_creates_photos_table(db, upload_dir):
    init_db(db, upload_dir, SEEDS_DIR)
    rows = db.execute('SELECT * FROM photos').fetchall()
    assert len(rows) == len(SEED_FILENAMES)


def test_init_db_creates_scoring_events_table(db, upload_dir):
    init_db(db, upload_dir, SEEDS_DIR)
    rows = db.execute('SELECT * FROM scoring_events').fetchall()
    assert rows == []


def test_init_db_copies_seed_images_into_upload_dir(db, upload_dir):
    init_db(db, upload_dir, SEEDS_DIR)
    for name in SEED_FILENAMES:
        assert os.path.isfile(os.path.join(upload_dir, name))


def test_init_db_is_idempotent(db, upload_dir):
    init_db(db, upload_dir, SEEDS_DIR)
    init_db(db, upload_dir, SEEDS_DIR)
    rows = db.execute('SELECT * FROM photos').fetchall()
    assert len(rows) == len(SEED_FILENAMES)


def test_reset_db_clears_scoring_events(db, upload_dir):
    init_db(db, upload_dir, SEEDS_DIR)
    db.execute("INSERT INTO scoring_events (metric, detail, ts) VALUES ('exploration', 'GET /', 1.0)")
    db.commit()
    reset_db(db, upload_dir, SEEDS_DIR, os.path.join(upload_dir, 'marker'))
    rows = db.execute('SELECT * FROM scoring_events').fetchall()
    assert rows == []


def test_reset_db_clears_uploaded_photos_and_reseeds(db, upload_dir):
    init_db(db, upload_dir, SEEDS_DIR)
    db.execute(
        "INSERT INTO photos (filename, thumb_filename, uploaded_at) VALUES ('evil.png', NULL, 2.0)"
    )
    db.commit()
    reset_db(db, upload_dir, SEEDS_DIR, os.path.join(upload_dir, 'marker'))
    rows = db.execute('SELECT filename FROM photos').fetchall()
    filenames = {r['filename'] for r in rows}
    assert filenames == set(SEED_FILENAMES)


def test_reset_db_removes_exploit_marker_file(db, upload_dir):
    init_db(db, upload_dir, SEEDS_DIR)
    marker_path = os.path.join(upload_dir, 'marker')
    with open(marker_path, 'w') as f:
        f.write('')
    assert os.path.exists(marker_path)
    reset_db(db, upload_dir, SEEDS_DIR, marker_path)
    assert not os.path.exists(marker_path)


def test_reset_db_without_existing_marker_file_does_not_error(db, upload_dir):
    init_db(db, upload_dir, SEEDS_DIR)
    marker_path = os.path.join(upload_dir, 'marker')
    reset_db(db, upload_dir, SEEDS_DIR, marker_path)
    assert not os.path.exists(marker_path)
