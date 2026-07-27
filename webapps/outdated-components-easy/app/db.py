import os
import shutil
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS photos (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    filename       TEXT NOT NULL,
    thumb_filename TEXT,
    uploaded_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS scoring_events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    metric TEXT NOT NULL,
    detail TEXT,
    ts     REAL NOT NULL
);
"""

SEED_FILENAMES = ['sample1.png', 'sample2.png', 'sample3.png']


def init_db(db, upload_dir, seeds_dir):
    db.executescript(SCHEMA)
    _seed_data(db, upload_dir, seeds_dir)
    db.commit()


def _seed_data(db, upload_dir, seeds_dir):
    existing = db.execute('SELECT COUNT(*) FROM photos').fetchone()[0]
    if existing > 0:
        return
    import time
    now = time.time()
    for i, name in enumerate(SEED_FILENAMES):
        dest = os.path.join(upload_dir, name)
        if not os.path.isfile(dest):
            shutil.copyfile(os.path.join(seeds_dir, name), dest)
        db.execute(
            'INSERT INTO photos (filename, thumb_filename, uploaded_at) VALUES (?, ?, ?)',
            (name, name, now - (len(SEED_FILENAMES) - i) * 60),
        )


def reset_db(db, upload_dir, seeds_dir, marker_path):
    db.execute('DELETE FROM scoring_events')
    db.execute('DELETE FROM photos')
    db.commit()
    if os.path.exists(marker_path):
        os.remove(marker_path)
    _seed_data(db, upload_dir, seeds_dir)
    db.commit()


def get_db(app):
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn
