import sqlite3

import bcrypt

REAL_PASSWORD = 'Welcome123!'
TARGET_USERNAME = 'mito'

SCHEMA = """
CREATE TABLE IF NOT EXISTS dev_accounts (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT NOT NULL,
    succeeded INTEGER NOT NULL,
    ts        REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS scoring_events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    metric TEXT NOT NULL,
    detail TEXT,
    ts     REAL NOT NULL
);
"""


def init_db(db):
    db.executescript(SCHEMA)
    _seed_data(db)
    db.commit()


def _seed_data(db):
    existing = db.execute('SELECT COUNT(*) FROM dev_accounts').fetchone()[0]
    if existing == 0:
        password_hash = bcrypt.hashpw(REAL_PASSWORD.encode(), bcrypt.gensalt()).decode()
        db.execute(
            'INSERT INTO dev_accounts (username, password_hash) VALUES (?, ?)',
            (TARGET_USERNAME, password_hash),
        )


def reset_db(db):
    db.execute('DELETE FROM scoring_events')
    db.execute('DELETE FROM login_attempts')
    db.execute('DELETE FROM dev_accounts')
    db.commit()
    _seed_data(db)
    db.commit()


def get_db(app):
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn
