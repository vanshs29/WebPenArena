import sqlite3
import time
import uuid

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email    TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role     TEXT NOT NULL DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS jobs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    department  TEXT NOT NULL,
    description TEXT NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS applications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    job_id     INTEGER NOT NULL,
    status     TEXT NOT NULL DEFAULT 'pending',
    applied_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scoring_events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    metric TEXT NOT NULL,
    detail TEXT,
    ts     REAL NOT NULL
);
"""

SEED_USERS = [
    # admin must be id=1; OR-tautology returns first row
    ("admin", "admin@talenthub.local", "Xk9$mP2#qL7vR4nZ", "admin"),
    ("alice", "alice@talenthub.local", "password123", "user"),
    ("bob",   "bob@talenthub.local",   "password456", "user"),
]

SEED_JOBS = [
    ("Software Engineer", "Engineering",       "Build and maintain core platform services."),
    ("HR Specialist",     "People & Culture",  "Support talent acquisition and employee relations."),
    ("Product Manager",   "Product",           "Drive product roadmap and cross-team alignment."),
]


def init_db(db):
    db.executescript(SCHEMA)
    _seed_config(db)
    _seed_data(db)
    db.commit()


def _seed_config(db):
    row = db.execute("SELECT value FROM config WHERE key='jwt_secret'").fetchone()
    if row is None:
        db.execute(
            "INSERT INTO config (key, value) VALUES ('jwt_secret', ?)",
            (str(uuid.uuid4()),),
        )


def _seed_data(db):
    for username, email, password, role in SEED_USERS:
        db.execute(
            "INSERT OR IGNORE INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
            (username, email, password, role),
        )

    for title, dept, desc in SEED_JOBS:
        db.execute(
            "INSERT OR IGNORE INTO jobs (title, department, description) VALUES (?, ?, ?)",
            (title, dept, desc),
        )

    # Seed applications only if none exist
    if db.execute("SELECT COUNT(*) FROM applications").fetchone()[0] == 0:
        alice = db.execute("SELECT id FROM users WHERE username='alice'").fetchone()
        bob   = db.execute("SELECT id FROM users WHERE username='bob'").fetchone()
        swe   = db.execute("SELECT id FROM jobs WHERE title='Software Engineer'").fetchone()
        hr    = db.execute("SELECT id FROM jobs WHERE title='HR Specialist'").fetchone()
        if alice and swe:
            db.execute(
                "INSERT INTO applications (user_id, job_id, status, applied_at) VALUES (?, ?, ?, ?)",
                (alice["id"], swe["id"], "pending", time.time()),
            )
        if bob and hr:
            db.execute(
                "INSERT INTO applications (user_id, job_id, status, applied_at) VALUES (?, ?, ?, ?)",
                (bob["id"], hr["id"], "pending", time.time()),
            )


def seed_db(db):
    _seed_config(db)
    _seed_data(db)
    db.commit()


def reset_db(app, db):
    db.execute("DELETE FROM scoring_events")
    db.execute("DELETE FROM applications")
    db.execute("DELETE FROM users")
    db.execute("DELETE FROM jobs")
    db.execute("DELETE FROM config")
    db.commit()
    new_secret = str(uuid.uuid4())
    db.execute("INSERT INTO config (key, value) VALUES ('jwt_secret', ?)", (new_secret,))
    _seed_data(db)
    db.commit()
    app.config["JWT_SECRET"] = new_secret
    return new_secret


def get_db(app):
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    return conn
