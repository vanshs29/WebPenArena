import sqlite3
import time
import uuid

import bcrypt

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS contacts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name  TEXT NOT NULL,
    email      TEXT NOT NULL,
    company    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS campaigns (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id   INTEGER NOT NULL,
    subject    TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_at REAL NOT NULL
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
    ("alice@blastcraft.local", "Password123!"),
    ("bob@blastcraft.local", "Password456!"),
]

SEED_CONTACTS = [
    ("Jordan", "Lee", "jordan.lee@example.com", "Example Co"),
    ("Priya", "Nair", "priya.nair@example.com", "Northwind Traders"),
    ("Sam", "Osei", "sam.osei@example.com", "Globex"),
]

SAMPLE_CONTACT = {
    "first_name": "Jordan",
    "last_name": "Lee",
    "email": "jordan.lee@example.com",
    "company": "Example Co",
}


def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _seed_config(db):
    row = db.execute("SELECT value FROM config WHERE key='jwt_secret'").fetchone()
    if row is None:
        db.execute(
            "INSERT INTO config (key, value) VALUES ('jwt_secret', ?)",
            (str(uuid.uuid4()),),
        )


def _seed_data(db):
    for email, password in SEED_USERS:
        db.execute(
            "INSERT OR IGNORE INTO users (email, password_hash) VALUES (?, ?)",
            (email, _hash(password)),
        )

    if db.execute("SELECT COUNT(*) FROM contacts").fetchone()[0] == 0:
        for first_name, last_name, email, company in SEED_CONTACTS:
            db.execute(
                "INSERT INTO contacts (first_name, last_name, email, company) VALUES (?, ?, ?, ?)",
                (first_name, last_name, email, company),
            )


def init_db(db):
    db.executescript(SCHEMA)
    _seed_config(db)
    _seed_data(db)
    db.commit()


def reset_db(app, db):
    db.execute("DELETE FROM scoring_events")
    db.execute("DELETE FROM campaigns")
    db.execute("DELETE FROM contacts")
    db.execute("DELETE FROM users")
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
