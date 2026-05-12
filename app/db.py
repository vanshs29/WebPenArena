import sqlite3
import time
import uuid

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    email    TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role     TEXT NOT NULL DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    description TEXT,
    price       REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS scoring_events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    metric  TEXT NOT NULL,
    detail  TEXT,
    ts      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

SEED_PRODUCTS = [
    ("Wireless Mouse", "Ergonomic 2.4GHz wireless mouse", 29.99),
    ("USB-C Hub", "7-in-1 USB-C hub with HDMI and SD card", 49.99),
    ("Mechanical Keyboard", "TKL mechanical keyboard with blue switches", 89.99),
]


def init_db(db):
    db.executescript(SCHEMA)
    _seed_config(db)
    _seed_data(db)
    db.commit()


def _seed_config(db):
    row = db.execute("SELECT value FROM config WHERE key='jwt_secret'").fetchone()
    if row is None:
        db.execute("INSERT INTO config (key, value) VALUES ('jwt_secret', ?)", (str(uuid.uuid4()),))


def _seed_data(db):
    # Plaintext passwords required: login uses string-interpolated SQL comparison
    # admin inserted first so id=1 — required for SQLi bypass to return admin row
    db.execute(
        "INSERT OR IGNORE INTO users (email, password, role) VALUES (?, ?, ?)",
        ("admin@shoplite.local", "S3cr3tAdmin!", "admin"),
    )
    db.execute(
        "INSERT OR IGNORE INTO users (email, password, role) VALUES (?, ?, ?)",
        ("user@shoplite.local", "password123", "user"),
    )
    for name, desc, price in SEED_PRODUCTS:
        db.execute(
            "INSERT OR IGNORE INTO products (name, description, price) VALUES (?, ?, ?)",
            (name, desc, price),
        )


def seed_db(db):
    _seed_config(db)
    _seed_data(db)
    db.commit()


def reset_db(app, db):
    db.execute("DELETE FROM scoring_events")
    db.execute("DELETE FROM users")
    db.execute("DELETE FROM products")
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
