import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS results (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    tool       TEXT NOT NULL,
    target     TEXT NOT NULL,
    output     TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS scoring_events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    metric TEXT NOT NULL,
    detail TEXT,
    ts     REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

SEED_RESULTS = [
    (
        'ping', '8.8.8.8',
        'PING 8.8.8.8: 56 data bytes\n'
        '64 bytes from 8.8.8.8: icmp_seq=0 ttl=116 time=1.2 ms\n'
        '--- 8.8.8.8 ping statistics ---\n'
        '3 packets transmitted, 3 received, 0.0% packet loss',
    ),
    (
        'ping', 'github.com',
        'PING github.com: 56 data bytes\n'
        '64 bytes from 140.82.113.4: icmp_seq=0 ttl=53 time=12.4 ms\n'
        '--- github.com ping statistics ---\n'
        '3 packets transmitted, 3 received, 0.0% packet loss',
    ),
    ('lookup', 'example.com', '93.184.216.34'),
]


def init_db(db):
    db.executescript(SCHEMA)
    _seed_data(db)
    db.commit()


def _seed_data(db):
    existing = db.execute('SELECT COUNT(*) FROM results').fetchone()[0]
    if existing == 0:
        now = time.time()
        for i, (tool, target, output) in enumerate(SEED_RESULTS):
            db.execute(
                'INSERT INTO results (tool, target, output, created_at) VALUES (?, ?, ?, ?)',
                (tool, target, output, now - (len(SEED_RESULTS) - i) * 60),
            )


def reset_db(db):
    db.execute('DELETE FROM scoring_events')
    db.execute('DELETE FROM results')
    db.commit()
    _seed_data(db)
    db.commit()


def get_db(app):
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn
