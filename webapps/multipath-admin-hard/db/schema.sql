CREATE TABLE IF NOT EXISTS workspaces (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT UNIQUE NOT NULL,
    is_seed       INTEGER NOT NULL DEFAULT 0,
    settings_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    email        TEXT UNIQUE NOT NULL,
    password     TEXT NOT NULL,
    role         TEXT NOT NULL DEFAULT 'member'
);

CREATE TABLE IF NOT EXISTS tickets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    subject      TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'open',
    assignee_id  INTEGER REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS saved_views (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id),
    name          TEXT NOT NULL,
    filter_string TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS telemetry_reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    marker      TEXT NOT NULL,
    reported_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS scoring_events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    metric TEXT NOT NULL,
    detail TEXT,
    ts     REAL NOT NULL
);
