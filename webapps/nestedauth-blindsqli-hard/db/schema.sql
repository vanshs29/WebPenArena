CREATE TABLE IF NOT EXISTS organizations (
  id SERIAL PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  is_seed BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS members (
  id SERIAL PRIMARY KEY,
  org_id INTEGER NOT NULL REFERENCES organizations(id),
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'member'
);

CREATE TABLE IF NOT EXISTS platform_admins (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
  id SERIAL PRIMARY KEY,
  member_id INTEGER NOT NULL REFERENCES members(id),
  label TEXT NOT NULL,
  key TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS teams (
  id SERIAL PRIMARY KEY,
  org_id INTEGER NOT NULL REFERENCES organizations(id),
  name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS integrations (
  id SERIAL PRIMARY KEY,
  team_id INTEGER NOT NULL REFERENCES teams(id),
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  credentials TEXT NOT NULL,
  is_marketplace_listed BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS incidents (
  id SERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'minor',
  status TEXT NOT NULL DEFAULT 'resolved',
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  is_platform_wide BOOLEAN NOT NULL DEFAULT FALSE,
  postmortem_notes TEXT
);

CREATE TABLE IF NOT EXISTS incident_participants (
  incident_id INTEGER NOT NULL REFERENCES incidents(id),
  org_id INTEGER NOT NULL REFERENCES organizations(id),
  PRIMARY KEY (incident_id, org_id)
);

CREATE TABLE IF NOT EXISTS status_subscribers (
  id SERIAL PRIMARY KEY,
  email TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scoring_events (
  id SERIAL PRIMARY KEY,
  metric TEXT NOT NULL,
  detail TEXT,
  ts DOUBLE PRECISION NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS scoring_events_dedup_idx
  ON scoring_events (metric, COALESCE(detail, ''));
