# Orchestrator: Scoring, Reset, and Benchmark Mode — Plan

**Status: implemented.** This doc is the design reference `orchestrator.py` and `scoring.py`
were built against; see both files for the actual code.

## Goal

`orchestrator.py` currently only builds, launches, and stops Docker containers. Every one of the
11 built web apps already exposes `GET /score/<token>` (HTML dashboard + `?format=json`) and
`POST /score/<token>/reset`, but the orchestrator never calls either — after `run_container()`
prints the score URL/token once, that information is discarded. There is no way to check or reset
a running app's score, or to see progress across multiple apps at once, without manually curling
each container.

This closes that gap and adds a **benchmark mode** that launches every registered app and shows a
live, aggregated view of scoring progress across all of them, while a human runs the pentest
agent manually against each app's printed URL.

---

## Future direction (context, not being built now)

The longer-term intent is for this whole thing to become a cloud-orchestrated benchmark web app:
an orchestrator service running on one port, launching/managing benchmark app instances on other
ports, reachable over the network rather than driven from a local interactive CLI. This matches
the already-recorded hosted-platform design (multi-tenant hosting, GitHub OAuth, `POST
/instances` / `POST /runs` / `GET /runs/<id>` HTTP API, agent execution staying external) —
paper-design-only for the thesis timeline. The version built now is still the local CLI
orchestrator, not a web service.

The only thing this changes about the plan below: `scoring.py`'s functions are kept as plain
functions with no `questionary`/`print` calls inside them, returning data (dicts/lists) rather
than printing — `orchestrator.py`'s menu actions do all the CLI rendering on top. This is a
natural, low-cost way to write it anyway (easier to test, cleaner separation), and it happens to
mean that if/when an HTTP API is ever put in front of this logic, the scoring core doesn't need
to be rewritten — only a new caller (a route handler instead of a CLI menu action) needs to be
added. Nothing else about this plan changes to accommodate the future direction: no API server,
no auth, no multi-tenancy is being built now.

---

## Design decisions

- **Agent invocation is out of scope.** No automation of Claude Code CLI, no subprocess/process
  lifecycle management, no timeouts. The user runs the agent themselves in a separate terminal
  against each app's printed URL; the orchestrator's job is only to launch apps and report
  scores as they come in.
- **Four metrics stay separate**, never blended into one number — this preserves the stage-level
  partial-credit granularity that's the project's core scoring design (see main `CLAUDE.md` §
  Scoring Framework).
- **Live scoreboard auto-refreshes** on an interval until the user exits (Ctrl+C), rather than
  being a one-shot snapshot.
- Aggregation is **equal-weighted across apps** — no difficulty weighting, since the numeric
  difficulty-scoring formula is still in progress (see main `CLAUDE.md` § Difficulty Scoring
  Methodology).

---

## New capabilities

### 1. `orchestrator/scoring.py` (new file) — discovery, fetch, reset, aggregate

Keeps HTTP/aggregation logic separate from the CLI/menu layer in `orchestrator.py`.

- `discover_running_apps(apps: list[dict]) -> list[dict]`
  Calls the existing `get_running_containers()` (`orchestrator.py`) for the raw `docker ps` rows,
  then for each row:
  - Recovers the registry `app` dict by matching container name against known ids — container
    names are `benchmark-<id>-<8-hex-short-uuid>`, so strip the `benchmark-` prefix and the
    trailing `-{8 hex chars}` suffix to get `id` unambiguously (ids never end in 8 hex chars).
  - Parses the host port out of the `Ports` column (e.g. `0.0.0.0:8003->5000/tcp`) with a regex.
  - Runs `docker inspect <name> --format '{{json .Config.Env}}'` and pulls `SCORE_TOKEN=...` out
    of the env list — this is how the token is recovered even for containers launched in a
    *previous* orchestrator run, since nothing is persisted to disk today.
  Returns `[{"app": <registry dict>, "container_name": ..., "host_port": ..., "token": ...}, ...]`.

- `fetch_score(host_port, token, timeout=3) -> dict | None`
  `GET http://localhost:<port>/score/<token>?format=json` via `requests`. Returns the parsed
  `{"task_id", "scores": {exploration, reconnaissance, vulnerability_detection, exploitation},
  "events"}` payload (this shape is already standardized across all 11 apps — verified against
  `webapps/sqli-easy/app/routes.py` and `scoring.py`). Returns `None` on any connection error,
  timeout, or non-200 — callers must treat that as "not ready yet," not a crash, since no app has
  a Docker `HEALTHCHECK` and a just-launched container (the JVM app especially, once
  `deserialization-easy` is built) may not be accepting connections yet.

- `reset_score(host_port, token, timeout=3) -> bool`
  `POST .../score/<token>/reset`. Returns whether it succeeded (200).

- `aggregate_scores(rows: list[dict]) -> dict`
  Takes `discover_running_apps()` output paired with a `fetch_score()` result per row. For each
  of the 4 metric names, sums the fractional value across apps that responded successfully, and
  reports it as `"<sum> / <N running>"`. Also returns the per-app rows (for the breakdown table)
  and a count of apps that didn't respond, so the scoreboard can honestly show e.g. "9/11 apps
  responding" instead of silently scoring unreachable apps as 0.

### 2. New menu actions in `orchestrator.py`

- **`action_view_scoreboard(apps)`** — the live aggregate view. If nothing is running, says so
  and returns. Otherwise loops: re-run `discover_running_apps` + `fetch_score` per app (apps can
  come and go between ticks), clear the screen (`\033[2J\033[H`), print the 4 aggregate metric
  totals, then a per-app breakdown table (App | Explore | Recon | VulnDetect | Exploit | Status),
  sleep ~3s, repeat. `except KeyboardInterrupt` returns cleanly to the main menu instead of
  crashing the CLI.

- **`action_view_app_score(apps)`** — one-shot detail view for a single running app. New helper
  `choose_running_app()` (mirrors the existing `choose_app()` pattern but sources choices from
  `discover_running_apps()` instead of the static registry) picks the app; prints its 4 metrics
  plus the most recent events from the JSON payload's `events` list.

- **`action_reset_scores(apps)`** — checkbox multi-select over currently-running apps (same
  `questionary.checkbox` + "All running apps" shortcut pattern already used in
  `action_rebuild`), gated by a `questionary.confirm` prompt since reset clears scoring state and
  re-seeds app data. POSTs reset to each selected app via `reset_score()`.

- **`action_benchmark_mode(apps)`** — thin wrapper: calls the existing `action_launch_all(apps)`
  unchanged (reuses its build-missing-images-first flow and per-app `run_container()` calls),
  then immediately calls `action_view_scoreboard(apps)` so the user drops straight into the live
  view with every app's URL already printed above it from the launch step.

- **`action_stop_all()`** — bulk counterpart to the existing `action_stop()`, needed because
  benchmark mode launches everything at once. Confirms, then `stop_container()` (existing helper)
  on every row from `get_running_containers()`.

### 3. Menu wiring

Add to the `MENU` dict in `orchestrator.py`: "Benchmark mode (launch all + live scoreboard)",
"View benchmark scoreboard", "View single app score", "Reset app score(s)", "Stop all running
apps". Most take `apps` like existing entries; `action_stop_all` is zero-arg like the existing
`action_stop`, so it joins that special-case branch in `main()`'s dispatch loop.

### 4. New dependency

Add `requests` to `orchestrator/requirements.txt` (currently only `questionary`). Chosen over
stdlib `urllib` for simpler JSON decoding + per-call timeouts across the repeated polling the
scoreboard does every refresh tick.

---

## Files touched

- `webpen-arena/orchestrator/orchestrator.py` — new actions + menu wiring; reuses existing
  `get_running_containers()`, `run_container()`, `action_launch_all()`, `stop_container()`,
  `choose_app()`-style pattern.
- `webpen-arena/orchestrator/scoring.py` — new file (discovery/fetch/reset/aggregate).
- `webpen-arena/orchestrator/requirements.txt` — add `requests`.

No changes needed to any web app — the score/reset endpoints and JSON shape are already
standardized across the corpus.

---

## Out of scope

- No automated Claude Code CLI invocation, no subprocess management, no per-app timeouts.
- No difficulty-weighted aggregation.
- No results-export file (JSON/CSV) — this is a live view only, not a persisted run record. Could
  be added later as a separate feature to keep a history of benchmark runs.

---

## Verification (once implemented)

- `python orchestrator/orchestrator.py` still runs; existing menu items behave unchanged.
- With a couple of apps built: Benchmark mode → apps launch, URLs print, scoreboard appears and
  updates every ~3s; trigger a scoring event via `curl` against a launched app's vulnerable route
  and confirm the scoreboard's totals move within one refresh tick.
- Reset app score(s) → confirm prompt → totals drop back to 0 for the reset app(s) on the next
  tick.
- View single app score → its numbers match that app's row in the aggregate breakdown table.
- Stop all running apps → containers removed; scoreboard reports no running apps on next view.
- No app test suites are run as part of this — this only touches orchestrator tooling, not the
  benchmark web apps themselves.
