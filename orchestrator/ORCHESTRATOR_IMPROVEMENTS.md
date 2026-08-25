# Orchestrator Improvements — Proposed

**Status: item 1 implemented (25 August 2026); items 2–6 still proposed, not yet built.**
Findings from a read-through of `orchestrator.py`, `dashboard.py`, `scoring.py`,
`registry.json`, and the dashboard frontend on 25 August 2026. This is a prioritized list to
work from, not a design doc for a single feature the way `ORCHESTRATOR_PLAN.md` /
`BENCHMARK_MODE_PLAN.md` are.

Ordered by impact, highest first.

---

## 1. Dashboard freezes for everyone during any build — IMPLEMENTED 25 August 2026

`dashboard.py:197` called `app.run(host="127.0.0.1", port=port, debug=False,
use_reloader=False)` with no `threaded=True`. Flask's dev server handles one request at a time
by default. `static/dashboard.js:202` polls `GET /api/scoreboard` every 2s, but
`api_rebuild_all` / `api_rebuild_one` / `api_launch_all` (`dashboard.py:71-130`) run `docker
build` synchronously inside the request handler. Several images in this corpus take minutes to
build (`deserialization-easy`'s Gradle+JDK build, `clickjacking-easy`'s Playwright+Chromium
image). During that window the whole dashboard was unresponsive: no scoreboard updates, no other
button worked, for every open tab, until the build finished.

**Fix applied:** added `threaded=True` to the `app.run()` call in `run_dashboard()`
(`dashboard.py`) — the minimum, one-line fix this item called for. Verified with a live
`werkzeug.serving.make_server(..., threaded=True)` test: a concurrent fast request no longer
waits on a slow one in flight. The "better long-term" alternative below (background
build thread/queue + a build-status endpoint the frontend polls, instead of the request
that kicked the build off) is **not implemented** — `threaded=True` means concurrent requests
no longer block each other, but a rebuild's own request/response cycle (and the "Working…"
button state tied to it in `dashboard.js`) still spans the full build duration.

---

## 2. Build failures are silently swallowed

`build_image_data()` (`orchestrator.py:65-74`) runs `docker build` with `capture_output=True`
and returns only `True`/`False`; stderr is discarded. When a rebuild fails via the web
dashboard, the user gets a red "FAILED" with no diagnostic at all. Given how build-fragile this
corpus already is (Node ABI breaks, JDK-vs-JRE, the sandbox's `ignore-scripts`/`bin-links`
npmrc gotchas documented in the main `CLAUDE.md`), losing the error text is the difference
between a fast fix and a guess-and-rerun loop.

**Fix:** return `result.stderr` (or the tail of it) alongside the boolean, and surface it in the
dashboard's event log or a dedicated error panel. The CLI's `build_image()` already streams
output live and doesn't need this.

---

## 3. Port selection has a real TOCTOU race

`find_free_port()` (`orchestrator.py:41-50`) binds a socket, closes it immediately, and returns
the port number; `run_container_data()` calls `docker run` afterward, sometimes seconds later
(build-then-launch paths). Two near-simultaneous launches (two dashboard tabs, or a manual CLI
launch racing the dashboard's launch-all) can both observe the same free port before either
container's `-p` binding actually lands, since nothing is holding the port open between the
check and the `docker run` call. When it hits, `docker run` fails opaquely.

**Fix:** on `docker run` failure in `run_container_data()`, retry once with a freshly picked
port instead of returning `None` outright. Cheap, and closes the race in practice without
needing a port-reservation mechanism.

---

## 4. No preflight check that Docker itself is available

Every Docker-calling function assumes the `docker` binary exists and the daemon is running. If
it isn't, `subprocess.run(["docker", ...])` either raises `FileNotFoundError` (uncaught,
surfaces as a raw traceback) or returns a nonzero code that callers like `image_exists()`
quietly interpret as "image not found," leading into a confusing "build it now?" prompt for a
problem that isn't actually about the image.

**Fix:** one check at the top of `main()` (CLI) and `run_dashboard()` (web), e.g. `docker info`,
with a clear message if it fails. Worth doing since this tool is meant to be handed to whoever
is running baseline agents, not just the person who wrote it.

---

## 5. CLI and web dashboard duplicate "what's running," and the CLI version is worse

`action_show_running` / `action_stop` / `action_stop_all` (`orchestrator.py:255-300`) call the
raw `get_running_containers()`: container name, ports, status only. The web dashboard's
`scoring.discover_running_apps()` (`scoring.py:39-74`) cross-references the registry and
recovers the app name, description, and score token from the same `docker ps` data. The CLI's
stop/show menus could call `scoring.discover_running_apps(apps)` instead and show app names
("ShopLite — running on :8003") rather than raw `benchmark-sqli-easy-a1b2c3d4` container
strings.

**Fix:** route the CLI's show/stop actions through `scoring.discover_running_apps()`. Removes
duplicate logic, keeps one source of truth, and matches the dashboard's UX.

---

## 6. Registry has no structured OWASP/difficulty/weight fields

`registry.json` only carries a free-text `description` string (e.g. `"OWASP A03:2021 — SQL
Injection (Easy)"`). Per the main `CLAUDE.md`'s Remaining Gaps item 2, the next concrete
methodology step is retrofitting every app with HTB-style 0.5/1/2 subtask weights, then
tercile-sorting the finished corpus into easy/medium/hard by overall score. Right now there is
nowhere in the orchestrator to store or surface that once it's computed; it would have to be
scraped back out of description strings or recomputed ad hoc.

**Fix:** add `owasp_category`, `design_difficulty`, and (once the weighting pass is done)
`overall_score` / `computed_tier` as real fields on each registry entry, so the dashboard can
eventually display and sort by them instead of bolting this on separately later.

---

## Not included here

Smaller/lower-confidence observations from the same read-through that weren't written up as
findings: hardcoded `find_free_port` range (8000-9000) could collide with other local dev
services; no `docker` Python SDK is used anywhere (intentional, subprocess + CLI is simpler and
matches `ORCHESTRATOR_PLAN.md`'s original decision, not a problem); no persisted history of past
benchmark runs (explicitly out of scope per `BENCHMARK_MODE_PLAN.md`'s "Out of scope" section).
