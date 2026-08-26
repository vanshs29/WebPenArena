# Orchestrator Improvements — Proposed

**Status: items 1–4 implemented (25 August 2026, 26 August 2026); items 5–6 still proposed, not yet built.**
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

## 2. Build failures are silently swallowed — IMPLEMENTED 26 August 2026

`build_image_data()` (`orchestrator.py:65-74`) ran `docker build` with `capture_output=True`
and returned only `True`/`False`; stderr was discarded. When a rebuild failed via the web
dashboard, the user got a red "FAILED" with no diagnostic at all. Given how build-fragile this
corpus already is (Node ABI breaks, JDK-vs-JRE, the sandbox's `ignore-scripts`/`bin-links`
npmrc gotchas documented in the main `CLAUDE.md`), losing the error text was the difference
between a fast fix and a guess-and-rerun loop.

**Fix applied:** `build_image_data()` now returns `{"ok": bool, "stderr": str}` — the last 4000
chars of `docker build`'s stderr, populated only on failure. All four dashboard endpoints that
call it (`/api/launch-all`, `/api/apps/<id>/launch`, `/api/rebuild-all`,
`/api/apps/<id>/rebuild`) thread `stderr` through into their JSON responses. The frontend
(`dashboard.js`/`.html`/`.css`) adds a dismissible "Build errors" panel above the tier tabs:
each failed build/launch appends an entry (app id, timestamp, scrollable `<pre>` of the stderr
tail), capped at the last 20, with a "Clear" button. Verified by simulating a `docker build`
against a deliberately broken Dockerfile (`RUN this-command-does-not-exist`) and confirming the
captured stderr tail contains the actual Docker/shell error text. `build_image()` (the CLI's
streamed version) was left untouched — the user already sees live output in the terminal there.

---

## 3. Port selection has a real TOCTOU race — IMPLEMENTED 26 August 2026

`find_free_port()` (`orchestrator.py:41-50`) binds a socket, closes it immediately, and returns
the port number; `run_container_data()` calls `docker run` afterward, sometimes seconds later
(build-then-launch paths). Two near-simultaneous launches (two dashboard tabs, or a manual CLI
launch racing the dashboard's launch-all) can both observe the same free port before either
container's `-p` binding actually lands, since nothing is holding the port open between the
check and the `docker run` call. When it hits, `docker run` fails opaquely.

**Fix applied:** `run_container_data()` now loops up to twice: each attempt picks a fresh port,
token, and container name, and only returns `None` if `docker run` fails on the second attempt
too. Verified by holding a specific host port with a throwaway container, monkeypatching
`find_free_port()` to hand back that busy port on the first call, and confirming
`run_container_data()` transparently retried with a real free port and succeeded on the second
attempt. No port-reservation mechanism was added — the retry is cheap and closes the race in
practice, per the original proposal.

---

## 4. No preflight check that Docker itself is available — IMPLEMENTED 26 August 2026

Every Docker-calling function assumes the `docker` binary exists and the daemon is running. If
it isn't, `subprocess.run(["docker", ...])` either raises `FileNotFoundError` (uncaught,
surfaces as a raw traceback) or returns a nonzero code that callers like `image_exists()`
quietly interpret as "image not found," leading into a confusing "build it now?" prompt for a
problem that isn't actually about the image.

**Fix applied:** added `docker_available()` (`orchestrator.py`) — runs `docker info`, catching
`FileNotFoundError` for a missing binary and treating any nonzero exit (daemon not running) as
unavailable too. Called at the top of `main()` (CLI) and `dashboard.run_dashboard()` (web),
each `sys.exit`-ing with a clear one-line message instead of a confusing image-build prompt or a
raw traceback. Verified directly: a real running daemon returns `True`; monkeypatching
`subprocess.run` to raise `FileNotFoundError` or to return a nonzero-code result both correctly
return `False`; both `main()` and `run_dashboard()` were confirmed to exit cleanly with the
intended message when `docker_available()` reports unavailable.

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
