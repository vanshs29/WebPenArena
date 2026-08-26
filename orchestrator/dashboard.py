"""
Benchmark mode web dashboard — Flask app serving a live scoreboard with launch/
reset/stop controls, replacing the old terminal scoreboard loop.

Kept as a thin HTTP layer over orchestrator.py's Docker helpers and scoring.py's
discovery/fetch/reset/aggregate functions — no scoring or Docker logic lives here.
"""

import logging
import sys
import webbrowser

try:
    from flask import Flask, jsonify, render_template
except ImportError:
    sys.exit("Missing dependency: pip install flask")

import scoring


def create_app(apps: list[dict]) -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index():
        return render_template("dashboard.html")

    @app.get("/api/scoreboard")
    def api_scoreboard():
        running = {row["app"]["id"]: row for row in scoring.discover_running_apps(apps)}

        entries = []
        for reg_app in apps:
            difficulty = scoring.difficulty_of(reg_app["id"])
            row = running.get(reg_app["id"])
            if row is None:
                entries.append({
                    "id": reg_app["id"],
                    "name": reg_app["name"],
                    "description": reg_app["description"],
                    "difficulty": difficulty,
                    "container_name": None,
                    "host_port": None,
                    "status": None,
                    "running": False,
                    "score": None,
                    "score_url": None,
                })
                continue

            score = scoring.fetch_score(row["host_port"], row["token"])
            entries.append({
                "id": reg_app["id"],
                "name": reg_app["name"],
                "description": reg_app["description"],
                "difficulty": difficulty,
                "container_name": row["container_name"],
                "host_port": row["host_port"],
                "status": row["status"],
                "running": True,
                "score": score,
                "score_url": f"http://localhost:{row['host_port']}/score/{row['token']}",
            })

        totals_by_difficulty = {}
        for tier in scoring.DIFFICULTIES:
            tier_entries = [e for e in entries if e["difficulty"] == tier]
            tier_agg = scoring.aggregate_scores(
                [{"app": e, "score": e["score"]} for e in tier_entries if e["running"]]
            )
            totals_by_difficulty[tier] = {
                "totals": tier_agg["totals"],
                "n_total": len(tier_entries),
                "n_responded": tier_agg["n_responded"],
            }

        agg = scoring.aggregate_scores([{"app": e, "score": e["score"]} for e in entries if e["running"]])

        return jsonify({
            "apps": entries,
            "totals": agg["totals"],
            "n_total": len(entries),
            "n_responded": agg["n_responded"],
            "totals_by_difficulty": totals_by_difficulty,
        })

    @app.post("/api/launch-all")
    def api_launch_all():
        from orchestrator import image_exists, build_image_data, run_container_data

        already_running = {row["app"]["id"] for row in scoring.discover_running_apps(apps)}

        launched, errors, skipped = [], [], []
        for reg_app in apps:
            if reg_app["id"] in already_running:
                skipped.append(reg_app["id"])
                continue
            if not image_exists(reg_app["image"]):
                build = build_image_data(reg_app)
                if not build["ok"]:
                    errors.append({
                        "id": reg_app["id"],
                        "error": "image build failed",
                        "stderr": build["stderr"],
                    })
                    continue
            info = run_container_data(reg_app)
            if info is None:
                errors.append({"id": reg_app["id"], "error": "docker run failed"})
            else:
                launched.append(info)

        return jsonify({"launched": launched, "errors": errors, "skipped": skipped})

    @app.post("/api/apps/<app_id>/launch")
    def api_launch_one(app_id):
        from orchestrator import image_exists, build_image_data, run_container_data

        reg_app = next((a for a in apps if a["id"] == app_id), None)
        if reg_app is None:
            return jsonify({"ok": False, "error": "unknown app"}), 404
        if _find_running(apps, app_id) is not None:
            return jsonify({"ok": False, "error": "already running"}), 409

        if not image_exists(reg_app["image"]):
            build = build_image_data(reg_app)
            if not build["ok"]:
                return jsonify({
                    "ok": False,
                    "error": "image build failed",
                    "stderr": build["stderr"],
                }), 500

        info = run_container_data(reg_app)
        if info is None:
            return jsonify({"ok": False, "error": "docker run failed"}), 500
        return jsonify({"ok": True, "info": info})

    @app.post("/api/rebuild-all")
    def api_rebuild_all():
        from orchestrator import build_image_data

        results = {}
        for reg_app in apps:
            results[reg_app["id"]] = build_image_data(reg_app)
        return jsonify({"results": results})

    @app.post("/api/apps/<app_id>/rebuild")
    def api_rebuild_one(app_id):
        from orchestrator import build_image_data

        reg_app = next((a for a in apps if a["id"] == app_id), None)
        if reg_app is None:
            return jsonify({"ok": False, "error": "unknown app"}), 404

        return jsonify(build_image_data(reg_app))

    @app.post("/api/apps/<app_id>/reset")
    def api_reset_one(app_id):
        row = _find_running(apps, app_id)
        if row is None:
            return jsonify({"ok": False, "error": "not running"}), 404
        ok = scoring.reset_score(row["host_port"], row["token"])
        return jsonify({"ok": ok})

    @app.post("/api/reset-all")
    def api_reset_all():
        results = {}
        for row in scoring.discover_running_apps(apps):
            results[row["app"]["id"]] = scoring.reset_score(row["host_port"], row["token"])
        return jsonify({"results": results})

    @app.post("/api/apps/<app_id>/stop")
    def api_stop_one(app_id):
        from orchestrator import stop_container_data

        row = _find_running(apps, app_id)
        if row is None:
            return jsonify({"ok": False, "error": "not running"}), 404
        ok = stop_container_data(row["container_name"])
        return jsonify({"ok": ok})

    @app.post("/api/stop-all")
    def api_stop_all():
        from orchestrator import stop_container_data

        stopped, errors = [], []
        for row in scoring.discover_running_apps(apps):
            if stop_container_data(row["container_name"]):
                stopped.append(row["app"]["id"])
            else:
                errors.append(row["app"]["id"])
        return jsonify({"stopped": stopped, "errors": errors})

    return app


def _find_running(apps: list[dict], app_id: str) -> dict | None:
    for row in scoring.discover_running_apps(apps):
        if row["app"]["id"] == app_id:
            return row
    return None


def run_dashboard(apps: list[dict]) -> None:
    from orchestrator import docker_available, find_free_port

    if not docker_available():
        sys.exit(
            "[error] Docker is not available. Make sure Docker is installed and the "
            "daemon is running, then try again."
        )

    import flask.cli
    flask.cli.show_server_banner = lambda *a, **kw: None
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    # Dedicated range, distinct from the 8000+ range app containers use, so the
    # dashboard's own port never competes with (or gets mistaken for) a benchmark
    # app's port.
    port = find_free_port(start=3000, end=4000)
    url = f"http://127.0.0.1:{port}/"
    print(f"\n[dashboard] {url}  (Ctrl+C to stop)\n")

    app = create_app(apps)
    webbrowser.open(url)

    try:
        app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False, threaded=True)
    except KeyboardInterrupt:
        print("\n[dashboard] Stopped.")
