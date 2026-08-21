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
            row = running.get(reg_app["id"])
            if row is None:
                entries.append({
                    "id": reg_app["id"],
                    "name": reg_app["name"],
                    "description": reg_app["description"],
                    "container_name": None,
                    "host_port": None,
                    "status": None,
                    "running": False,
                    "score": None,
                })
                continue

            score = scoring.fetch_score(row["host_port"], row["token"])
            entries.append({
                "id": reg_app["id"],
                "name": reg_app["name"],
                "description": reg_app["description"],
                "container_name": row["container_name"],
                "host_port": row["host_port"],
                "status": row["status"],
                "running": True,
                "score": score,
            })

        agg = scoring.aggregate_scores([{"app": e, "score": e["score"]} for e in entries if e["running"]])

        return jsonify({
            "apps": entries,
            "totals": agg["totals"],
            "n_total": len(entries),
            "n_responded": agg["n_responded"],
        })

    @app.post("/api/launch-all")
    def api_launch_all():
        from orchestrator import image_exists, build_image_data, run_container_data

        launched, errors = [], []
        for reg_app in apps:
            if not image_exists(reg_app["image"]):
                if not build_image_data(reg_app):
                    errors.append({"id": reg_app["id"], "error": "image build failed"})
                    continue
            info = run_container_data(reg_app)
            if info is None:
                errors.append({"id": reg_app["id"], "error": "docker run failed"})
            else:
                launched.append(info)

        return jsonify({"launched": launched, "errors": errors})

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
    from orchestrator import find_free_port

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
        app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print("\n[dashboard] Stopped.")
