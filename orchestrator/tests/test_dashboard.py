from pathlib import Path

import dashboard
import orchestrator
import report
import scoring


def _apps():
    return [{
        "id": "sqli-easy", "name": "ShopLite", "description": "d",
        "path": "webapps/sqli-easy", "image": "benchmark/sqli-easy", "container_port": 5000,
    }]


def _mixed_tier_apps():
    return [
        {
            "id": "sqli-easy", "name": "ShopLite", "description": "d",
            "path": "webapps/sqli-easy", "image": "benchmark/sqli-easy", "container_port": 5000,
        },
        {
            "id": "idor-easy", "name": "NoteNest", "description": "d",
            "path": "webapps/idor-easy", "image": "benchmark/idor-easy", "container_port": 3000,
        },
        {
            "id": "sqli-medium", "name": "TalentHub", "description": "d",
            "path": "webapps/sqli-medium", "image": "benchmark/sqli-medium", "container_port": 5000,
        },
    ]


def test_api_report_writes_files_and_returns_markdown(tmp_path, monkeypatch):
    monkeypatch.setattr(scoring, "discover_running_apps", lambda apps: [])
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path)

    client = dashboard.create_app(_apps()).test_client()
    resp = client.post("/api/report", json={"label": "trial-1"})

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert "ShopLite" in data["markdown"]

    md_path = Path(data["md_path"])
    json_path = Path(data["json_path"])
    assert md_path.exists()
    assert json_path.exists()
    assert md_path.parent == tmp_path


def test_api_report_without_label_still_succeeds(tmp_path, monkeypatch):
    monkeypatch.setattr(scoring, "discover_running_apps", lambda apps: [])
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path)

    client = dashboard.create_app(_apps()).test_client()
    resp = client.post("/api/report", json={})

    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True


def test_api_report_with_no_body_still_succeeds(tmp_path, monkeypatch):
    monkeypatch.setattr(scoring, "discover_running_apps", lambda apps: [])
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path)

    client = dashboard.create_app(_apps()).test_client()
    resp = client.post("/api/report")

    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True


def test_api_launch_tier_only_launches_apps_in_that_tier(monkeypatch):
    monkeypatch.setattr(scoring, "discover_running_apps", lambda apps: [])
    monkeypatch.setattr(orchestrator, "image_exists", lambda image: True)
    monkeypatch.setattr(orchestrator, "build_image_data", lambda app: {"ok": True, "stderr": ""})

    launched_ids = []

    def fake_run(app):
        launched_ids.append(app["id"])
        return {"id": app["id"], "container_name": f"benchmark-{app['id']}-abc"}

    monkeypatch.setattr(orchestrator, "run_container_data", fake_run)

    client = dashboard.create_app(_mixed_tier_apps()).test_client()
    resp = client.post("/api/launch-tier/easy")

    assert resp.status_code == 200
    data = resp.get_json()
    assert sorted(launched_ids) == ["idor-easy", "sqli-easy"]
    assert sorted(entry["id"] for entry in data["launched"]) == ["idor-easy", "sqli-easy"]
    assert data["errors"] == []
    assert data["skipped"] == []


def test_api_launch_tier_skips_already_running_apps_in_that_tier(monkeypatch):
    apps = _mixed_tier_apps()
    already_running = [{"app": apps[0]}]  # sqli-easy already running
    monkeypatch.setattr(scoring, "discover_running_apps", lambda a: already_running)
    monkeypatch.setattr(orchestrator, "image_exists", lambda image: True)
    monkeypatch.setattr(orchestrator, "build_image_data", lambda app: {"ok": True, "stderr": ""})

    launched_ids = []

    def fake_run(app):
        launched_ids.append(app["id"])
        return {"id": app["id"], "container_name": f"benchmark-{app['id']}-abc"}

    monkeypatch.setattr(orchestrator, "run_container_data", fake_run)

    client = dashboard.create_app(apps).test_client()
    resp = client.post("/api/launch-tier/easy")

    data = resp.get_json()
    assert launched_ids == ["idor-easy"]
    assert data["skipped"] == ["sqli-easy"]


def test_api_launch_tier_rejects_unknown_tier():
    client = dashboard.create_app(_mixed_tier_apps()).test_client()
    resp = client.post("/api/launch-tier/bogus")

    assert resp.status_code == 400
    assert resp.get_json()["ok"] is False


def test_api_launch_tier_reports_build_errors(monkeypatch):
    monkeypatch.setattr(scoring, "discover_running_apps", lambda apps: [])
    monkeypatch.setattr(orchestrator, "image_exists", lambda image: False)
    monkeypatch.setattr(
        orchestrator, "build_image_data",
        lambda app: {"ok": False, "stderr": "boom"},
    )

    client = dashboard.create_app(_mixed_tier_apps()).test_client()
    resp = client.post("/api/launch-tier/easy")

    data = resp.get_json()
    assert {e["id"] for e in data["errors"]} == {"sqli-easy", "idor-easy"}
    assert all(e["stderr"] == "boom" for e in data["errors"])
