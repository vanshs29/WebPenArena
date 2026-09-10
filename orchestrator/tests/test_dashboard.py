from pathlib import Path

import dashboard
import report
import scoring


def _apps():
    return [{
        "id": "sqli-easy", "name": "ShopLite", "description": "d",
        "path": "webapps/sqli-easy", "image": "benchmark/sqli-easy", "container_port": 5000,
    }]


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
