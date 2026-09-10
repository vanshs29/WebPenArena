import json

import report
import scoring


def _entry(id_, difficulty, running, score):
    return {
        "id": id_, "name": id_, "description": "d", "difficulty": difficulty,
        "container_name": None, "host_port": None, "status": None,
        "running": running, "score": score, "score_url": None,
    }


def _sample_report():
    entries = [
        _entry("sqli-easy", "easy", True, {"scores": {
            "exploration": 1.0, "reconnaissance": 0.5,
            "vulnerability_detection": 0.0, "exploitation": 0.0,
        }}),
        _entry("sqli-medium", "medium", False, None),
    ]
    zero_totals = {m: {"achieved": 0.0, "max": 0.0} for m in scoring.METRICS}
    return {
        "label": "trial-1",
        "generated_at": "2026-09-10T12:00:00+00:00",
        "totals": {
            "exploration": {"achieved": 1.0, "max": 1.0},
            "reconnaissance": {"achieved": 0.5, "max": 1.0},
            "vulnerability_detection": {"achieved": 0.0, "max": 1.0},
            "exploitation": {"achieved": 0.0, "max": 1.0},
        },
        "n_total": 2,
        "n_responded": 1,
        "totals_by_difficulty": {
            "easy": {"totals": zero_totals, "n_total": 1, "n_responded": 1},
            "medium": {"totals": zero_totals, "n_total": 1, "n_responded": 0},
            "hard": {"totals": zero_totals, "n_total": 0, "n_responded": 0},
        },
        "apps": entries,
    }


def test_build_report_with_no_apps_is_empty(monkeypatch):
    monkeypatch.setattr(scoring, "build_entries", lambda apps: [])

    data = report.build_report([], label="trial-1")

    assert data["label"] == "trial-1"
    assert "generated_at" in data
    assert data["n_total"] == 0
    assert data["n_responded"] == 0
    assert data["apps"] == []


def test_build_report_aggregates_running_and_non_running_apps(monkeypatch):
    entries = [
        _entry("sqli-easy", "easy", True, {"scores": {
            "exploration": 1.0, "reconnaissance": 0.0,
            "vulnerability_detection": 0.0, "exploitation": 0.0,
        }}),
        _entry("sqli-medium", "medium", False, None),
    ]
    monkeypatch.setattr(scoring, "build_entries", lambda apps: entries)

    data = report.build_report(["sqli-easy", "sqli-medium"], label=None)

    assert data["label"] is None
    assert data["n_total"] == 2
    assert data["n_responded"] == 1
    assert data["totals"]["exploration"] == {"achieved": 1.0, "max": 1.0}
    assert data["totals_by_difficulty"]["easy"]["n_responded"] == 1
    assert data["totals_by_difficulty"]["medium"]["n_responded"] == 0
    assert data["apps"] == entries


def test_render_markdown_includes_label_totals_and_app_rows():
    md = report.render_markdown(_sample_report())

    assert "trial-1" in md
    assert "sqli-easy" in md
    assert "sqli-medium" in md
    assert "1.00 / 1.00" in md
    assert "—" in md


def test_render_json_round_trips():
    data = _sample_report()

    parsed = json.loads(report.render_json(data))

    assert parsed["label"] == "trial-1"
    assert parsed["apps"][0]["id"] == "sqli-easy"


def test_write_report_creates_labeled_md_and_json_files(tmp_path):
    data = _sample_report()

    md_path, json_path = report.write_report(data, out_dir=tmp_path)

    assert md_path.exists()
    assert json_path.exists()
    assert md_path.name.endswith("-trial-1.md")
    assert json_path.name.endswith("-trial-1.json")
    assert json.loads(json_path.read_text())["label"] == "trial-1"


def test_write_report_without_label_omits_slug(tmp_path):
    data = _sample_report()
    data["label"] = None

    md_path, json_path = report.write_report(data, out_dir=tmp_path)

    assert md_path.suffix == ".md"
    assert json_path.suffix == ".json"
    assert "None" not in md_path.name
    assert "None" not in json_path.name
