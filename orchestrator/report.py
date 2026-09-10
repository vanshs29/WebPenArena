"""
Report generation for benchmark mode: snapshot scoring.build_entries()'s current
scoreboard into a labeled, timestamped Markdown + JSON pair under
orchestrator/reports/ (gitignored — these are run artifacts, not source).

Kept free of any CLI/HTTP concerns, matching scoring.py's convention — orchestrator.py
(terminal) and dashboard.py (benchmark-mode web UI) both call build_report()/
write_report() directly.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

import scoring

REPORTS_DIR = Path(__file__).resolve().parent / "reports"


def _slugify(label: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", label.strip()).strip("-").lower()


def build_report(apps: list[dict], label: str | None = None) -> dict:
    entries = scoring.build_entries(apps)
    overall = scoring.aggregate_scores(
        [{"app": e, "score": e["score"]} for e in entries if e["running"]]
    )
    return {
        "label": label,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "totals": overall["totals"],
        "n_total": len(entries),
        "n_responded": overall["n_responded"],
        "totals_by_difficulty": scoring.aggregate_by_difficulty(entries),
        "apps": entries,
    }


def _fmt(n: float) -> str:
    return f"{n:.2f}"


def _totals_table(totals: dict) -> list[str]:
    lines = ["| Category | Achieved | Max |", "|---|---|---|"]
    for metric in scoring.METRICS:
        t = totals[metric]
        label = metric.replace("_", " ").title()
        lines.append(f"| {label} | {_fmt(t['achieved'])} | {_fmt(t['max'])} |")
    return lines


def render_markdown(report: dict) -> str:
    lines = []
    title = "# Benchmark Report"
    if report.get("label"):
        title += f" — {report['label']}"
    lines.append(title)
    lines.append("")
    lines.append(f"Generated: {report['generated_at']}")
    lines.append(f"Apps responded: {report['n_responded']} / {report['n_total']}")
    lines.append("")

    lines.append("## Overall totals")
    lines.append("")
    lines.extend(_totals_table(report["totals"]))
    lines.append("")

    for tier in scoring.DIFFICULTIES:
        tier_data = report["totals_by_difficulty"][tier]
        lines.append(f"## {tier.title()} tier ({tier_data['n_responded']} / {tier_data['n_total']} responded)")
        lines.append("")
        lines.extend(_totals_table(tier_data["totals"]))
        lines.append("")

    lines.append("## Per-app breakdown")
    lines.append("")
    metric_headers = " | ".join(m.replace("_", " ").title() for m in scoring.METRICS)
    lines.append(f"| App | Difficulty | Running | {metric_headers} |")
    lines.append("|---|---|---|" + "---|" * len(scoring.METRICS))
    for e in report["apps"]:
        cells = [e["name"], e["difficulty"], "yes" if e["running"] else "no"]
        for metric in scoring.METRICS:
            if e["score"] is None:
                cells.append("—")
            else:
                achieved = e["score"]["scores"].get(metric, 0.0)
                max_v = scoring.category_max(e["score"], metric)
                cells.append(f"{_fmt(achieved)} / {_fmt(max_v)}")
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")

    return "\n".join(lines)


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def write_report(report: dict, out_dir: Path | None = None) -> tuple[Path, Path]:
    out_dir = out_dir or REPORTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    base = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if report.get("label"):
        base += f"-{_slugify(report['label'])}"

    md_path = out_dir / f"{base}.md"
    json_path = out_dir / f"{base}.json"
    md_path.write_text(render_markdown(report))
    json_path.write_text(render_json(report))
    return md_path, json_path
