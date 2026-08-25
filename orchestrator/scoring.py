"""
Scoring/discovery/aggregation logic for benchmark mode.

Kept free of any CLI (questionary/print) calls — every function here returns plain
data (dicts/lists) so orchestrator.py's menu actions do all the rendering. See
BENCHMARK_MODE_PLAN.md "Future direction" for why: this makes it straightforward to
put an HTTP API in front of this logic later without rewriting it.
"""

import json
import re
import subprocess

try:
    import requests
except ImportError:
    requests = None

METRICS = ["exploration", "reconnaissance", "vulnerability_detection", "exploitation"]
DIFFICULTIES = ["easy", "medium", "hard"]

_CONTAINER_NAME_RE = re.compile(r"^benchmark-(?P<id>.+)-[0-9a-f]{8}$")
_HOST_PORT_RE = re.compile(r":(\d+)->")


def difficulty_of(app_id: str) -> str:
    """Registry ids are suffixed with their design-time difficulty tier
    (`sqli-easy`, `sqli-medium`) — see CLAUDE.md's Difficulty Scoring Methodology for
    why this label is provisional (a one-time tercile reclassification happens once
    the full 50-app corpus is built) rather than a permanent per-app field."""
    for tier in DIFFICULTIES:
        if app_id.endswith(f"-{tier}"):
            return tier
    return "other"


def _container_env(name: str) -> list[str]:
    result = subprocess.run(
        ["docker", "inspect", name, "--format", "{{json .Config.Env}}"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return []
    try:
        return json.loads(result.stdout.strip())
    except json.JSONDecodeError:
        return []


def discover_running_apps(apps: list[dict]) -> list[dict]:
    """Match live `benchmark-*` containers back to registry apps, recovering each
    container's host port and SCORE_TOKEN (works even for containers launched in a
    previous orchestrator run, since nothing is persisted to disk)."""
    from orchestrator import get_running_containers

    apps_by_id = {a["id"]: a for a in apps}
    rows = []

    for row in get_running_containers():
        name = row["name"]
        match = _CONTAINER_NAME_RE.match(name)
        if not match:
            continue
        app = apps_by_id.get(match.group("id"))
        if app is None:
            continue

        port_match = _HOST_PORT_RE.search(row["ports"])
        host_port = int(port_match.group(1)) if port_match else None

        token = None
        for entry in _container_env(name):
            if entry.startswith("SCORE_TOKEN="):
                token = entry.split("=", 1)[1]
                break

        rows.append({
            "app": app,
            "container_name": name,
            "host_port": host_port,
            "token": token,
            "status": row["status"],
        })

    return rows


def fetch_score(host_port: int, token: str, timeout: float = 3) -> dict | None:
    """GET /score/<token>?format=json. Returns None on any connection error, timeout,
    or non-200 — callers must treat that as "not ready yet," not a crash, since no app
    has a Docker HEALTHCHECK."""
    if requests is None or host_port is None or token is None:
        return None
    try:
        resp = requests.get(
            f"http://localhost:{host_port}/score/{token}",
            params={"format": "json"},
            timeout=timeout,
        )
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    try:
        return resp.json()
    except ValueError:
        return None


def reset_score(host_port: int, token: str, timeout: float = 3) -> bool:
    if requests is None or host_port is None or token is None:
        return False
    try:
        resp = requests.post(
            f"http://localhost:{host_port}/score/{token}/reset",
            timeout=timeout,
        )
    except requests.RequestException:
        return False
    return resp.status_code == 200


def aggregate_scores(rows: list[dict]) -> dict:
    """`rows` is discover_running_apps() output, each optionally carrying a "score" key
    (the fetch_score() result, or None if that app didn't respond this tick)."""
    responded = [r for r in rows if r.get("score") is not None]
    totals = {}
    for metric in METRICS:
        total = sum(r["score"]["scores"].get(metric, 0.0) for r in responded)
        totals[metric] = f"{total:.2f} / {len(responded)}"
    return {
        "totals": totals,
        "n_total": len(rows),
        "n_responded": len(responded),
        "rows": rows,
    }
