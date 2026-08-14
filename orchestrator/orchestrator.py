#!/usr/bin/env python3
"""
Benchmark orchestrator — interactive CLI for building and launching
vulnerable web app environments via Docker.

Usage:
    cd webpen-arena
    python orchestrator/orchestrator.py
"""

import json
import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

try:
    import questionary
except ImportError:
    sys.exit("Missing dependency: pip install questionary")

import scoring

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = Path(__file__).resolve().parent / "registry.json"


def load_registry() -> list[dict]:
    with open(REGISTRY_PATH) as f:
        return json.load(f)["apps"]


# ---------------------------------------------------------------------------
# Port helpers
# ---------------------------------------------------------------------------

def find_free_port(start: int = 8000, end: int = 9000) -> int:
    for port in range(start, end):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("", port))
                return port
            except OSError:
                continue
    raise RuntimeError("No free port found in range 8000–9000")


# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------

def image_exists(image: str) -> bool:
    result = subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True,
    )
    return result.returncode == 0


def build_image(app: dict) -> bool:
    context = str(REPO_ROOT / app["path"])
    print(f"\n[build] docker build -t {app['image']} {context}\n")
    result = subprocess.run(
        ["docker", "build", "-t", app["image"], context],
    )
    return result.returncode == 0


def run_container(app: dict) -> None:
    host_port = find_free_port()
    token = str(uuid.uuid4())
    short_id = uuid.uuid4().hex[:8]
    container_name = f"benchmark-{app['id']}-{short_id}"

    cmd = [
        "docker", "run", "-d",
        "--name", container_name,
        "-p", f"{host_port}:{app['container_port']}",
        "-e", f"SCORE_TOKEN={token}",
        app["image"],
    ]
    print(f"\n[launch] {' '.join(cmd)}\n")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[error] {result.stderr.strip()}")
        return

    score_url = f"http://localhost:{host_port}/score/{token}"
    print("=" * 60)
    print(f"  App          : {app['name']} ({app['description']})")
    print(f"  Container    : {container_name}")
    print(f"  Host port    : {host_port}")
    print(f"  Score URL    : {score_url}")
    print(f"  Score token  : {token}")
    print("=" * 60)


def get_running_containers() -> list[dict]:
    result = subprocess.run(
        [
            "docker", "ps",
            "--filter", "name=benchmark-",
            "--format",
            "{{.Names}}\t{{.Ports}}\t{{.Status}}",
        ],
        capture_output=True,
        text=True,
    )
    rows = []
    for line in result.stdout.strip().splitlines():
        parts = line.split("\t")
        if len(parts) == 3:
            rows.append({"name": parts[0], "ports": parts[1], "status": parts[2]})
    return rows


def stop_container(name: str) -> None:
    print(f"\n[stop] stopping {name} …")
    subprocess.run(["docker", "stop", name], check=True)
    subprocess.run(["docker", "rm", name], check=True)
    print(f"[stop] {name} removed.")


# ---------------------------------------------------------------------------
# Menu helpers
# ---------------------------------------------------------------------------

def app_label(app: dict) -> str:
    return f"{app['name']}  —  {app['description']}"


def choose_app(apps: list[dict], prompt: str = "Which web app?") -> dict | None:
    choices = {app_label(a): a for a in apps}
    answer = questionary.select(prompt, choices=list(choices.keys())).ask()
    if answer is None:
        return None
    return choices[answer]


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

def action_launch(apps: list[dict]) -> None:
    app = choose_app(apps, "Which web app to launch?")
    if app is None:
        return

    if not image_exists(app["image"]):
        print(f"\n[warn] Image '{app['image']}' not found locally.")
        build_first = questionary.confirm("Build it now?").ask()
        if not build_first:
            print("[abort] Cannot launch without a built image.")
            return
        if not build_image(app):
            print("[error] Build failed — aborting launch.")
            return

    run_container(app)


def action_rebuild(apps: list[dict]) -> None:
    all_label = "All apps"
    choices = [all_label] + [app_label(a) for a in apps]
    label_to_app = {app_label(a): a for a in apps}

    answers = questionary.checkbox("Select image(s) to rebuild:", choices=choices).ask()
    if not answers:
        print("[abort] Nothing selected.")
        return

    targets = apps if all_label in answers else [label_to_app[a] for a in answers if a != all_label]

    for app in targets:
        ok = build_image(app)
        status = "OK" if ok else "FAILED"
        print(f"\n[rebuild] {app['image']} → {status}")


def action_rebuild_and_launch(apps: list[dict]) -> None:
    app = choose_app(apps, "Which web app to rebuild and launch?")
    if app is None:
        return

    ok = build_image(app)
    if not ok:
        print("[error] Build failed — aborting launch.")
        return

    run_container(app)


def action_launch_all(apps: list[dict]) -> None:
    missing = [a for a in apps if not image_exists(a["image"])]
    if missing:
        names = ", ".join(a["name"] for a in missing)
        print(f"\n[warn] Missing images: {names}")
        build_first = questionary.confirm("Build missing images now?").ask()
        if not build_first:
            print("[abort] Cannot launch without built images.")
            return
        for app in missing:
            if not build_image(app):
                print(f"[error] Build failed for {app['name']} — aborting.")
                return

    print(f"\n[launch-all] Starting {len(apps)} app(s)…")
    for app in apps:
        run_container(app)


def action_show_running() -> None:
    rows = get_running_containers()
    if not rows:
        print("\n[info] No benchmark containers are currently running.")
        return

    print(f"\n{'CONTAINER':<40} {'PORTS':<30} {'STATUS'}")
    print("-" * 80)
    for r in rows:
        print(f"{r['name']:<40} {r['ports']:<30} {r['status']}")


def action_stop() -> None:
    rows = get_running_containers()
    if not rows:
        print("\n[info] No benchmark containers are running.")
        return

    choices = {r["name"]: r for r in rows}
    answer = questionary.select(
        "Which container to stop?", choices=list(choices.keys())
    ).ask()
    if answer is None:
        return
    stop_container(answer)


def action_stop_all() -> None:
    rows = get_running_containers()
    if not rows:
        print("\n[info] No benchmark containers are running.")
        return

    print(f"\nRunning containers ({len(rows)}):")
    for r in rows:
        print(f"  - {r['name']}")

    confirmed = questionary.confirm(
        f"Stop and remove all {len(rows)} running benchmark container(s)?", default=False
    ).ask()
    if not confirmed:
        print("[abort] Nothing stopped.")
        return

    for r in rows:
        stop_container(r["name"])


# ---------------------------------------------------------------------------
# Benchmark mode: scoreboard, single-app score, reset
# ---------------------------------------------------------------------------

def choose_running_app(apps: list[dict], prompt: str = "Which running app?") -> dict | None:
    rows = scoring.discover_running_apps(apps)
    if not rows:
        print("\n[info] No benchmark containers are currently running.")
        return None
    choices = {f"{r['app']['name']}  ({r['container_name']})": r for r in rows}
    answer = questionary.select(prompt, choices=list(choices.keys())).ask()
    if answer is None:
        return None
    return choices[answer]


def action_view_scoreboard(apps: list[dict]) -> None:
    if not scoring.discover_running_apps(apps):
        print("\n[info] No benchmark containers are currently running.")
        return

    print("\n[scoreboard] Live view — Ctrl+C to return to the menu.")
    try:
        while True:
            rows = scoring.discover_running_apps(apps)
            if not rows:
                print("\n[info] No benchmark containers are currently running.")
                return

            for row in rows:
                row["score"] = scoring.fetch_score(row["host_port"], row["token"])
            agg = scoring.aggregate_scores(rows)

            print("\033[2J\033[H", end="")
            print(f"Benchmark scoreboard — {agg['n_responded']}/{agg['n_total']} apps responding")
            print("=" * 70)
            for metric in scoring.METRICS:
                print(f"  {metric:<24}: {agg['totals'][metric]}")
            print("=" * 70)

            print(f"\n{'APP':<24} {'EXPLORE':<9} {'RECON':<9} {'VULNDET':<9} {'EXPLOIT':<9} STATUS")
            print("-" * 70)
            for row in rows:
                app = row["app"]
                score = row["score"]
                if score is None:
                    print(f"{app['id']:<24} {'-':<9} {'-':<9} {'-':<9} {'-':<9} not responding")
                    continue
                s = score["scores"]
                print(
                    f"{app['id']:<24} "
                    f"{s.get('exploration', 0):<9.2f} "
                    f"{s.get('reconnaissance', 0):<9.2f} "
                    f"{s.get('vulnerability_detection', 0):<9.2f} "
                    f"{s.get('exploitation', 0):<9.2f} "
                    f"{row['status']}"
                )

            time.sleep(3)
    except KeyboardInterrupt:
        print("\n[scoreboard] Returning to menu.")


def action_view_app_score(apps: list[dict]) -> None:
    row = choose_running_app(apps, "Which app's score to view?")
    if row is None:
        return

    score = scoring.fetch_score(row["host_port"], row["token"])
    if score is None:
        print(f"\n[warn] {row['app']['name']} did not respond to the score request.")
        return

    print(f"\n{'=' * 60}")
    print(f"  App        : {row['app']['name']} ({row['app']['description']})")
    print(f"  Task id    : {score.get('task_id')}")
    print(f"{'=' * 60}")
    for metric in scoring.METRICS:
        print(f"  {metric:<24}: {score['scores'].get(metric, 0):.2f}")
    print(f"{'=' * 60}")

    events = score.get("events", [])
    print(f"\n  Recent events ({len(events)} total, newest first):")
    for event in events[:10]:
        print(f"    - {event}")


def action_reset_scores(apps: list[dict]) -> None:
    rows = scoring.discover_running_apps(apps)
    if not rows:
        print("\n[info] No benchmark containers are currently running.")
        return

    all_label = "All running apps"
    labels = {f"{r['app']['name']}  ({r['container_name']})": r for r in rows}
    choices = [all_label] + list(labels.keys())

    answers = questionary.checkbox("Select app(s) to reset:", choices=choices).ask()
    if not answers:
        print("[abort] Nothing selected.")
        return

    targets = rows if all_label in answers else [labels[a] for a in answers if a != all_label]

    confirmed = questionary.confirm(
        f"Reset {len(targets)} app(s)? This clears scoring state and re-seeds app data.",
        default=False,
    ).ask()
    if not confirmed:
        print("[abort] Nothing reset.")
        return

    for row in targets:
        ok = scoring.reset_score(row["host_port"], row["token"])
        status = "OK" if ok else "FAILED"
        print(f"[reset] {row['app']['name']} → {status}")


def action_benchmark_mode(apps: list[dict]) -> None:
    action_launch_all(apps)
    action_view_scoreboard(apps)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

MENU = {
    "Launch a web app": action_launch,
    "Launch all web apps": action_launch_all,
    "Benchmark mode (launch all + live scoreboard)": action_benchmark_mode,
    "View benchmark scoreboard": action_view_scoreboard,
    "View single app score": action_view_app_score,
    "Reset app score(s)": action_reset_scores,
    "Rebuild image(s)": action_rebuild,
    "Rebuild and launch a web app": action_rebuild_and_launch,
    "Show running apps": action_show_running,
    "Stop a running app": action_stop,
    "Stop all running apps": action_stop_all,
    "Exit": None,
}


def main() -> None:
    apps = load_registry()

    while True:
        print()
        choice = questionary.select(
            "What would you like to do?", choices=list(MENU.keys())
        ).ask()

        if choice is None or choice == "Exit":
            print("Bye.")
            break

        action = MENU[choice]
        if action in (action_show_running, action_stop, action_stop_all):
            action()
        else:
            action(apps)


if __name__ == "__main__":
    main()
