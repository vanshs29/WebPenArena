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
import uuid
from pathlib import Path

try:
    import questionary
except ImportError:
    sys.exit("Missing dependency: pip install questionary")

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
    raise RuntimeError(f"No free port found in range {start}–{end}")


# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------

def image_exists(image: str) -> bool:
    result = subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True,
    )
    return result.returncode == 0


def build_image_data(app: dict) -> dict:
    """Build `app`'s image with no streamed output to the caller's stdout/stderr —
    used by the web dashboard, which must not leak subprocess output to the
    terminal. Returns {"ok": bool, "stderr": str}; `stderr` is the tail of
    docker build's stderr, populated only on failure, so the dashboard can show
    a diagnostic instead of a bare FAILED with no detail. `build_image()` is the
    CLI-facing wrapper that streams output live and doesn't need this."""
    context = str(REPO_ROOT / app["path"])
    result = subprocess.run(
        ["docker", "build", "-t", app["image"], context],
        capture_output=True,
        text=True,
    )
    ok = result.returncode == 0
    stderr = "" if ok else result.stderr[-4000:]
    return {"ok": ok, "stderr": stderr}


def build_image(app: dict) -> bool:
    context = str(REPO_ROOT / app["path"])
    print(f"\n[build] docker build -t {app['image']} {context}\n")
    result = subprocess.run(
        ["docker", "build", "-t", app["image"], context],
    )
    return result.returncode == 0


def run_container_data(app: dict) -> dict | None:
    """Launch a container for `app`, returning launch info as a dict (no printing)
    or None on failure. Used by both the CLI (`run_container`, which prints this)
    and the web dashboard (which renders it in the browser instead)."""
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
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None

    return {
        "id": app["id"],
        "name": app["name"],
        "description": app["description"],
        "container_name": container_name,
        "host_port": host_port,
        "token": token,
        "score_url": f"http://localhost:{host_port}/score/{token}",
    }


def run_container(app: dict) -> None:
    print(f"\n[launch] starting {app['name']}…\n")
    info = run_container_data(app)
    if info is None:
        print("[error] docker run failed")
        return

    print("=" * 60)
    print(f"  App          : {info['name']} ({info['description']})")
    print(f"  Container    : {info['container_name']}")
    print(f"  Host port    : {info['host_port']}")
    print(f"  Score URL    : {info['score_url']}")
    print(f"  Score token  : {info['token']}")
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


def stop_container_data(name: str) -> bool:
    """Stop+remove `name` with no streamed output — used by the web dashboard.
    `stop_container()` is the CLI-facing wrapper that prints progress."""
    stop_ok = subprocess.run(["docker", "stop", name], capture_output=True).returncode == 0
    rm_ok = subprocess.run(["docker", "rm", name], capture_output=True).returncode == 0
    return stop_ok and rm_ok


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
# Benchmark mode: web dashboard
# ---------------------------------------------------------------------------

def action_benchmark_mode_web(apps: list[dict]) -> None:
    import dashboard
    dashboard.run_dashboard(apps)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

MENU = {
    "Launch a web app": action_launch,
    "Launch all web apps": action_launch_all,
    "Benchmark mode (web dashboard)": action_benchmark_mode_web,
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
