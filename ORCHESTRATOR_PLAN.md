# Benchmark Orchestrator — Plan

## Goal

Reorganise the repo so every web app lives in its own subdirectory, then provide a single
interactive CLI tool to build, launch, and manage any of them via Docker.

---

## Directory Layout (after reorganisation)

```
prototype-webapp/
├── webapps/
│   ├── sqli-easy/          ← ShopLite   (was: root app/ + run.py + Dockerfile)
│   │   ├── app/
│   │   ├── run.py
│   │   ├── requirements.txt
│   │   ├── Dockerfile
│   │   ├── PLAN.md
│   │   └── CLAUDE.md
│   ├── idor-easy/          ← NoteNest   (was: idor-easy/)
│   │   ├── src/
│   │   ├── app.js / run.js
│   │   ├── package.json
│   │   ├── Dockerfile
│   │   ├── PLAN.md
│   │   └── CLAUDE.md
│   └── sqli-medium/        ← TalentHub  (was: sqli-medium/)
│       ├── app/
│       ├── run.py
│       ├── requirements.txt
│       ├── Dockerfile
│       ├── PLAN.md
│       └── CLAUDE.md
├── orchestrator/
│   ├── orchestrator.py     ← interactive CLI (main entry point)
│   ├── registry.json       ← app manifest
│   └── requirements.txt    ← questionary only
├── ORCHESTRATOR_PLAN.md    ← this file
├── PLAN.md                 ← overall benchmark plan (unchanged)
└── CLAUDE.md               ← project instructions (unchanged)
```

No app's internal code is changed — only file paths move.

---

## App Registry (`orchestrator/registry.json`)

Single source of truth for all registered web apps. Adding a new app = adding one entry.

```json
{
  "apps": [
    {
      "id": "sqli-easy",
      "name": "ShopLite",
      "description": "OWASP A03:2021 — SQL Injection (Easy)",
      "path": "webapps/sqli-easy",
      "image": "benchmark/sqli-easy",
      "container_port": 5000
    },
    {
      "id": "idor-easy",
      "name": "NoteNest",
      "description": "OWASP A01:2021 — IDOR / Broken Access Control (Easy)",
      "path": "webapps/idor-easy",
      "image": "benchmark/idor-easy",
      "container_port": 3000
    },
    {
      "id": "sqli-medium",
      "name": "TalentHub",
      "description": "OWASP A03:2021 — SQL Injection (Medium)",
      "path": "webapps/sqli-medium",
      "image": "benchmark/sqli-medium",
      "container_port": 5000
    }
  ]
}
```

---

## Orchestrator Features

### Top-level menu

```
? What would you like to do?
  ❯ Launch a web app
    Launch all web apps
    Rebuild image(s)
    Rebuild and launch a web app
    Show running apps
    Stop a running app
    Stop all running apps
    Exit
```

### Launch

1. Dropdown of registered apps (name + description).
2. Warn if the image has not been built yet (offer to build first).
3. Find a free host port starting at 8000 via `socket.bind()`.
4. Generate a UUID4 as `SCORE_TOKEN`.
5. `docker run -d --name benchmark-<id>-<short_uuid> -p <host_port>:<container_port> -e SCORE_TOKEN=<token> benchmark/<id>`
6. Print: container name, host port, score URL (`http://localhost:<port>/score/<token>`).

### Launch all web apps

1. Check which registered images are missing locally.
2. If any are missing, offer to build them all before proceeding; abort if declined or a build fails.
3. Call the Launch flow above for each app in registry order, each with its own free port and score token.

### Rebuild (standalone)

1. Multi-select checkbox list of apps (plus "All" shortcut that checks every box).
2. For each selected app: `docker build -t benchmark/<id> webapps/<id>/` (streaming output).

### Rebuild and Launch

1. Single-select dropdown of one app.
2. Run rebuild for that app (streaming output).
3. On success, continue through the Launch flow above.

### Show running apps

`docker ps --filter name=benchmark- --format json` → formatted table:
app name | container name | host port | status | score URL.

### Stop a running app

Dropdown populated from live `docker ps` output.
`docker stop <name> && docker rm <name>`.

### Stop all running apps

Lists every running benchmark container from live `docker ps` output, then asks a single
`questionary.confirm()` before stopping and removing all of them (same
`docker stop <name> && docker rm <name>` per container as the single-container flow above).
Aborts with no changes if declined or if nothing is running.

---

## Port Management

```python
import socket

def find_free_port(start=8000, end=9000):
    for port in range(start, end):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(('', port))
                return port
            except OSError:
                continue
    raise RuntimeError("No free port found in range 8000–9000")
```

Pure stdlib — no external dependency.

---

## Docker Image Naming

All benchmark images use the `benchmark/<id>` namespace:

| App id       | Image tag              |
|--------------|------------------------|
| sqli-easy    | `benchmark/sqli-easy`  |
| idor-easy    | `benchmark/idor-easy`  |
| sqli-medium  | `benchmark/sqli-medium`|

Container names follow `benchmark-<id>-<8-char-uuid>` to allow multiple simultaneous instances.

---

## Dependencies

```
# orchestrator/requirements.txt
questionary>=2.0
```

Docker is invoked via `subprocess` + the `docker` CLI — no Python Docker SDK required.

---

## Migration Steps

1. `mkdir -p webapps/sqli-easy` → move ShopLite root files in.
2. `git mv idor-easy webapps/idor-easy`
3. `git mv sqli-medium webapps/sqli-medium`
4. Update `CLAUDE.md` file-path references that point to old locations.
5. Write `orchestrator/registry.json`, `orchestrator/requirements.txt`, `orchestrator/orchestrator.py`.
6. Verify: `docker build` from new paths, `python orchestrator/orchestrator.py` runs cleanly.
