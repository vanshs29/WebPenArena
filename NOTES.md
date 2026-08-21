# Session Notes — 29 June 2026

## Benchmark environments — current state

### Complete (5 apps — in orchestrator registry, fully tested)

| id | App | Vuln | Stack | Tests | Port |
|----|-----|------|-------|-------|------|
| sqli-easy | ShopLite | SQLi login bypass (OWASP A03, easy) | Python/Flask/SQLite | 44 | 5000 |
| idor-easy | NoteNest | IDOR on notes API (OWASP A01, easy) | Node.js/Express/SQLite | 64 | 3000 |
| sqli-medium | TalentHub | SQLi on hidden endpoint + filter bypass (OWASP A03, medium) | Python/Flask/SQLite | 107 | 5000 |
| xss-easy | PinBoard | Stored XSS via public message board (OWASP A03, easy) | Go/net/http/SQLite | 78 | 8080 |
| cmdi-easy | PulseHub | OS command injection via ping tool (OWASP A03, easy) | Python/Flask/SQLite | 41 | 5000 |

### Planned (4 apps — PLAN.md written, not yet implemented)

| id | App | Vuln | Stack |
|----|-----|------|-------|
| traversal-easy | DocVault | Path traversal via `?name=../secret.txt` (OWASP A05, easy) | Node.js/Express |
| ssrf-easy | LinkPeek | SSRF via unvalidated URL fetch (OWASP A10, easy) | Go/net/http |
| jwt-easy | DevBlog | JWT alg:none forgery (OWASP A07, easy) | Node.js/Express |
| debug-easy | TaskAPI | Exposed `/debug/env` leaks admin API key (OWASP A02, easy) | Ruby/Sinatra |

---

## How to run complete apps

### Via orchestrator (recommended)
```bash
cd /home/vsri29/info4990/webpen-arena
pip install -r orchestrator/requirements.txt
python orchestrator/orchestrator.py
```

### Direct (no Docker)

**Python/Flask** (sqli-easy, sqli-medium, cmdi-easy):
```bash
cd webapps/<id>
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
PORT=5001 SCORE_TOKEN=$(python -c "import uuid; print(uuid.uuid4())") python run.py
```

**Node.js** (idor-easy):
```bash
cd webapps/idor-easy
npm install
PORT=5003 SCORE_TOKEN=$(node -e "console.log(require('crypto').randomUUID())") node run.js
```

**Go** (xss-easy):
```bash
cd webapps/xss-easy
SCORE_TOKEN=$(python3 -c "import uuid; print(uuid.uuid4())")
PATH=$PATH:$HOME/go/bin PORT=8080 go run .
```

Score dashboard: `http://localhost:<port>/score/<token>`
Score JSON: `http://localhost:<port>/score/<token>?format=json`

---

## Running tests

```bash
# Python apps (sqli-easy, sqli-medium, cmdi-easy)
cd webapps/<id>
source .venv/bin/activate
python -m pytest tests/ -v

# Node apps (idor-easy)
cd webapps/idor-easy
node ./node_modules/jest/bin/jest.js --forceExit

# Go apps (xss-easy)
cd webapps/xss-easy
PATH=$PATH:$HOME/go/bin go test ./... -v
```

---

## Known exploit solutions

### sqli-medium (TalentHub)
Full walkthrough: `/home/vsri29/info4990/sqli-medium-solution.txt`

Key steps:
1. Discover `POST /api/v1/login` via enumeration (`GET /api/v1/login` gives a field-name hint)
2. Confirm SQLi with a single unbalanced quote (`'`)
3. `' OR '1'='1' --` blocked by comment filter
4. `' OR '1'='1` in both fields bypasses filter; returns admin JWT with `via_sqli: True`
5. Use JWT for `GET /admin` → `GET /admin/applicants`

---

## Framework decisions

New apps use modern, varied stacks. Decision made 29 June 2026 to avoid adding more
Python/Flask. Full framework list with assignment heuristics saved in Claude memory
(`project_framework_list.md`).

Stack distribution across the full 9-app benchmark:
- Python/Flask: sqli-easy, sqli-medium, cmdi-easy
- Node.js/Express: idor-easy, traversal-easy, jwt-easy
- Go/net/http: xss-easy, ssrf-easy
- Ruby/Sinatra: debug-easy

---

## sqli-easy recent changes (uncommitted)

- `app/scoring.py` — added `get_exploration_surfaces()` returning set of surfaces hit
- `app/routes.py` — passes `surfaces_hit` to score dashboard template
- `app/templates/score_dashboard.html` — reworked into stage/checkpoint checklist table
- `run.py` — now respects `PORT` env var (consistent with other apps)
