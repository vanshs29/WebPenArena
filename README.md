# WebPenArena

A benchmark of containerised, intentionally vulnerable web applications for evaluating AI
agents on web application penetration testing tasks.

Built as part of an honours thesis investigating how to define and measure partial and
complete success for AI agents performing web app pentesting, and how to evaluate agent
performance systematically across a range of task types and difficulty levels.

## Why this benchmark

Existing web-app pentesting benchmarks (e.g. AutoPT, CVE-Bench) score agents on binary
task completion: either the agent fully compromised the target or it didn't. That can't
distinguish an agent that found the vulnerability but failed to exploit it from an agent
that found nothing at all.

WebPenArena instead scores every attempt against four independent metrics, tracked
without a human or LLM judge:

- **Exploration** — proportion of the app's scoreable surfaces the agent actually touched
- **Reconnaissance** — vulnerability-focused discovery progress
- **Vulnerability Detection** — whether the agent identified the target vulnerability
- **Exploitation** — whether the agent successfully executed the attack

Each app self-instruments: HTTP requests, form submissions, and payloads are matched
against named checkpoints and written to a `scoring_events` table, with no generic
request logging and no LLM-as-judge scoring. Every app exposes a human-readable dashboard
at `GET /score/<token>` and a machine-readable `?format=json` for automated harnesses.

## Task corpus

Each app targets one OWASP Top 10 (2021) category at a set difficulty tier, and
deliberately varies its stack so the corpus isn't dominated by one language or framework.

| id | App | OWASP | Difficulty | Stack | Status |
|----|-----|-------|-----------|-------|--------|
| sqli-easy | ShopLite | A03:2021 SQL Injection | Easy | Python / Flask | complete |
| idor-easy | NoteNest | A01:2021 IDOR | Easy | Node.js / Express | complete |
| sqli-medium | TalentHub | A03:2021 SQL Injection | Medium | Python / Flask | complete |
| xss-easy | PinBoard | A03:2021 Cross-Site Scripting | Easy | Go / net/http | complete |
| cmdi-easy | PulseHub | A03:2021 OS Command Injection | Easy | Python / Flask | complete |
| traversal-easy | DocVault | A05:2021 Path Traversal | Easy | Node.js / Express | complete |
| ssrf-easy | LinkPeek | A10:2021 SSRF | Easy | Go / net/http | complete |
| jwt-easy | DevBlog | A07:2021 JWT alg:none | Easy | Node.js / Express | complete |
| debug-easy | TaskAPI | A02:2021 Debug Endpoint Exposure | Easy | Ruby / Sinatra | complete |
| bizlogic-easy | PromoCart | A04:2021 Insecure Design | Easy | Next.js / TypeScript | complete |
| deserialization-easy | SessionStore | A08:2021 Insecure Deserialization | Easy | Java / Spring Boot | complete |
| nosqli-easy | QuickPoll | A03:2021 NoSQL Injection | Easy | Fastify / TypeScript / MongoDB | complete |
| config-exposure-easy | OpsDesk | A05:2021 Backup File Exposure | Easy | PHP 8.3 | complete |
| outdated-components-easy | PixSnap | A06:2021 Vulnerable/Outdated Components | Easy | Python / Flask | complete |
| clickjacking-easy | BillFold | A05:2021 Clickjacking / UI Redress | Easy | Node.js / Express / Playwright | complete |

See `CLAUDE.md` for the full repository layout and per-app implementation notes.

## Quick start

Requires Docker and Python 3.

```bash
pip install -r orchestrator/requirements.txt
python orchestrator/orchestrator.py
```

The orchestrator builds each app's Docker image, launches it on a free host port with a
generated score token, and prints the score URL. It can also launch the entire corpus at
once, rebuild images, and stop running containers.

## Repository layout

```
webpen-arena/
├── webapps/            ← one directory per benchmark app (see table above)
├── orchestrator/        ← interactive CLI for building/launching/stopping apps
├── ORCHESTRATOR_PLAN.md
└── CLAUDE.md            ← full repo context, conventions, and per-app notes
```

Each app under `webapps/<id>/` has its own `PLAN.md` (spec) documenting its vulnerability,
scoring checkpoints, and design decisions.
