# Scoring Rework: HTB-Style Subtask Weights

Retrofit plan for the scoring-model revision already decided in the root `CLAUDE.md`
(2026-08-07): every named subtask across all four categories gets a weight of
0.5 (easy) / 1 (medium) / 2 (hard); category score = sum of weights of subtasks
fired; overall score = sum of max achievable weight across the whole app. Raw,
unnormalized, HTB-style — not a 0–1 fraction. This doc is the retrofit plan for the
17 already-built apps; write it before touching any app's code.

---

## 1. Current model (verified against source, not assumed)

Checked `sqli-medium` (the only app with genuine multi-subcheck categories) and
`sqli-easy` (the minimal single-check-per-category case):

- Every category's subtasks are boolean checks (fired / not fired), **equally weighted
  within the category**.
- `get_scores()` returns `category_score = fired_count / total_count` (exploration:
  `distinct_surfaces_hit / SCOREABLE_SURFACES`), each capped to `[0, 1]`.
- Dashboard (`score_dashboard.html` / equivalent) shows a fraction (e.g. "2 / 3 steps"),
  a percentage badge, and a ✓/✗ per checkpoint row.
- The JSON API (`?format=json`) returns the same `[0,1]` fractions, no max/ceiling field.
- **No overall/combined score exists anywhere in any app today** — this is new, not a
  rename of something that already exists.
- Reference implementations: `webapps/sqli-medium/app/scoring.py` +
  `.../templates/score_dashboard.html` (multi-subcheck); `webapps/sqli-easy/app/scoring.py`
  (single-check minimal case).

## 2. Target model

- Every subtask, **including each exploration surface** (not just recon/vuln-detect/
  exploit), gets a weight in `{0.5, 1, 2}`, assigned by the researcher at design time —
  never computed or judged at run time.
- `category_score(run) = Σ weight[s] for s in category.subtasks if s fired` — raw sum,
  no division.
- `category_max(app) = Σ weight[s] for s in category.subtasks` — a static ceiling.
- `overall_max(app) = Σ category_max[c] for c in the 4 categories` — the number the
  eventual 50-app tercile pass (easy/medium/hard) will sort on. Per-run, per-category
  scores are still **reported separately, never blended** — this doesn't change.

## 3. Weight-assignment rubric (proposed — needs your sign-off before I apply it)

Modeled on HTB's public machine-submission difficulty criteria
(step count / script-only vs. custom / rabbit holes), mapped onto the "what triggers
it" column every checkpoint already has documented on its dashboard:

| Weight | Criteria |
|--------|----------|
| **0.5 (easy)** | Single obvious action, no chaining — one direct request or an already-visible form/link (e.g. loading a page, hitting an endpoint linked from the UI). |
| **1 (medium)** | One non-obvious step — interpreting an error/behavioral signal, finding an unlinked-but-guessable endpoint off a visible naming pattern, or a single crafted (not blind) payload. |
| **2 (hard)** | Multi-step chaining, blind inference with no direct feedback, a filter/encoding bypass, or a non-trivial constructed payload/exploit. |

Assigning a weight becomes a pass over each app's existing "what triggers it" text, not
new analysis — but it's still a subjective per-subtask call, so I want your read on the
three-tier wording (or examples of misclassification) before applying it across 17 apps.

## 4. Per-app contract changes

1. `scoring.py`/equivalent: add a weights mapping (name → weight) covering every
   checkpoint in all four categories including exploration; replace the fraction math in
   `get_scores()` with weighted sums; add category-max and overall-max constants.
2. Dashboard template: each checkpoint row gains its weight (e.g. "0.5 pt"); each category
   header row changes from "N / M" or a % badge to "`fired_sum` / `category_max` pts".
3. `?format=json`: add `max_score` (per-category + overall) alongside the existing
   `scores`, so the eventual tercile pass can read `overall_max` straight from a live
   container.
4. Tests: every assertion on a fraction (`== 2/3`, `pytest.approx(0.5)`, etc.) becomes an
   assertion on the new weighted sum — this is the bulk of the mechanical work.
5. `orchestrator/registry.json`: add `overall_max_score` per app, so tercile
   classification later doesn't require booting all 50 containers to read a static number.
6. Each app's `PLAN.md` §scoring: record the assigned weight + one-line rationale per
   subtask — the audit trail for the methodology write-up.

## 5. Sequencing

1. **This doc** — lock rubric + contract, get sign-off.
2. **Prototype on `sqli-medium`** — it's the only app with real multi-subcheck categories
   in recon/vuln-detect/exploit, so it's the actual stress test of "sum of weights" vs.
   the trivial single-check case every other easy app has today. Full verification
   (tests, dashboard, JSON, live container) before touching anything else.
3. **Retrofit the remaining 16 apps**, one at a time, grouped by stack (Flask ×4, Express
   ×3 [+2 Playwright], Fastify ×1, Go ×2, Ruby ×2, PHP ×1, Java ×1, Next.js ×1) since the
   mechanical pattern repeats within a stack.
4. **Update `webpen-arena/CLAUDE.md`**'s scoring-model description and Cross-App
   Conventions once the pattern is locked, so any future app is built to the new contract
   from the start.

## 6. Decisions (2026-08-26)

- Rubric in §3 approved as written — applying it as-is, no example walkthrough needed.
- Prototyping on `sqli-medium` first, per §5.
- `overall_max_score` storage location (registry.json / JSON API / both) is **deferred** —
  discuss later. For now: compute it and document it (as a `scoring.py` constant + a note
  in each app's `PLAN.md`), but don't wire it into `registry.json` or the JSON API response
  yet. Revisit once the storage decision is made, rather than picking one now and having
  to undo it.

## 7. Live-orchestrator half of the deferral resolved (28 Aug 2026)

The deferral in §6 above blocked longer than intended: with sqli-medium retrofitted but nothing
downstream aware of its real ceiling, the orchestrator's cross-app aggregate (`scoring.py`'s
`aggregate_scores()`) and the web dashboard's meter bars (`static/dashboard.js`'s `patchCard()`)
both silently assumed every category score maxes at 1 — sqli-medium's exploration bar (max 8.5)
rendered as "100% full" after a single surface hit.

Resolved for this specific consumer: `?format=json` now includes a `max_score` object
(`webapps/sqli-medium/app/routes.py`, wiring in the already-computed `CATEGORY_MAX_SCORES`/
`OVERALL_MAX_SCORE` constants). The orchestrator reads it live and defaults to 1.0 per category
when absent, so un-retrofitted apps are unaffected. `registry.json` storage remains deferred —
this fix didn't need it, since the live dashboard only ever looks at apps that are already
running (and thus already have a JSON response to read from). The registry field is still the
right call for the eventual one-time 50-app tercile pass, which is a static, offline
computation and shouldn't require booting every container.

As each of the remaining 16 apps gets retrofitted per §5 step 3, its route handler should add
the same `max_score` key to its own `?format=json` response — no further orchestrator changes
will be needed when that happens.
