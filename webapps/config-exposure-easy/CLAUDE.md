# SDE Agent — Strict TDD Workflow

## Core Mandate

This agent follows **Test-Driven Development (TDD)** without exception. The red-green-refactor cycle is the only permitted implementation path. No production code may be written before a failing test exists that demands it.

---

## Workflow: Required Order of Operations

### 1. Plan

Before writing any code, produce a written plan that covers:
- What the feature/fix does and why
- The public API or interface (function signatures, endpoints, data shapes)
- Edge cases and failure modes to handle
- Which test types are needed: unit, functional, and/or system

**Do not skip this step.** The plan is the contract. If the plan changes mid-implementation, re-plan explicitly rather than silently pivoting.

### 2. Write Tests First

Write all tests before any implementation:
- **Unit tests** — isolated logic, one unit of behavior per test, all dependencies mocked/stubbed
- **Functional tests** — a feature end-to-end within the system boundary (e.g., a service method, a CLI command), real internal dependencies, external ones stubbed
- **System tests** — full integration across process/network boundaries; use sparingly and only when integration risk is real

Tests must be **specific and meaningful** — they should fail for the right reason, not just because the code doesn't exist yet. Write assertions that would catch regressions, not just presence checks.

### 3. Run Tests — Confirm They Fail

Run the full test suite (or the relevant subset) and confirm:
- New tests fail (red)
- Existing tests still pass

If a new test passes before any implementation, it is either testing the wrong thing or duplicating existing behavior. Investigate before proceeding.

### 4. Implement to Pass Tests

Write the minimum production code needed to make the failing tests pass. Do not implement anything not covered by a test.

Follow language-appropriate best practices (see below).

### 5. Run Tests — Confirm They Pass

Run the full test suite. All tests, old and new, must pass (green).

### 6. Refactor (Optional)

Clean up the implementation — improve naming, eliminate duplication, simplify logic — without changing behavior. Run the full suite again after any refactor to confirm nothing regressed.

---

## Test Immutability Rule

**Once tests are written, they may not be changed automatically.**

If a test is not passing:
1. First assume the implementation is wrong — fix the implementation.
2. If you genuinely believe the test is incorrect (wrong expectation, testing the wrong thing, based on a misunderstood requirement), **stop and flag it for human review** rather than modifying the test.

Changing a test to make it pass defeats the purpose of TDD. When in doubt, escalate.

---

## Programming Best Practices

Apply the following regardless of language:

### General
- Write the simplest code that passes the test. Avoid over-engineering.
- Prefer composition over inheritance.
- Keep functions/methods small and single-purpose.
- Name things by what they are, not how they work.
- No comments explaining *what* the code does — only *why*, when non-obvious.
- No dead code, unused imports, or commented-out blocks.

### Error Handling
- Validate at system boundaries (user input, external APIs, file I/O). Trust internal code.
- Fail fast and explicitly. Prefer returning errors over silently swallowing them.
- Do not add error handling for conditions that cannot occur.

### Testing
- One logical assertion per test where practical.
- Test behavior, not implementation details.
- Test names describe what the behavior is, not what the code does (`calculates_total_with_discount`, not `test_calculate`).
- Avoid logic (loops, conditionals) inside tests. If you need it, the test is too complex.

### Language-Specific
Apply idiomatic conventions for the language in use (e.g., PEP 8 for Python, `gofmt` for Go, `prettier` + ESLint for TypeScript, `rustfmt` for Rust). Use the project's existing linter/formatter config if present.

---

## What Requires Human Review

Pause and ask a human before proceeding when:
- A test is not passing and you believe the test itself is wrong
- The plan needs to change significantly after tests are written
- A design decision has meaningful tradeoffs not resolvable from the requirements
- A test deletion or major test restructure seems necessary

Do not autonomously delete, skip, or weaken tests. Do not use test framework escape hatches (`.skip`, `// TODO: fix this`) without flagging them explicitly.

---

## File & Scope Discipline

- Edit only files relevant to the current task.
- Do not refactor unrelated code while implementing a feature.
- Do not introduce new abstractions unless a test forces them or duplication appears three or more times.
- Prefer editing existing files to creating new ones.

---

## Definition of Done

A task is complete when:
1. All new tests pass
2. All pre-existing tests still pass
3. No tests are skipped or marked expected-failure without human sign-off
4. The implementation contains no code not exercised by a test

---

## Implementation Notes (ConfigLeak, complete)

Status: complete, 40 tests passing (10 unit + 30 feature/system), matching `PLAN.md` exactly.

### Running the test suite (no local PHP in this sandbox)

There was no local `php` binary available, so the entire TDD cycle ran inside `php:8.3-cli`
Docker containers rather than on the host:

```bash
# one-time: download phpunit as a self-contained PHAR (no Composer needed —
# pdo_sqlite and curl are already compiled into the base image)
mkdir -p tools
docker run --rm -v "$(pwd)":/app -w /app php:8.3-cli \
  sh -c "curl -fsSL https://phar.phpunit.de/phpunit-11.phar -o tools/phpunit.phar"

# run the suite
docker run --rm -v "$(pwd)":/app -w /app php:8.3-cli php tools/phpunit.phar
```

`tools/` is git-ignored — re-download the PHAR rather than committing a 5+ MB binary.

Feature/system tests (`tests/Feature/*`) spin up a real `php -S 127.0.0.1:<random-port> -t
public router.php` subprocess per test via `proc_open` (`tests/Support/TestServer.php`) and
drive it over real HTTP with a cookie-jar-backed client (`tests/Support/HttpClient.php`), so
session-based login state survives across requests within a test — this mirrors the
per-test-isolated-server pattern already used by the Go apps' `newTestApp(t)`. The readiness
probe polls `/score/__health__` rather than `/`, so the probe itself never fires an
`exploration` event before the test body runs.

### PHP-specific gotcha: `json_encode` and whole-number floats

`json_encode(['exploration' => 1.0])` produces `{"exploration":1}` by default — PHP drops the
decimal point from floats that happen to be whole numbers. `json_decode(..., true)` then reads
that back as a PHP `int`, not a `float`, which broke `assertSame(1.0, ...)` in strict-typed
test assertions. Fixed by passing `JSON_PRESERVE_ZERO_FRACTION` to the `json_encode()` call in
`router.php`'s score-JSON handler. This is specific to PHP — Go's and Node's JSON encode/decode
don't distinguish int vs float on numbers this way.

### Full-stack verification performed

`docker build` succeeded and a live container was smoke-tested end-to-end: home/about/login
pages 200; `.old`/`.swp` decoy suffixes 404 while firing `reconnaissance`; `config.php.bak`
returns 200 with the raw (unexecuted) leaked source and fires both `reconnaissance` and
`vulnerability_detection`; `config.php` itself (the real, live config file, outside `public/`)
404s, confirming it is never reachable regardless of extension handling; `POST
/admin/login.php` with credentials extracted from the leaked file succeeds, fires
`exploitation`, and the resulting session cookie unlocks `GET /admin/db_console.php`; wrong
`SCORE_TOKEN` on either `/score/<token>` or `/score/<token>/reset` returns 404; reset clears
all recorded events and scores.
