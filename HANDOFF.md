# Agent handoff — SecDevSW Vulnerability Lab

Brief for continuing this project in an agentic coding session (Claude Code / your
orchestrator). Read this + `README.md` first, then pick from the backlog.

## What this is
A self-hosted, intentionally vulnerable training lab for OWASP Top 10:2025.
`apps/python/` is the mature **challenge app** (12 challenges, a Helpdesk web app with
a scoreboard). `apps/java/` (Javalin, single `Main.java`) is at parity for 11/12 —
`deser` is pending. `apps/dotnet/` is still the older **demonstrator** pattern
(side-by-side `/vuln` and `/secure` routes). Landing + compose tie it together.

## Invariants — do not break these
- **Localhost only.** Keep compose bound to `127.0.0.1`. It is deliberately vulnerable.
- **Flags appear only via the exploit or on the scoreboard after solving.** Never print a
  flag in page content reachable without the exploit (this was a bug class we fixed:
  IDOR flag in a ticket body, flag on the admin panel). Loot-style flags that *require*
  the exploit to retrieve are fine (cmdi file, XXE file, SSRF metadata, XSS→collector).
- **Each challenge = one registry entry + an embedded flaw + server-side detection.**
  `CHALLENGES` holds id/cat/diff/goal/hints/flag/fix; the flaw lives in a normal feature;
  a `solve("<id>")` call fires only on the real exploit condition (e.g. cross-owner
  access, injection that returns data, a cookie-exfil payload — not a bare `alert(1)`).
- **Keep the teaching arc**: exploit first, then the scoreboard reveals the fix note;
  `/hardening` and `/storage` are the day-3 "fix it in source" surfaces.
- Verify changes; don't regress the 12/12 (see Verification).

## Architecture (Python app)
- Single `apps/python/app.py`, Flask, inline Jinja templates, SQLite at `/tmp/helpdesk.db`
  (reseeded on boot). Deps: flask, argon2-cffi, lxml. Dockerfile installs `iputils-ping`.
- `CHALLENGES` registry → `/scoreboard` renders it; `solve()`/`solved_ids()` persist solves.
- `admin_bot` daemon thread simulates the XSS victim (exfil-only detection).
- Feature routes carry the flaws: `/login` (SQLi), `/ticket/<id>` (IDOR), `/search`
  (UNION), `/ticket/import` (XXE), `/profile` (mass-assignment, SSRF, pickle),
  `/admin/ping` (cmdi), `/report` (error disclosure), `/storage` (A04 + crack),
  `/hardening` (headers/CSP/logging self-check), `/collector` (XSS sink).

## Run & verify
```bash
docker compose up --build        # whole stack; Python challenge app on :5000
```
Fast correctness check without Docker (Python only), expect `SOLVED 12/12`:
drive each challenge through `app.test_client()` and assert every id in `CHALLENGES`
is in the `solved` table (see the pattern used during development — login, cross-owner
ticket view, UNION search, role=admin POST, XXE import, SSRF url, cmdi ping, double
pickle import, cookie-exfil comment). The XSS bot needs ~3s.

## Backlog (prioritised)
1. **Language parity**: Java — add `deser` (an app class whose `readObject` drops the
   `/tmp/deser_pwned` canary; no vulnerable library). .NET — convert from demonstrator to
   the Helpdesk challenge model — same challenge ids, flags, and server-side
   solve-detection. Keep the invariants above.
1b. **Day-3 dev mode** (to discuss): DB on a named volume + seed-once so code edits and
   restarts don't wipe solves; `docker-compose.dev.yml` with source bind mounts
   (Python `use_reloader=True, debug=False` — never the Werkzeug debugger).
2. **Deepen the Python set**: CSRF (state-changing form, no token), JWT `alg:none` /
   weak-secret, blind/boolean SQLi, open redirect, path traversal, a business-logic flaw.
3. **Day-3 deliverables**: ship a `semgrep` ruleset + `trivy`/`grype`/`syft` config and a
   one-page remediation worksheet; provide a reference "fixed" branch/flag for `/hardening`
   (headers + CSP `report-uri` + `audit()` calls) so instructors can diff.
4. **Classroom hardening**: per-session solve state (currently global), a reset endpoint,
   and the single-image `supervisord` variant noted in the README.

## Adding a challenge (pattern)
1. Append a dict to `CHALLENGES` (id, cat, diff, goal, hints[3], flag, fix).
2. Embed the flaw in a feature handler; call `solve("<id>")` only on the true exploit.
3. Keep any flag out of non-exploit content. Done — the scoreboard renders it.
