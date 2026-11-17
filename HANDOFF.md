# Agent handoff — SecDevSW Vulnerability Lab (Helpdesk)

*Last updated: 2026-11-17 (evening before the Secure Coding / day-3 session).*

Brief for a planning or coding agent continuing this project. Read this, then `README.md`,
then the instructor docs (see *Instructor material* below).

## Instructor material: deliberately OUTSIDE the repo
Solution and teaching docs must **not** be in the repo or in any container image (trainees
clone the repo; dev mode bind-mounts the app folders into the containers). They live in a
sibling folder next to the repo: `../OWASP-DEMO-Helpdesk-instructor/`

| File | Content |
|---|---|
| `FIX-GUIDE.md` | Step-by-step remediation for H1–H3 + all 12 challenges, Python **and** C#: where (search string), why, fix, how to verify. All code tested. |
| `HARDENING-dotnet.md` | The former `apps/dotnet/HARDENING.md`: Linux-free C# day-3 walkthrough (setup, dev loop, `/hardening`, fix table, troubleshooting). |
| `PRESENTATION.md` | ~30-slide Marp deck for day 3, with speaker notes. |

Rules: never add solution/fix docs back into the repo; never reference them from repo
files, the landing page or the apps. `apps/python/.dockerignore` and
`apps/dotnet/.dockerignore` exclude `*.md` from build contexts as a safety net (bind
mounts in dev mode are NOT filtered by `.dockerignore`, so keep docs out of `apps/`).

## What this is
A self-hosted, intentionally vulnerable training lab for OWASP Top 10:2025: one
**Helpdesk** web app with 12 embedded challenges, a scoreboard with server-side solve
detection, and a day-3 `/hardening` dashboard where trainees fix the code. It's built
**three times at feature parity**, one per stack, so each cohort can work in its own
language. All run as a Docker Compose stack bound to `127.0.0.1`.

| Stack | Path | Port | Status |
|---|---|---|---|
| Python / Flask (**source of truth**) | `apps/python/app.py` (single file) | 5000 | 12/12, day-3 ready, **verified** |
| C# / ASP.NET Core 8 | `apps/dotnet/Program.cs` (single file) | 5001 | 12/12, day-3 ready, **verified** |
| Java / Javalin | `apps/java/src/main/java/lab/Main.java` | 7000 | 11/12 (`deser` missing), **no** day-3 surfaces, not used tomorrow |
| Landing page | `landing/` (nginx) | 8080 | static |

**Tomorrow's session uses only Python and C#.** Its goal is *Remediate → Verify*:
trainees patch the vulnerabilities and add security headers, CSP and audit logging, then
re-run each exploit to confirm it now fails.

## Repository / git state  ⚠ read first
- `main` = `3ab51b9`. `origin/dev` = `0590a4e`, which is `main` +2 commits (Python dev mode +
  .NET port) and fast-forwards cleanly.
- The local checkout is on branch **`dev`** (tracking `origin/dev`) with **uncommitted**
  changes from this session (below). **Nothing is committed, merged or pushed.** The owner
  wants to test by hand before anything goes to `main`. Don't merge or push without
  explicit approval.
- The repo lives on a WSL share (`\\wsl.localhost\kali-linux\...`). Git on Windows refuses
  it ("dubious ownership"), so use `git -c safe.directory=* <cmd>` per command and don't
  change the global config. Expect harmless LF→CRLF warnings.
- `scripts/install-docker-kali.sh` shows as modified **only because it lost its exec bit**
  (no content change). Restore it with `git checkout -- scripts/install-docker-kali.sh`
  before committing, or the README's `sudo ./scripts/install-docker-kali.sh` breaks.

### Uncommitted changes from this session
| File | Change |
|---|---|
| `apps/python/app.py`, `apps/dotnet/Program.cs` | **CSP-ready UI:** inline `<style>` and the hints `<script>` moved to `APP_CSS` / `HINTS_JS` constants served at `/assets/app.css` and `/assets/hints.js`; two inline `style=` attributes replaced by the classes `.btn.alt` and `.searchform`. Pages now contain **no inline code**, so a strict `default-src 'self'` CSP doesn't break the UI. |
| same | **XSS detection fix:** comment HTML now comes from one helper (`render_comment()` / `RenderComment()`), used by the ticket page **and** the admin bot. The bot fires only if the *rendered* output has a live sink (regex `<script\|<[a-z][^>]*[\s/]on[a-z]+\s*=`). Before this, escaping the output didn't stop the bot, so a correct fix looked broken. |
| `apps/dotnet/HARDENING.md` | **Deleted from the repo** (moved to the instructor folder as `HARDENING-dotnet.md`, updated: stronger CSP, `/assets` note, corrected #5, #9 → `RenderComment`, "guard above `Solve()`" rule). Commit this as a deletion. It still exists in git history on `origin/dev`. |
| `README.md`, `landing/index.html`, `Program.cs` header comment | All references to fix guides removed; README says instructor material is handed out separately. |
| `apps/python/.dockerignore`, `apps/dotnet/.dockerignore` (new) | Exclude `*.md` (+ `bin/ obj/`, `__pycache__/`, `*.db`) from image build contexts. |
| ⚠ `apps/dotnet/Program.cs` `SetSecurityHeaders` | Contains the owner's **manual test**: all six headers filled in. This is the H1 solution and **must be reverted** to the empty TODO body before committing. |

## Verification done this session (Docker Desktop on Windows, 2026-11-17)
- **Vulnerable apps:** both images build. A black-box exploit run solves **12/12** in Python
  and in C#, and the collector receives the admin cookie.
- **Dev overlay** (`docker-compose.dev.yml`): solves survive a container restart. Saving a
  source edit reloads the app without a rebuild (Flask reloader / `dotnet watch`), and
  `/hardening` went 0/6 → 6/6 headers.
- **Reference fixes** (every fix in FIX-GUIDE, applied to scratch copies): **11/12
  exploits blocked** in both stacks; only `crack_md5` stays solvable, by design. A
  functional check passes: assets served with the correct content types; all pages
  CSP-clean; login, wrong-password login, password change + re-login; legacy plaintext →
  hashed upgrade on first login; own-ticket view/comment (escaped); search scoped to the
  owner; benign XML import; profile export→import; admin ping; `/hardening` 6/6 headers +
  4/4 audit events.
- **Not verified:** a real browser rendering the pages with the strict CSP on (only a
  static scan for inline code); Java (untouched).

### Test tooling (⚠ ephemeral: in the session scratchpad, may be gone)
`C:\Users\CHRIS5~1\AppData\Local\Temp\claude\57ec7629ca437c75\d4a27198-455a-48f1-94b2-cc0ebbdea056\scratchpad\`
- `exploit_all.py <base> <in-container-port> <python|dotnet>`: runs all 12 exploits,
  reports solved/missing.
- `func_check.py <base> <vuln|fixed>`: the functional + CSP-clean check.
- `apply_fixes.py <app.py> <Program.cs>`: applies every reference fix as anchored,
  asserted string patches (this is the source of the FIX-GUIDE snippets).
- `fixed/`: fully fixed copies of both apps + a compose file (ports 5060/5061).
- `port-override.yml`: maps Python to host port 5050 (see the port clash below).

**Recommended:** copy these into the instructor folder (they encode solutions, so not
into the repo) so they survive the session. Ask the owner first.

## Invariants — do not break
- **Localhost only.** Every compose port stays bound to `127.0.0.1`. Never run the apps
  outside Docker (real RCE via cmdi and deser).
- **Flags appear only via the exploit or on the scoreboard after solving.**
- **Each challenge = one registry entry + a flaw inside a normal feature + server-side
  detection** that fires only on the real exploit (cross-owner access, exfiltrated data, a
  live XSS sink plus `document.cookie` plus a URL, not `alert(1)`).
- **Parity:** same challenge ids, flags, routes and detection semantics across stacks. The
  Python app leads.
- **No inline code in page templates** (no `<style>`, inline `<script>`, `style=` or `on*=`).
  New CSS/JS goes into `APP_CSS` / `HINTS_JS` (or new `/assets/*` routes). Otherwise the
  CSP lesson breaks.
- **XSS detection must judge rendered output** via the shared `render_comment` /
  `RenderComment`, so the encoding fix is observable.
- **Detection lines sit above where fixes go** (e.g. `solve("idor")` after the fetch).
  FIX-GUIDE tells trainees to put guards *above* them. Don't move detection in a way that
  changes this without updating the guide.
- **Teaching arc:** exploit → scoreboard reveals the fix note → fix in source → re-run the
  exploit to verify. Solves are never revoked.
- **Never `debug=True`** in Flask (Werkzeug console = RCE). Dev mode uses the reloader only.

## Known issues / gotchas for tomorrow
1. **Host port 5000 clash on the owner's machine:** an unrelated container
   `dice-poker-web-1` binds `0.0.0.0:5000` and starts with Docker Desktop. Stop it before
   starting the Python app. Trainee machines may hit the same clash (e.g. macOS AirPlay
   uses 5000).
2. **The scoreboard can't show "fixed".** Verification is manual (re-run the exploit).
3. **After fix #5 (hashing)**, the `sqli_login` detection compares the submitted password
   with the stored hash, so a *legitimate* admin login would count as a solve. Harmless in
   class (the admin password is secret); FIX-GUIDE says the line can be deleted.
4. **HSTS** is graded for presence only; browsers ignore it on plain-HTTP localhost.
5. **The admin bot ignores CSP** (it models an old browser), so the CSP alone doesn't stop
   #9 from solving. This is intentional and explained in the guide (CSP mitigates,
   encoding fixes).
6. **Solve state is global** per app instance (one DB), with no per-user progress. Fine
   when each trainee runs their own stack locally.
7. **Instructor docs are out of the repo** (decided). Distribute them separately, e.g. as a
   handout after the session. The old `HARDENING.md` remains visible in git history.
8. The C# build prints `warning CS8321: 'Audit' declared but never used`. Expected until
   trainees wire it up (H3).

## Backlog (prioritised)
1. **Before tomorrow, owner-driven:** the owner's manual test → restore the exec bit →
   revert the test headers in `Program.cs` → commit on `dev` (including the
   `HARDENING.md` deletion) → merge to `main` (only on approval). Optionally persist the
   test tooling + reference fixes (in the instructor folder, **not** in the repo).
2. **Browser-verify the strict CSP** on all pages (styling + hint button), and the
   CSP-report demo (unfixed XSS + CSP → `/csp-report` counter climbs).
3. **Java parity:** CSP refactor (check for inline CSS/JS), `render_comment` + bot change,
   `/hardening` (headers/CSP/audit), dev overlay (`docker-compose.dev.yml` service + live
   reload), `deser` (an app class whose `readObject` drops `/tmp/deser_pwned`, with no
   vulnerable library), and Java sections in FIX-GUIDE.
4. **Classroom quality:** a "verify mode" per challenge (e.g. a button that re-runs the
   exploit server-side and shows *still vulnerable / fixed*); a reset endpoint;
   per-session solve state.
5. **Deepen the challenge set** (Python first, then port): CSRF, JWT `alg:none` / weak
   secret, blind SQLi, open redirect, path traversal, a business-logic flaw.
6. **Day-3 tooling:** a `semgrep` ruleset, `trivy`/`grype`/`syft` config, and a one-page
   worksheet.
7. **Single-image variant** (supervisord) as described in the README.

## Run & verify (quick reference)
```bash
docker compose up --build                                   # days 1-2, whole stack
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build python dotnet  # day 3
docker compose -f docker-compose.yml -f docker-compose.dev.yml down -v                   # reset
```
Fast check: run `exploit_all.py` against a fresh container (expect `12 / 12 solved`); for
a fixed build, expect only `crack_md5` and run `func_check.py ... fixed` (expect `ALL OK`).
Seeded users: `alice/alicepw`, `bob/bobpw`, `admin/S3cr3t-R00t-P@ss` (fake, intentional).

## Adding a challenge (pattern)
1. Append to `CHALLENGES` (id, cat, diff, title, goal, hints[3], flag, fix) **in Python
   first**, then port to C# (and Java).
2. Embed the flaw in a feature handler, marked `# VULN (Axx): …`; call `solve("<id>")` only
   on the true exploit condition.
3. Keep flags out of non-exploit content; no inline JS/CSS; add a section to the
   instructor `FIX-GUIDE.md` and a slide (outside the repo).
