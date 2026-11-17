# SecDevSW Vulnerability Lab

Self-hosted, intentionally vulnerable training lab for **OWASP Top 10:2025**.
No external accounts, no licensing constraints, runs offline — the part you own and
control, alongside hosted labs (PortSwigger/Juice Shop) for the attack-only drills.

> ⚠️ **Intentionally vulnerable.** The compose file binds every port to `127.0.0.1`.
> Never run this on a public, shared, or production network.

## Safe use — read before running

The apps contain **real** remote-code-execution flaws (OS command injection,
insecure deserialization) and an SSRF that fetches arbitrary URLs. Containment
comes from Docker, so:

1. **Run it only via `docker compose`.** Never start an app directly on your machine
   (`python app.py`, `java -jar …`, `dotnet run`): the command-injection and
   deserialization challenges would then execute on *your* host, not in a container.
2. **Only on your own machine, bound to localhost.** Do not change the `127.0.0.1`
   port bindings, and don't run it on a shared server, cloud VM, or lab PC others can reach.
3. **No GitHub Codespaces / cloud dev environments.** Their port forwarding can
   publish the apps to the internet.
4. **Stop it when you're done:** `docker compose down`.

### The flaws are deliberate
Every vulnerability, outdated pattern and hard-coded "credential" (e.g.
`S3cr3t-R00t-P@ss`) in this repository is intentional and fake. Please **don't file
security issues** for them. Scanner alerts (Dependabot, code scanning, secret
scanning) are expected — on day 3 they're part of the exercise.

## Quickstart

No Docker yet on **Kali Linux**? Run `sudo ./scripts/install-docker-kali.sh`. It
installs Docker Engine + the Compose plugin from Docker's official Debian repo
(pinned to `trixie`, since Kali reports `kali-rolling`, which Docker doesn't publish),
removes a conflicting `docker.io`, and adds you to the `docker` group (log out/in after).

```bash
docker compose up --build
```

Open **http://localhost:8080** for the landing page. Then start at the Python
challenge lab's scoreboard: **http://localhost:5000/scoreboard**.

| App | URL | Mode |
|-----|-----|------|
| Python/Flask | http://localhost:5000 | **Challenge lab** (Helpdesk + scoreboard) |
| Java/Javalin | http://localhost:7000 | **Challenge lab** (same Helpdesk, 11/12 — `deser` in progress) |
| .NET/C# | http://localhost:5001 | Demonstrator (vuln/secure routes) |

## Helpdesk challenge lab (Juice Shop / PSA style)

Implemented in Python/Flask (`apps/python`, reference) and Java/Javalin
(`apps/java`, port 7000) with the same challenge ids, flags and server-side solve
detection, so a cohort can work in its own stack. Paths below are identical in both;
only the port differs.

A single coherent **Helpdesk** application. Vulnerabilities are embedded in normal
features — you find and exploit them to reach a goal. The server **auto-detects**
each solve, flips it green on `/scoreboard`, and reveals the flag + the remediation
note. Progressive hints (3 per challenge) suit mixed-level cohorts.

| # | OWASP 2025 | Challenge | Diff | Where |
|---|---|---|---|---|
| 1 | A05 | Authentication bypass (SQLi) | easy | `/login` — `admin'--` |
| 2 | A01 | Read the admin's ticket (IDOR) | easy | `/ticket/<id>` (walk ids) |
| 3 | A01 | Forced browsing to admin | easy | `/admin` |
| 4 | A02/A10 | Verbose error / info disclosure | easy | ticket "Printable report" → `/report?id=abc` |
| 5 | A04 | Crack a leaked hash | easy | `/storage` |
| 6 | A05 | Credential exfiltration (UNION SQLi) | medium | ticket search |
| 7 | A01 | Privilege escalation (mass assignment) | medium | `POST /profile role=admin` |
| 8 | A05 | XXE file disclosure | medium | `/ticket/import` (XML) |
| 9 | A05 | Steal admin cookie (stored XSS → collector) | medium | ticket comment + `/collector/log` |
| 10 | A01 | SSRF via avatar fetch | medium | `/profile/avatar?url=` |
| 11 | A05 | OS command injection | hard | `/admin/ping` (needs the admin role) |
| 12 | A08 | Insecure deserialization | hard | profile export/import (Java: in progress) |

Notes:
- **Chained kill chain**: #7 (privesc) grants the admin role needed for #11 (command
  injection); #6 (UNION exfil) + #5 (crack) model loot-then-crack.
- **XSS is not arbitrary**: a background admin bot (every 2s) only "fires" on a real
  cookie-exfil payload (a sink **and** `document.cookie` **and** a URL). `alert(1)`
  proves nothing. It delivers the admin cookie to `/collector`; read `/collector/log`.
- **IDOR** target is the admin's ticket (you don't have that login), so it genuinely
  requires the flaw; reading another normal user's ticket doesn't count.
- **SSRF**: `/internal/metadata` only answers the server itself — you have to make
  the server fetch it.
- Seeded users: `alice/alicepw`, `bob/bobpw`, `admin/<secret>`. Register your own too.
- Reset state: restart the container (DB is reseeded on boot).

### Credential storage hands-on (A04) — `/storage`
A password shown under cleartext / MD5 / SHA-256 / PBKDF2 / Argon2id with a live
wordlist crack: fast hashes fall instantly, PBKDF2/Argon2id resist. Includes the
"crack the leaked MD5" challenge.

### Day-3 hardening — `/hardening`
Defensive targets that start **red** and go green as trainees fix `app.py`:
- **Security response headers** — a live self-check of CSP, HSTS, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy. Implement `set_headers()`
  (after_request) and set `SECURITY_HEADERS_ENABLED=True`.
- **CSP reporting** — add a CSP with `report-uri /csp-report`; violations collect there.
- **Logging & monitoring (A09)** — the `audit()` helper is barely called; wire it into
  login success/failure, access_denied and admin_action. The dashboard grades coverage.
This is the day-3 flow: read the source, fix the flaws + headers + logging, then run
code/dependency scanners (see A03 below).

#### Day-3 dev mode (live reload + kept progress)
Rebuilding on every edit is slow and wipes solve progress. For day 3, run the Python
app with the dev overlay:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up python
```

This bind-mounts `apps/python/app.py` and turns on Flask's reloader, so **saving the
file reloads the app in ~1s — no rebuild** — and moves the SQLite DB onto a named
volume so **solves survive reloads and restarts**. The loop is: edit `app.py` → save →
refresh `/hardening` and watch red go green, with your day-1/2 solves intact.

- **How headers get set:** the only nginx here serves the landing page — it is *not* a
  proxy in front of the app — so response headers must come from the app. Implement
  `set_headers()` (the `@app.after_request` hook) and set `SECURITY_HEADERS_ENABLED =
  True`. `/hardening` fetches the app's own `/` over loopback and grades the headers,
  so it needs no external scanner.
- **Reset progress:** `docker compose -f docker-compose.yml -f docker-compose.dev.yml
  down -v` (removes the volume), or set `RESET=1` for one boot.
- **Never use `debug=True`:** it exposes the Werkzeug console (arbitrary code
  execution). The overlay uses the reloader only.

### Teaching flow
Challenge-first, then remediation: learners exploit (Understand → Demonstrate →
Investigate), the scoreboard reveals the **Fix** note on solve, then they apply it in
the app's source and re-run the exploit to confirm it now fails (Remediate → Verify).
The .NET demonstrator's `/secure` handlers show a worked before/after.

### Adding a challenge
1. Append a dict to `CHALLENGES` in `apps/python/app.py` (id, cat, diff, goal, hints, flag, fix).
2. Embed the flaw in a feature handler; call `solve("<id>")` from the detection check.
3. Done — the scoreboard renders it automatically.

## Demonstrator app (.NET)

Side-by-side `/<class>/vuln` vs `/<class>/secure` routes for SQLi, XSS, IDOR and
cryptographic storage — the explicit before/after for the Remediate→Verify step.
**Conversion to the Helpdesk challenge model is the next step** for parity with
Python and Java. (`/hardening` is also Python-only so far.)

## Stack-level categories (no per-app route)

- **A03 Software Supply Chain Failures** — generate an SBOM and scan these images:
  ```bash
  syft secdevsw-lab-java:latest -o cyclonedx-json > sbom.json
  grype secdevsw-lab-java:latest        # or: trivy image secdevsw-lab-java:latest
  ```
  Pin an old `log4j-core` in `apps/java/pom.xml` and re-scan for a live finding.
- **A09 Security Logging & Alerting Failures** — compare a feature that logs security
  events against one that doesn't; show the difference in `docker compose logs`.
- **A06 Insecure Design** — threat-modeling exercise on the Helpdesk's own design
  (auth, object access, trust boundaries).

## Single-image variant

For a single `docker run` instead of a compose checkout, add a top-level Dockerfile
that installs the three runtimes and starts the apps under `supervisord` behind the
nginx landing. Larger image, simpler distribution; the compose layout stays the
source of truth.

## License

[MIT](LICENSE). No third-party lab content is bundled. The vulnerability patterns are
the standard textbook classes (same category as DVWA / Juice Shop). Provided for
education only, without warranty — see the safe-use rules above.
