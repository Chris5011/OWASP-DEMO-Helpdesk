# Fixing the .NET Helpdesk — a day-3 guide for C# developers

This is the hands-on remediation guide for the **.NET / C# Helpdesk** challenge lab.
It assumes you are comfortable in **C# and Visual Studio / VS Code / Rider**, but **not**
on the Linux command line. You never need a Linux shell: everything runs in Docker and
you edit `Program.cs` in your normal editor.

> The whole app is one file: **`apps/dotnet/Program.cs`**. Every fix below is an edit to
> that file. You do not rebuild the image or restart anything by hand — a *dev mode*
> watches the file and reloads for you.

---

## 0. One-time setup (Windows or macOS)

1. Install **Docker Desktop** (<https://www.docker.com/products/docker-desktop/>) and
   start it. Wait until the whale icon says *Docker Desktop is running*.
2. Open a terminal **in the repo root** (the folder with `docker-compose.yml`):
   - **Windows:** right-click the folder → *Open in Terminal* (PowerShell), or in VS Code
     *Terminal → New Terminal*.
   - **macOS:** *Terminal*, then `cd` into the folder (drag the folder onto the Terminal
     window to paste its path).

That is the only command line you need. All commands below are **the same on Windows,
macOS and Linux** — Docker hides the OS differences.

---

## 1. Run the lab (days 1–2, attack mode)

```bash
docker compose up --build dotnet
```

Open **<http://localhost:5001/scoreboard>**. Leave this window running; `Ctrl+C` stops it.

- Everything is bound to `127.0.0.1` (localhost) only — nothing is exposed to your
  network. Keep it that way.
- Restarting the container resets all progress (fresh database every boot).

---

## 2. Day-3 dev mode (edit → save → see it go green)

For fixing, use the **dev overlay**. It does two things the normal run does not:

- **Hot reload:** when you save `Program.cs`, the app recompiles in ~1–2 seconds. No
  rebuild, no manual restart.
- **Kept progress:** your solved challenges live on a Docker volume, so they survive
  reloads *and* restarts.

Start it (one line — copy the whole thing):

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up dotnet
```

Now the loop is:

1. Open **`apps/dotnet/Program.cs`** in your editor.
2. Make a fix (see sections below).
3. **Save.** Watch the terminal print `dotnet watch 🔥 Hot reload of changes succeeded`.
4. Refresh the page (e.g. **<http://localhost:5001/hardening>**) and watch red turn green.

> **Most edits apply in ~1s.** A few bigger *structural* edits (adding a new top-level
> variable, changing a type) make `dotnet watch` do a quick full **restart** instead —
> you'll see `Restarting...`. Either way your solved challenges are kept. If the terminal
> ever shows a **build error**, the old version keeps running; fix the C# error, save
> again, and it recovers.

**Reset everything (wipe solves + database):**

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml down -v
```

(The `-v` removes the saved database volume. Without `-v`, a restart keeps your progress.)

---

## 3. The three hardening targets on `/hardening`

Open **<http://localhost:5001/hardening>**. Three panels start **red**. You make them green
by editing `Program.cs`.

### 3a. Security response headers

The app sets **no** security headers. There is no reverse proxy doing it for you — in this
lab the only nginx just serves the landing page, so headers must come from the app itself.

Find this method in `Program.cs` (search for `SetSecurityHeaders`):

```csharp
void SetSecurityHeaders(HttpResponse resp)
{
    // TODO(trainee): add the headers in REQUIRED_HEADERS here.
}
```

Fill it in. A solid starting set:

```csharp
void SetSecurityHeaders(HttpResponse resp)
{
    resp.Headers["Content-Security-Policy"]   = "default-src 'self'; report-uri /csp-report";
    resp.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
    resp.Headers["X-Frame-Options"]           = "DENY";
    resp.Headers["X-Content-Type-Options"]    = "nosniff";
    resp.Headers["Referrer-Policy"]           = "no-referrer";
    resp.Headers["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()";
}
```

Save, refresh `/hardening` → all six rows go **green**. (This method already runs on every
response via `app.Use(...)`; you only fill in the body.)

### 3b. CSP reporting

The CSP above ends with `report-uri /csp-report`. The `/csp-report` endpoint already
exists and counts what it receives. Once a browser hits a page that violates your policy,
the counter on `/hardening` climbs. (In real life you'd ship these to your log pipeline.)

### 3c. Security logging & monitoring (A09)

There is a helper:

```csharp
void Audit(string ev, string detail = "") { /* writes one row to the audit table */ }
```

It is barely called. `/hardening` wants to see four event types logged. Add `Audit(...)`
calls at the security-relevant points (the TODO comments mark them):

| Event to log      | Where in `Program.cs`                                              |
|-------------------|-------------------------------------------------------------------|
| `login_success`   | `/login` POST, after a successful sign-in                          |
| `login_failure`   | `/login` POST, on invalid credentials                             |
| `access_denied`   | wherever you return **403** (e.g. `/report`, `/admin/ping`)        |
| `admin_action`    | `/admin/ping` when an admin runs diagnostics                      |

Example:

```csharp
Audit("login_success", name);
Audit("login_failure", u);
Audit("access_denied", $"report id={rid} by {u.Name}");
Audit("admin_action", $"ping host={host}");
```

Save → the A09 panel rows flip to **green** as each event type shows up.

---

## 4. Fixing the 12 vulnerabilities (Remediate → Verify)

Each scoreboard challenge reveals a short **Fix** note when solved. Below is the concrete
C# version for this app. After a fix, **re-run the exploit and confirm it no longer
works** — that is the "Verify" step. (Fixing a challenge does not un-solve it on the
scoreboard; the solve is a historical record. Verify by re-attacking and seeing it fail.)

| # | id | Vulnerable pattern (what to find) | The C# fix |
|---|----|-----------------------------------|------------|
| 1 | `sqli_login` | `$"... WHERE name = '{u}' ..."` string-built SQL in `/login` | Use a parameterised `SqliteCommand` with `$u`/`$p` parameters; never interpolate input into SQL. |
| 2 | `idor` | `/ticket/{id}` loads any ticket, no owner check | After loading, check `owner == u.Name` (or `u.Role == "admin"`); otherwise return 403. |
| 3 | `forced_admin` | `/admin` renders for anyone | At the top: `if (u.Role != "admin") return 403;` — authorize server-side, don't just hide the menu link. |
| 4 | `error_disclosure` | `/report` shows the full exception + a fake `DB_PASS` | `int.TryParse(...)`; on bad input return a generic message; log the detail with `Audit`, never render stack traces. |
| 5 | `crack_md5` | `/storage` stores the demo password as unsalted MD5 | Store with **Argon2id** (or PBKDF2). The page already shows these as the "green" schemes. |
| 6 | `sqli_union` | `/search` concatenates `q` into a `LIKE` query | Parameterise: `... WHERE title LIKE $q` with `cmd.Parameters.AddWithValue("$q", "%" + q + "%")`. |
| 7 | `privesc` | `/profile` POST writes every field, including `role` | Bind an allow-list of **only** `password`; never let the client set `role`. Remove `role` from the accepted fields. |
| 8 | `xxe` | `/ticket/import` sets `XmlResolver` + `DtdProcessing.Parse` | Set `XmlResolver = null` and `DtdProcessing = DtdProcessing.Prohibit` (the secure defaults). Better: accept JSON, not XML. |
| 9 | `xss_stored` | comments rendered **unescaped** in `/ticket/{id}` | HTML-encode the comment body on render: `Enc(commentBody)` (as every other field already does). Add the CSP from §3a. |
| 10 | `ssrf` | `/profile/avatar` fetches any user URL server-side | Allow-list the host; reject loopback/link-local (`127.0.0.1`, `localhost`, `169.254.169.254`, `0.0.0.0`) before fetching. |
| 11 | `cmdi` | `/admin/ping` runs `"ping -c1 " + host` through `/bin/sh -c` | Don't use a shell. Validate `host` against an IP/hostname allow-list, then pass `ping`'s args as an argument vector (no `/bin/sh`). |
| 12 | `deser` | `/profile/import` uses `TypeNameHandling.All` | Deserialize into a fixed type with `TypeNameHandling.None` (the default) and a schema; never let the blob choose its own type. |

> Fixes like #1, #6, #9 are **method-body edits** and hot-reload instantly. #3, #4, #10,
> #11 add a check at the top of a handler — also instant. All of them keep your progress.

---

## 5. Then: scan the stack (A03 supply chain)

Day-3 also includes dependency scanning. From the repo root:

```bash
syft secdevsw-lab-dotnet:latest -o cyclonedx-json > sbom-dotnet.json
grype secdevsw-lab-dotnet:latest        # or: trivy image secdevsw-lab-dotnet:latest
```

To get a guaranteed finding, pin an old package in `apps/dotnet/lab.csproj` (e.g. an
outdated `Newtonsoft.Json`) and re-scan.

---

## 6. Troubleshooting (no Linux needed)

| Symptom | Fix |
|---|---|
| `docker: command not found` / nothing happens | Docker Desktop isn't running. Start it; wait for the whale icon. |
| `port is already allocated` / `:5001` in use | Something else uses 5001, or an old container is up. Run `docker compose down`, then start again. |
| Edits don't reload | You're in **normal** mode. Use the **dev overlay** command in §2. |
| Red won't go green after an edit | Check the terminal for a **build error** (red text); fix the C# and save again. Then hard-refresh the browser (`Ctrl+F5`). |
| Want to see logs | Docker Desktop → *Containers* → click `dotnet` → **Logs** tab (no CLI needed). |
| Start over completely | `docker compose -f docker-compose.yml -f docker-compose.dev.yml down -v` (the `-v` wipes saved progress). |

---

*This file is remediation guidance, not an attack key. It lives in the repo on purpose.
The exploit answer key is kept separately by your instructor.*
