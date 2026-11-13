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
            "Enforce function-level authorization server-side, not by hiding links.")
    );

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
            + "<a href=\"/\">Home</a><a href=\"/tickets\">Tickets</a><a href=\"/scoreboard\">Scoreboard</a>");
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
                + "<p class=row><a class=btn href=/ticket/new>+ New ticket</a></p>"
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
                + "<p class=muted>owner: " + h(t.get("owner")) + "</p>"
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

        // ---- admin: forced browsing ---------------------------------------- //
        app.get("/admin", ctx -> {
            var u = requireUser(ctx);
            if (u == null) return;
            // VULN (A01): reachable by anyone who knows the URL; only hidden from the menu.
            if (!"admin".equals(u.get("role"))) {
                solve("forced_admin");
            }
            page(ctx, "<div class=card><h2>Admin panel</h2>"
                + "<p class=muted>Admin-only area. (Solving is detected server-side; see the scoreboard.)</p></div>");
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
    }
}
