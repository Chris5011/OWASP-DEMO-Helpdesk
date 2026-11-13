package lab;

import io.javalin.Javalin;
import java.sql.*;
import org.mindrot.jbcrypt.BCrypt;

/**
 * SecDevSW Vulnerability Lab - Java / Javalin parallel implementation.
 * INTENTIONALLY VULNERABLE. Localhost only.
 * Mirrors the Python reference: each class has /vuln and /secure routes.
 */
public class Main {
    static Connection conn;

    public static void main(String[] args) throws Exception {
        conn = DriverManager.getConnection("jdbc:sqlite:/tmp/ljava.db");
        seed();

        Javalin app = Javalin.create();

        app.get("/", ctx -> ctx.html(
            "<h1>SecDevSW Lab &middot; Java/Javalin</h1><p>Intentionally vulnerable &mdash; localhost only.</p>"
          + "<ul>"
          + "<li>A05 SQLi: <a href='/sqli/vuln?name=admin'>/sqli/vuln</a> | <a href='/sqli/secure?name=admin'>/sqli/secure</a></li>"
          + "<li>A05 XSS: <a href='/xss/vuln?q=hi'>/xss/vuln</a> | <a href='/xss/secure?q=hi'>/xss/secure</a></li>"
          + "<li>A01 IDOR: <a href='/idor/vuln?id=1'>/idor/vuln</a> | <a href='/idor/secure?id=1&user=alice'>/idor/secure</a></li>"
          + "<li>A04 Crypto: <a href='/crypto/vuln?pw=secret'>/crypto/vuln</a> | <a href='/crypto/secure?pw=secret'>/crypto/secure</a></li>"
          + "</ul>"));

        // --- A05 SQL injection ---
        app.get("/sqli/vuln", ctx -> {
            String name = ctx.queryParam("name");
            // VULN: user input concatenated into SQL text.
            String q = "SELECT id,name FROM users WHERE name = '" + name + "'";
            StringBuilder sb = new StringBuilder("query: " + q + "\n");
            try (Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(q)) {
                while (rs.next()) sb.append(rs.getInt("id")).append(",").append(rs.getString("name")).append("\n");
            } catch (SQLException e) { sb.append("error: ").append(e.getMessage()); }
            ctx.result(sb.toString());
        });
        app.get("/sqli/secure", ctx -> {
            // SECURE: PreparedStatement - input bound as data.
            try (PreparedStatement ps = conn.prepareStatement("SELECT id,name FROM users WHERE name = ?")) {
                ps.setString(1, ctx.queryParam("name"));
                ResultSet rs = ps.executeQuery();
                StringBuilder sb = new StringBuilder();
                while (rs.next()) sb.append(rs.getInt("id")).append(",").append(rs.getString("name")).append("\n");
                ctx.result(sb.toString());
            }
        });

        // --- A05 XSS ---
        app.get("/xss/vuln", ctx -> {
            // VULN: raw reflection into HTML.
            ctx.html("<h3>Results for: " + ctx.queryParam("q") + "</h3>");
        });
        app.get("/xss/secure", ctx -> {
            // SECURE: context-aware output encoding before it reaches HTML.
            ctx.html("<h3>Results for: " + escapeHtml(ctx.queryParam("q")) + "</h3>");
        });

        // --- A01 IDOR ---
        app.get("/idor/vuln", ctx -> {
            // VULN: fetch by id, no ownership check.
            ctx.result(fetchUser(ctx.queryParam("id"), null));
        });
        app.get("/idor/secure", ctx -> {
            // SECURE: enforce that the record belongs to the caller.
            String user = ctx.queryParam("user") == null ? "alice" : ctx.queryParam("user");
            ctx.result(fetchUser(ctx.queryParam("id"), user));
        });

        // --- A04 cryptographic storage ---
        app.get("/crypto/vuln", ctx -> {
            // VULN: unsalted MD5.
            ctx.result("md5: " + md5(ctx.queryParam("pw")));
        });
        app.get("/crypto/secure", ctx -> {
            // SECURE: bcrypt (salted, slow).
            String pw = ctx.queryParam("pw");
            String h = BCrypt.hashpw(pw, BCrypt.gensalt());
            ctx.result("bcrypt: " + h + " verifies=" + BCrypt.checkpw(pw, h));
        });

        app.start(7000);
    }

    static String fetchUser(String id, String caller) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT id,name,owner,secret FROM users WHERE id=?")) {
            ps.setString(1, id);
            ResultSet rs = ps.executeQuery();
            if (!rs.next()) return "not found";
            if (caller != null && !rs.getString("owner").equals(caller)) return "forbidden";
            return "id=" + rs.getInt("id") + " name=" + rs.getString("name") + " secret=" + rs.getString("secret");
        }
    }

    static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#x27;");
    }

    static String md5(String s) throws Exception {
        byte[] d = java.security.MessageDigest.getInstance("MD5").digest(s.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : d) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    static void seed() throws SQLException {
        try (Statement st = conn.createStatement()) {
            st.executeUpdate("DROP TABLE IF EXISTS users");
            st.executeUpdate("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, owner TEXT, secret TEXT)");
            st.executeUpdate("INSERT INTO users VALUES "
                + "(1,'admin','admin','admin-flag-A1B2'),"
                + "(2,'alice','alice','alice-private-note'),"
                + "(3,'bob','bob','bob-private-note')");
        }
    }
}
