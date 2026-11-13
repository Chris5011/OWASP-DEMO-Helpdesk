// SecDevSW Vulnerability Lab - .NET / C# minimal API parallel implementation.
// INTENTIONALLY VULNERABLE. Localhost only.
// Mirrors the Python reference: each class has /vuln and /secure routes.
using Microsoft.Data.Sqlite;
using System.Net;
using System.Security.Cryptography;
using System.Text;

const string DB = "Data Source=/tmp/lnet.db";
Seed();

var app = WebApplication.CreateBuilder(args).Build();

app.MapGet("/", () => Results.Content(
    "<h1>SecDevSW Lab &middot; .NET/C#</h1><p>Intentionally vulnerable &mdash; localhost only.</p><ul>"
  + "<li>A05 SQLi: <a href='/sqli/vuln?name=admin'>/sqli/vuln</a> | <a href='/sqli/secure?name=admin'>/sqli/secure</a></li>"
  + "<li>A05 XSS: <a href='/xss/vuln?q=hi'>/xss/vuln</a> | <a href='/xss/secure?q=hi'>/xss/secure</a></li>"
  + "<li>A01 IDOR: <a href='/idor/vuln?id=1'>/idor/vuln</a> | <a href='/idor/secure?id=1&user=alice'>/idor/secure</a></li>"
  + "<li>A04 Crypto: <a href='/crypto/vuln?pw=secret'>/crypto/vuln</a> | <a href='/crypto/secure?pw=secret'>/crypto/secure</a></li>"
  + "</ul>", "text/html"));

// --- A05 SQL injection ---
app.MapGet("/sqli/vuln", (string name) =>
{
    using var c = new SqliteConnection(DB); c.Open();
    // VULN: interpolated user input in the SQL text.
    var sql = $"SELECT id,name FROM users WHERE name = '{name}'";
    using var cmd = new SqliteCommand(sql, c);
    return Results.Text("query: " + sql + "\n" + ReadRows(cmd));
});
app.MapGet("/sqli/secure", (string name) =>
{
    using var c = new SqliteConnection(DB); c.Open();
    // SECURE: parameterized query.
    using var cmd = new SqliteCommand("SELECT id,name FROM users WHERE name = $n", c);
    cmd.Parameters.AddWithValue("$n", name);
    return Results.Text(ReadRows(cmd));
});

// --- A05 XSS ---
// VULN: raw reflection into HTML.
app.MapGet("/xss/vuln", (string q) => Results.Content($"<h3>Results for: {q}</h3>", "text/html"));
// SECURE: HTML-encode the untrusted value.
app.MapGet("/xss/secure", (string q) =>
    Results.Content($"<h3>Results for: {WebUtility.HtmlEncode(q)}</h3>", "text/html"));

// --- A01 IDOR ---
// VULN: no ownership check.
app.MapGet("/idor/vuln", (string id) => Results.Text(FetchUser(id, null)));
// SECURE: record must belong to the caller.
app.MapGet("/idor/secure", (string id, string? user) => Results.Text(FetchUser(id, user ?? "alice")));

// --- A04 cryptographic storage ---
app.MapGet("/crypto/vuln", (string pw) =>
{
    // VULN: unsalted MD5.
    var hash = Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(pw))).ToLower();
    return Results.Text("md5: " + hash);
});
app.MapGet("/crypto/secure", (string pw) =>
{
    // SECURE: bcrypt (salted, slow). Package: BCrypt.Net-Next.
    var h = BCrypt.Net.BCrypt.HashPassword(pw);
    return Results.Text($"bcrypt: {h} verifies={BCrypt.Net.BCrypt.Verify(pw, h)}");
});

app.Run("http://0.0.0.0:5001");

// --- helpers ---
static string ReadRows(SqliteCommand cmd)
{
    var sb = new StringBuilder();
    try
    {
        using var r = cmd.ExecuteReader();
        while (r.Read()) sb.AppendLine($"{r.GetInt32(0)},{r.GetString(1)}");
    }
    catch (SqliteException e) { sb.Append("error: " + e.Message); }
    return sb.ToString();
}

static string FetchUser(string id, string? caller)
{
    using var c = new SqliteConnection(DB); c.Open();
    using var cmd = new SqliteCommand("SELECT id,name,owner,secret FROM users WHERE id=$id", c);
    cmd.Parameters.AddWithValue("$id", id);
    using var r = cmd.ExecuteReader();
    if (!r.Read()) return "not found";
    if (caller != null && r.GetString(2) != caller) return "forbidden";
    return $"id={r.GetInt32(0)} name={r.GetString(1)} secret={r.GetString(3)}";
}

static void Seed()
{
    using var c = new SqliteConnection(DB); c.Open();
    foreach (var sql in new[]
    {
        "DROP TABLE IF EXISTS users",
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, owner TEXT, secret TEXT)",
        "INSERT INTO users VALUES (1,'admin','admin','admin-flag-A1B2'),(2,'alice','alice','alice-private-note'),(3,'bob','bob','bob-private-note')"
    })
    {
        using var cmd = new SqliteCommand(sql, c); cmd.ExecuteNonQuery();
    }
}
