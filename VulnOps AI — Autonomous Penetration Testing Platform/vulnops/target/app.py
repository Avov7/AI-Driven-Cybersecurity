"""
VulnOps AI — Mock Vulnerable Target

This is an INTENTIONALLY misconfigured Flask application for demo purposes only.
It simulates a real-world poorly-configured web application so that the VulnOps
AI scanner has something interesting to find.

DO NOT deploy this in production.
"""
from flask import Flask, jsonify, Response, request

app = Flask(__name__)


# ── Intentionally bad response headers ────────────────────────────────────────
@app.after_request
def add_bad_headers(response):
    # Reveals technology stack
    response.headers["Server"]       = "Apache/2.4.49 (Debian)"
    response.headers["X-Powered-By"] = "Python/3.11 Flask/2.1.0"
    # Missing: X-Frame-Options, CSP, HSTS, X-Content-Type-Options, Referrer-Policy
    return response


# ── Main page ──────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return """
    <html>
      <head><title>VulnCorp Employee Portal</title></head>
      <body>
        <h1>VulnCorp Internal Employee Portal</h1>
        <p>Welcome. Please <a href="/login">log in</a>.</p>
      </body>
    </html>
    """


# ── Login page (no brute-force protection) ────────────────────────────────────
@app.route("/login")
def login():
    return """
    <html>
      <body>
        <h2>Login</h2>
        <form method="POST" action="/login">
          <input name="username" placeholder="Username" /><br/>
          <input name="password" type="password" placeholder="Password" /><br/>
          <button type="submit">Login</button>
        </form>
      </body>
    </html>
    """


# ── Admin panel — NO authentication ──────────────────────────────────────────
@app.route("/admin")
def admin():
    return jsonify({
        "status":  "ok",
        "message": "Admin Panel — No authentication required",
        "users": [
            {"id": 1, "username": "admin",   "role": "superadmin", "email": "admin@vulncorp.com"},
            {"id": 2, "username": "alice",   "role": "editor",     "email": "alice@vulncorp.com"},
            {"id": 3, "username": "bob",     "role": "viewer",     "email": "bob@vulncorp.com"},
        ],
        "system_info": {
            "db_host": "postgres-internal",
            "app_version": "1.0.3",
            "debug_mode": True,
        },
    })


# ── .env file exposed ─────────────────────────────────────────────────────────
@app.route("/.env")
def env_file():
    return Response(
        "DB_HOST=postgres\n"
        "DB_USER=admin\n"
        "DB_PASSWORD=VulnCorp2024!\n"
        "SECRET_KEY=dev-not-safe-key-please-change\n"
        "API_KEY=sk-demo-fake-key-1234567890\n"
        "STRIPE_SECRET=sk_test_fakefakefake\n"
        "DEBUG=True\n",
        mimetype="text/plain",
    )


# ── API — unauthenticated user listing with open CORS ─────────────────────────
@app.route("/api/users")
def api_users():
    resp = jsonify([
        {"id": 1, "username": "admin",   "email": "admin@vulncorp.com",   "last_login": "2026-06-27"},
        {"id": 2, "username": "alice",   "email": "alice@vulncorp.com",   "last_login": "2026-06-26"},
        {"id": 3, "username": "charlie", "email": "charlie@vulncorp.com", "last_login": "2026-06-25"},
    ])
    # Open CORS — allows any origin
    resp.headers["Access-Control-Allow-Origin"]      = "*"
    resp.headers["Access-Control-Allow-Methods"]     = "GET, POST, PUT, DELETE"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


# ── robots.txt — reveals sensitive paths ──────────────────────────────────────
@app.route("/robots.txt")
def robots():
    return Response(
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /backup\n"
        "Disallow: /internal\n"
        "Disallow: /.env\n"
        "Disallow: /api/users\n"
        "Disallow: /api/admin\n"
        "Disallow: /config\n",
        mimetype="text/plain",
    )


# ── Backup archive (pretend) ──────────────────────────────────────────────────
@app.route("/backup.zip")
def backup():
    # Return fake content — just to show it's accessible
    return Response(
        b"PK\x03\x04FAKEZIP",
        mimetype="application/zip",
        headers={"Content-Disposition": "attachment; filename=backup.zip"},
    )


# ── Config JSON exposed ────────────────────────────────────────────────────────
@app.route("/config.json")
def config():
    return jsonify({
        "db_url":       "postgresql://admin:VulnCorp2024!@localhost/appdb",
        "redis_url":    "redis://localhost:6379",
        "jwt_secret":   "not-a-real-secret",
        "allowed_hosts": ["*"],
        "debug":        True,
    })


# ── Health check ──────────────────────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
