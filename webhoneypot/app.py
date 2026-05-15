"""
app.py — Webhoneypot (HTTP Honeypot)
======================================
Flask application that simulates a vulnerable web server to attract and
capture HTTP-based attacks: SQLi, XSS, SSTI, XXE, LFI, SSRF, admin enumeration,
malicious uploads and scanner probing.

Every incoming request is captured by the before_request hook and written
to http_events.jsonl before any route handler runs. The logged fields
(method, path, query, user_agent, content_type, body) exactly match the
fields consumed by featurize_http() in feature_extraction.py — ensuring
full consistency between captured logs and ML feature extraction.

The server never executes payloads — it simply returns plausible responses
to keep attackers engaged while the collector processes their activity.

Exposed endpoints (port 8081):
    /                   Homepage
    /admin, /wp-admin   Admin panel stubs → 403
    /login, /signin     Auth forms → always 401
    /api/parse          SQLi / XXE injection target
    /api/search, /search SQLi via query parameters
    /render             SSTI template injection target
    /.env               Config file enumeration target
    /actuator/**        Spring Boot management stub
    /upload             Malicious file upload target
    404 catch-all       Captures scanner path probing

Author  : Hafsa Daoudim
Project : Final Training Project — JobInTech 2026
"""

from flask import Flask, request, jsonify
import json
import os
from datetime import datetime

app = Flask(__name__)

LOG_DIR  = "/app/logs"
LOG_FILE = os.path.join(LOG_DIR, "http_events.jsonl")


# ── Logging ───────────────────────────────────────────────────────────────────

def log_event(event: dict):
    """Append one event dict to the JSONL log file (thread-safe append mode)."""
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def client_ip() -> str:
    return request.remote_addr


@app.before_request
def capture_request():
    """
    Capture every incoming HTTP request before any route handler runs.

    The logged fields are the exact same fields read by featurize_http()
    in feature_extraction.py — guaranteeing that what the honeypot captures
    is what the ML model was trained on (no feature drift).

    body is capped at 2000 chars to prevent oversized log entries from
    large file uploads or fuzzer payloads.
    """
    event = {
        "timestamp":    datetime.utcnow().isoformat() + "Z",
        "source_ip":    client_ip(),
        "service":      "http",
        "method":       request.method,
        "path":         request.path,
        "query":        request.query_string.decode("utf-8", errors="ignore"),
        "user_agent":   request.headers.get("User-Agent", ""),
        "content_type": request.headers.get("Content-Type", ""),
        "body":         request.get_data(as_text=True)[:2000],
    }
    log_event(event)


# ── Homepage ──────────────────────────────────────────────────────────────────

@app.get("/")
def home():
    """Minimal landing page — keeps the server looking alive to scanners."""
    return "<h3>It works.</h3>", 200


# ── Admin enumeration targets ─────────────────────────────────────────────────
# These paths are in SENSITIVE_PATHS (feature_extraction.py) — accessing them
# triggers is_sensitive_path=1 and an asset boost in the RBA score.

@app.get("/admin")
def admin():
    return "<h3>Admin panel</h3><p>Access denied.</p>", 403

@app.get("/wp-admin")
def wp_admin():
    return "<h3>WordPress Admin</h3><p>Forbidden.</p>", 403

@app.get("/phpmyadmin")
def pma():
    return "<h3>phpMyAdmin</h3><p>Forbidden</p>", 403

@app.get("/wp-login.php")
def wp_login():
    return "<h3>WordPress Login</h3>", 200


# ── Authentication forms ──────────────────────────────────────────────────────
# Always return 401 on POST — realistic enough to encourage brute-force attempts.

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        return jsonify({"status": "invalid credentials"}), 401
    return """
    <h3>Login</h3>
    <form method="post">
      <input name="username" placeholder="username" />
      <input name="password" type="password" placeholder="password" />
      <button type="submit">Login</button>
    </form>
    """, 200

@app.route("/signin", methods=["GET", "POST"])
def signin():
    if request.method == "POST":
        return jsonify({"status": "invalid credentials"}), 401
    return """
    <h3>Sign In</h3>
    <form method="post">
      <input name="email" placeholder="email" />
      <input name="password" type="password" placeholder="password" />
      <button type="submit">Sign In</button>
    </form>
    """, 200

@app.route("/auth", methods=["GET", "POST"])
def auth():
    if request.method == "POST":
        return jsonify({"token": "invalid"}), 401
    return jsonify({"message": "POST credentials to authenticate"}), 200


# ── Injection endpoints ───────────────────────────────────────────────────────

@app.route("/api/parse", methods=["GET", "POST"])
def api_parse():
    """
    Primary target for SQLi, XXE and XML/JSON body injection.
    Accepts any Content-Type and echoes the payload size — encourages
    attackers to send larger, more complex payloads for richer log data.
    """
    data = request.get_data(as_text=True)
    return jsonify({"parsed": len(data), "status": "ok"}), 200

@app.route("/api/search", methods=["GET", "POST"])
def api_search():
    """
    Target for SQLi via query parameters (id, q).
    Reflecting the raw query value back makes the endpoint appear exploitable.
    """
    query = (request.args.get("q") or request.args.get("id") or
             request.args.get("search", ""))
    return jsonify({"results": [], "query": query}), 200

@app.route("/search", methods=["GET", "POST"])
def search():
    """Alias of /api/search — frequently probed by automated scanners."""
    term = request.args.get("id") or request.args.get("q", "")
    return jsonify({"results": [], "term": term}), 200


# ── SSTI target ───────────────────────────────────────────────────────────────

@app.route("/render", methods=["GET", "POST"])
def render_tpl():
    """
    Template injection (SSTI) target.

    Accepts a `tpl` parameter and echoes it back — simulates a server-side
    template renderer. Attackers typically test with {{7*7}}, ${7*7} or
    #{7*7} to probe the template engine type.
    Triggers has_template_syntax=1 and high ua_entropy in featurize_http().
    """
    tpl = request.args.get("tpl") or request.form.get("tpl", "")
    return jsonify({"rendered": tpl, "status": "ok"}), 200


# ── Configuration file stubs ──────────────────────────────────────────────────

@app.get("/.env")
def dotenv():
    """Config file enumeration target. Returns 404 to simulate a hidden file."""
    return "Not Found", 404

@app.route("/actuator", methods=["GET"])
@app.route("/actuator/<path:subpath>", methods=["GET"])
def actuator(subpath=""):
    """
    Spring Boot Actuator stub.
    Attackers probe /actuator/env, /actuator/heapdump, /actuator/beans
    looking for exposed management endpoints. All sub-paths are captured.
    """
    return jsonify({"status": "UP"}), 200


# ── File upload target ────────────────────────────────────────────────────────

@app.route("/upload", methods=["GET", "POST"])
def upload():
    """
    Malicious file upload target (webshells, backdoors, scripts).
    Always blocks the upload — the valuable data is the attempt itself,
    captured by before_request before this handler runs.
    """
    if request.method == "POST":
        return jsonify({"status": "upload blocked"}), 403
    return "<h3>Upload</h3>", 200


# ── 404 catch-all ─────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    """
    Catch-all for scanner path probing (/.git, /backup.zip, /config.php…).
    Every 404 is still logged by before_request — no event is lost.
    """
    return "<h3>Not Found</h3>", 404


if __name__ == "__main__":
    # debug=False — prevents the reloader from spawning a second process
    # that would write duplicate log entries
    app.run(host="0.0.0.0", port=8081, debug=False)