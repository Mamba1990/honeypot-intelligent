from flask import Flask, request, jsonify
import json
import os
from datetime import datetime

app = Flask(__name__)

LOG_DIR  = "/app/logs"
LOG_FILE = os.path.join(LOG_DIR, "http_events.jsonl")


def log_event(event: dict):
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def client_ip():
    return request.remote_addr


@app.before_request
def capture_request():
    """
    Capture et journalise chaque requete entrante dans http_events.jsonl.
    Les champs enregistres (method, path, query, user_agent, content_type, body)
    sont exactement ceux lus par featurize_http() dans feature_extraction.py,
    garantissant la coherence entre les logs HTTP et l'extraction de features ML.
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


# ── Page d'accueil ─────────────────────────────────────────────────────────────
@app.get("/")
def home():
    return "<h3>It works.</h3>", 200


# ── Enumeration admin ──────────────────────────────────────────────────────────
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


# ── Formulaires d'authentification ────────────────────────────────────────────
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


# ── Endpoints d'injection ──────────────────────────────────────────────────────
@app.route("/api/parse", methods=["GET", "POST"])
def api_parse():
    """Cible pour injections SQLi, XXE et injection de corps XML/JSON."""
    data = request.get_data(as_text=True)
    return jsonify({"parsed": len(data), "status": "ok"}), 200

@app.route("/api/search", methods=["GET", "POST"])
def api_search():
    """Cible pour injections SQLi via parametre id ou q."""
    query = request.args.get("q") or request.args.get("id") or \
            request.args.get("search", "")
    return jsonify({"results": [], "query": query}), 200

@app.route("/search", methods=["GET", "POST"])
def search():
    """Alias de /api/search — route frequemment ciblee par les scanners."""
    term = request.args.get("id") or request.args.get("q", "")
    return jsonify({"results": [], "term": term}), 200


# ── Injection de templates SSTI ────────────────────────────────────────────────
@app.route("/render", methods=["GET", "POST"])
def render_tpl():
    """
    Cible d'injection de templates (SSTI).
    Accepte un parametre 'tpl' en query string ou dans le body.
    """
    tpl = request.args.get("tpl") or request.form.get("tpl", "")
    return jsonify({"rendered": tpl, "status": "ok"}), 200


# ── Fichiers de configuration sensibles ───────────────────────────────────────
@app.get("/.env")
def dotenv():
    """Cible pour enumeration de fichiers de configuration."""
    return "Not Found", 404

@app.route("/actuator", methods=["GET"])
@app.route("/actuator/<path:subpath>", methods=["GET"])
def actuator(subpath=""):
    """Cible Spring Boot Actuator — endpoints de management exposes."""
    return jsonify({"status": "UP"}), 200


# ── Upload de fichiers malveillants ────────────────────────────────────────────
@app.route("/upload", methods=["GET", "POST"])
def upload():
    """Cible pour test d'upload de fichiers malveillants (webshells, scripts...)."""
    if request.method == "POST":
        return jsonify({"status": "upload blocked"}), 403
    return "<h3>Upload</h3>", 200


# ── Catch-all — capture tout le reste ─────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return "<h3>Not Found</h3>", 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081, debug=False)
