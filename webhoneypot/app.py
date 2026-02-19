from flask import Flask, request, jsonify
import json
import os
from datetime import datetime

app = Flask(__name__)

LOG_DIR = "/app/logs"
LOG_FILE = os.path.join(LOG_DIR, "http_events.jsonl")

def log_event(event: dict):
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

def client_ip():
    return request.remote_addr

@app.before_request
def capture_request():
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "source_ip": client_ip(),
        "service": "http",
        "method": request.method,
        "path": request.path,
        "query": request.query_string.decode("utf-8", errors="ignore"),
        "user_agent": request.headers.get("User-Agent", ""),
        "content_type": request.headers.get("Content-Type", ""),
        "body": request.get_data(as_text=True)[:2000],
    }
    log_event(event)

@app.get("/")
def home():
    return "<h3>It works.</h3>", 200

@app.get("/admin")
def admin():
    return "<h3>Admin panel</h3><p>Access denied.</p>", 403

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

@app.get("/wp-login.php")
def wp_login():
    return "<h3>WordPress Login</h3>", 200

@app.get("/phpmyadmin")
def pma():
    return "<h3>phpMyAdmin</h3><p>Forbidden</p>", 403

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        return jsonify({"status": "upload blocked"}), 403
    return "<h3>Upload</h3>", 200

@app.errorhandler(404)
def not_found(e):
    return "<h3>Not Found</h3>", 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)

