"""
collector.py — Honeypot Intelligent
=====================================
Core pipeline component. Tails HTTP and SSH honeypot logs, classifies
events via expert rules, scores anomalies with Isolation Forest, computes
a hybrid RBA score, and persists incidents, IOCs and alerts to SQLite.

Flow:
    webhoneypot (HTTP) ──┐
                          ├──► collector.py ──► SQLite ──► FastAPI ──► Dashboard
    cowrie      (SSH)  ──┘

The collector bridges both Docker networks:
    honeypot-net  — reads log files produced by the honeypots (read-only)
    internal-net  — writes results to the shared SQLite database

Author  : Hafsa Daoudim
Project : Final Training Project — JobInTech 2026
"""

import os
import sys

# Ensures the same featurizer module is used at training time and inference time.
# Both paths cover image-baked and volume-mounted deployments.
sys.path.insert(0, "/app")
sys.path.insert(0, "/app/ml")

import json
import sqlite3
import time
from datetime import datetime
from collections import defaultdict, deque

import joblib
import numpy as np

from feature_extraction import featurize_http, featurize_ssh_cowrie

# ── Paths ─────────────────────────────────────────────────────────────────────
DB_PATH    = "/db/incidents.db"
POS_FILE   = "/db/collector_pos.json"  # Read offsets persisted across restarts
HTTP_LOG   = "/web/logs/http_events.jsonl"
COWRIE_LOG = "/cowrie/var/log/cowrie/cowrie.json"

ML_HTTP_MODEL_PATH = "/app/ml/model_http.joblib"
ML_SSH_MODEL_PATH  = "/app/ml/model_ssh.joblib"

_ml_http = None  # Lazy-loaded singletons
_ml_ssh  = None

# ── Timing & flood control ────────────────────────────────────────────────────
WINDOW_SECONDS           = 60   # Sliding window for frequency scoring
ALERT_COOLDOWN_SECONDS   = 60   # Min delay between identical alerts per IP
MAX_INCIDENTS_PER_IP_60S = 100  # Hard cap — protects SQLite from burst scanners

_last_alert_time      = {}  # (ip, alert_type) → last epoch
_http_incident_counts = defaultdict(lambda: deque())
_ssh_incident_counts  = defaultdict(lambda: deque())

# ── RBA thresholds ────────────────────────────────────────────────────────────
RBA_ALERT_HIGH = 80  # → high-severity alert
RBA_ALERT_MED  = 60  # → medium-severity alert

# ── ML critical score ─────────────────────────────────────────────────────────
# Calibrated to the 1st–2nd percentile of the lowest scores observed in eval_http.py.
# When ml_score < ML_CRITICAL_SCORE:
#   • event flagged as critical anomaly
#   • alert cooldown bypassed (fires immediately)
#   • RBA score receives +20 ML_Boost
#
# History: -0.62 (initial, small dataset) → -0.67 (recalibrated after retraining)
# Rule: round percentile p1–p2 to 2 decimal places after every retraining cycle.
ML_CRITICAL_SCORE = -0.67

# ── HTTP expert-rule dictionaries ─────────────────────────────────────────────
HTTP_SUSPICIOUS_KEYWORDS = [        # SQLi / XSS markers → injection_attempt
    "or 1=1", "' or 1=1", "union select", "<script",
    "../", "sleep(", "benchmark(", "xp_cmdshell",
]

HTTP_CMD_INJECTION_PATTERNS = [     # OS command injection → command_injection
    "$(", "`", ";", "&&", "|", "whoami", "id",
    "uname", "cat ", "wget ", "curl ", "nc ", "bash ",
]

HTTP_SENSITIVE_PATHS = [            # Recon targets → enum_admin + asset boost
    "/admin", "/.env", "/phpmyadmin", "/wp-login.php",
    "/wp-admin", "/login", "/render", "/actuator",
]

# ── SSH expert-rule dictionaries (Cowrie) ─────────────────────────────────────
SSH_POST_EXP_KW = [                 # Persistence / exfiltration commands
    "wget", "curl", "chmod", "bash", "python",
    "nc ", "netcat", "perl", "sh "
]

SSH_RECON_KW = [                    # Environment mapping commands
    "uname", "whoami", "id", "cat /etc/passwd",
    "ip a", "ifconfig", "ps ", "netstat"
]

# Aligned with train_ssh.py — events outside this set are discarded as noise
SSH_VALID_EVENTS = {
    "cowrie.login.failed",    # Failed authentication attempt
    "cowrie.login.success",   # Attacker authenticated
    "cowrie.command.input",   # Command executed in the emulated shell
    "cowrie.command.failed",  # Unknown command — sign of a real attacker
}


# ── Database ──────────────────────────────────────────────────────────────────

def init_db():
    """Create the three core tables if they do not exist."""
    os.makedirs("/db", exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, source_ip TEXT, service TEXT,
        category TEXT, score INTEGER, raw TEXT
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id INTEGER, ioc_type TEXT, ioc_value TEXT,
        FOREIGN KEY(incident_id) REFERENCES incidents(id)
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, source_ip TEXT, alert_type TEXT,
        severity INTEGER, details TEXT
    )""")

    con.commit()
    ensure_columns(con)
    con.close()


def ensure_columns(con: sqlite3.Connection):
    """Non-breaking migration: add ML columns if absent (backward compatibility)."""
    cur = con.cursor()
    cur.execute("PRAGMA table_info(incidents)")
    cols = {row[1] for row in cur.fetchall()}
    if "ml_is_anomaly" not in cols:
        try: cur.execute("ALTER TABLE incidents ADD COLUMN ml_is_anomaly INTEGER DEFAULT 0")
        except Exception: pass
    if "ml_score" not in cols:
        try: cur.execute("ALTER TABLE incidents ADD COLUMN ml_score REAL DEFAULT 0")
        except Exception: pass
    con.commit()


def incidents_has_ml_columns(con: sqlite3.Connection) -> bool:
    cur = con.cursor()
    cur.execute("PRAGMA table_info(incidents)")
    cols = {row[1] for row in cur.fetchall()}
    return ("ml_is_anomaly" in cols) and ("ml_score" in cols)


def insert_incident(ts, ip, service, category, score, raw,
                    ml_is_anomaly=0, ml_score=0.0) -> int:
    """
    Persist an enriched incident to SQLite.

    The `raw` field stores the original log line as-is (forensic non-repudiation).
    Same pattern as Elasticsearch _source and Splunk _raw.
    """
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    if incidents_has_ml_columns(con):
        cur.execute("""
            INSERT INTO incidents(timestamp,source_ip,service,category,score,raw,ml_is_anomaly,ml_score)
            VALUES (?,?,?,?,?,?,?,?)
        """, (ts, ip, service, category, int(score), raw, int(ml_is_anomaly), float(ml_score)))
    else:
        cur.execute("""
            INSERT INTO incidents(timestamp,source_ip,service,category,score,raw)
            VALUES (?,?,?,?,?,?)
        """, (ts, ip, service, category, int(score), raw))
    incident_id = cur.lastrowid
    con.commit()
    con.close()
    return incident_id


def insert_ioc(incident_id: int, ioc_type: str, ioc_value: str):
    """Store one IOC linked to an incident (path, query, user_agent, command…)."""
    if not ioc_value:
        return
    ioc_value = str(ioc_value).strip()
    if not ioc_value:
        return
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("INSERT INTO iocs(incident_id,ioc_type,ioc_value) VALUES (?,?,?)",
                (incident_id, ioc_type, ioc_value))
    con.commit()
    con.close()


def normalize_alert_details(details):
    """Coerce alert details to a valid JSON string regardless of input type."""
    if details is None:
        return json.dumps({"message": ""})
    if isinstance(details, (dict, list)):
        return json.dumps(details)
    s = str(details).strip()
    if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
        try:
            json.loads(s)
            return s
        except Exception:
            pass
    return json.dumps({"message": s})


def insert_alert(ts: str, ip: str, alert_type: str, severity: int, details):
    """
    Write an alert to SQLite, enforcing the per-(IP, type) cooldown.
    Bypassed only when the caller has confirmed ml_score < ML_CRITICAL_SCORE.
    """
    now = time.time()
    key = (ip, alert_type)
    if now - _last_alert_time.get(key, 0) < ALERT_COOLDOWN_SECONDS:
        return  # Still within cooldown — suppress
    _last_alert_time[key] = now
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        INSERT INTO alerts(timestamp,source_ip,alert_type,severity,details)
        VALUES (?,?,?,?,?)
    """, (ts, ip, alert_type, int(severity), normalize_alert_details(details)))
    con.commit()
    con.close()


def should_alert(ip: str, alert_type: str) -> bool:
    """Return True if the cooldown has expired for this (IP, alert_type) pair."""
    if not ip:
        return False
    return (time.time() - _last_alert_time.get((ip, alert_type), 0)) >= ALERT_COOLDOWN_SECONDS


def clamp_0_100(x: float) -> int:
    return int(max(0, min(100, round(x))))


def short(s: str, n: int = 160) -> str:
    """Truncate a string to avoid oversized database values."""
    s = (s or "").replace("\n", " ").strip()
    return s if len(s) <= n else s[:n] + "…"


def is_flood_ip(ip: str, counts: dict, now: float) -> bool:
    """Sliding-window flood guard (O(1) amortized). Returns True if IP should be skipped."""
    if not ip:
        return False
    dq = counts[ip]
    dq.append(now)
    while dq and now - dq[0] > WINDOW_SECONDS:
        dq.popleft()
    return len(dq) > MAX_INCIDENTS_PER_IP_60S


# ── Log tail readers ──────────────────────────────────────────────────────────

def tail_jsonl(filepath, last_pos):
    """Read new JSONL lines since last_pos. Returns (new_pos, events)."""
    if not os.path.exists(filepath):
        return last_pos, []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(last_pos)
        lines = f.readlines()
        new_pos = f.tell()
    events = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return new_pos, events


def tail_cowrie_json(filepath, last_pos):
    """Read new Cowrie JSON lines since last_pos. Returns (new_pos, events)."""
    if not os.path.exists(filepath):
        return last_pos, []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(last_pos)
        lines = f.readlines()
        new_pos = f.tell()
    events = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return new_pos, events


# ── Isolation Forest ──────────────────────────────────────────────────────────

def ml_http_enabled() -> bool:
    return os.path.exists(ML_HTTP_MODEL_PATH)

def ml_ssh_enabled() -> bool:
    return os.path.exists(ML_SSH_MODEL_PATH)

def load_http_model():
    """Lazy-load the HTTP model once and cache it for subsequent calls."""
    global _ml_http
    if _ml_http is None and ml_http_enabled():
        _ml_http = joblib.load(ML_HTTP_MODEL_PATH)
    return _ml_http

def load_ssh_model():
    """Lazy-load the SSH model once and cache it for subsequent calls."""
    global _ml_ssh
    if _ml_ssh is None and ml_ssh_enabled():
        _ml_ssh = joblib.load(ML_SSH_MODEL_PATH)
    return _ml_ssh

def ml_predict_http(evt: dict) -> tuple[int, float]:
    """
    Run Isolation Forest on one HTTP event using the 16-dim featurize_http() vector.
    Returns (ml_is_anomaly, ml_score). Score closer to -1 = more anomalous.
    """
    if not ml_http_enabled():
        return 0, 0.0
    try:
        model = load_http_model()
        X = np.array([featurize_http(evt)], dtype=float)
        score = float(model.score_samples(X)[0])
        pred  = int(model.predict(X)[0])
        return (1 if pred == -1 else 0), score
    except Exception:
        return 0, 0.0

def ml_predict_ssh(ev: dict, fails_60s: int) -> tuple[int, float]:
    """
    Run Isolation Forest on one Cowrie SSH event using the 12-dim featurize_ssh_cowrie() vector.
    fails_60s is included as a frequency feature — must match training conditions.
    """
    if not ml_ssh_enabled():
        return 0, 0.0
    try:
        model = load_ssh_model()
        X = np.array([featurize_ssh_cowrie(ev, fails_60s=fails_60s)], dtype=float)
        score = float(model.score_samples(X)[0])
        pred  = int(model.predict(X)[0])
        return (1 if pred == -1 else 0), score
    except Exception:
        return 0, 0.0


# ── Expert-rule classification ────────────────────────────────────────────────

def classify_http_label(event: dict) -> str:
    """
    Classify an HTTP event using deterministic expert rules (first match wins).
    Priority: enum_admin > command_injection > injection_attempt > upload_probe > http_activity
    """
    path     = event.get("path", "")
    combined = (event.get("query") or "").lower() + " " + (event.get("body") or "").lower()

    if any(path.startswith(p) for p in HTTP_SENSITIVE_PATHS):
        return "enum_admin"
    if any(p in combined for p in HTTP_CMD_INJECTION_PATTERNS):
        return "command_injection"
    if any(s in combined for s in HTTP_SUSPICIOUS_KEYWORDS):
        return "injection_attempt"
    if path == "/upload":
        return "upload_probe"
    return "http_activity"


def classify_ssh_label(ev: dict) -> str:
    """
    Classify a Cowrie SSH event using deterministic expert rules.
    Maps eventid + command content to: ssh_login_failed | ssh_login_success |
    post_exploitation | recon | ssh_command | ssh_command_failed | ssh_activity
    """
    etype = ev.get("eventid", "")
    if etype == "cowrie.login.failed":
        return "ssh_login_failed"
    if etype == "cowrie.login.success":
        return "ssh_login_success"
    if etype in ("cowrie.command.input", "cowrie.command.failed"):
        cmd = (ev.get("input") or "").lower()
        if any(x in cmd for x in SSH_POST_EXP_KW):
            return "post_exploitation"
        if any(x in cmd for x in SSH_RECON_KW):
            return "recon"
        if etype == "cowrie.command.failed":
            return "ssh_command_failed"  # Unknown to Cowrie — real attacker signal
        return "ssh_command"
    return "ssh_activity"


# ── RBA scoring ───────────────────────────────────────────────────────────────

def compute_rba_http(event: dict, req_60s: int, ml_is_anomaly: int) -> tuple[int, dict, list]:
    """
    Compute the composite RBA score for an HTTP event.

    RBA = base(10) + threat(0-40) + frequency(0-20) + asset(0-35)
          + indicators(0-15) + ml_boost(0|20)

    Returns: (risk clamped to [0,100], components dict, indicators list)
    """
    method = (event.get("method") or "").upper()
    path   = (event.get("path")   or "")
    query  = (event.get("query")  or "")
    body   = (event.get("body")   or "")
    ua     = (event.get("user_agent") or "")
    combined = query.lower() + " " + body.lower()

    indicators, base = [], 10

    # Asset — how sensitive is the targeted path?
    asset = 0
    if any(path.startswith(p) for p in HTTP_SENSITIVE_PATHS):
        asset = 20; indicators.append("sensitive_path")
    if path == "/upload":
        asset = max(asset, 15); indicators.append("upload_probe")
    if path.startswith("/admin"):
        asset = max(asset, 35); indicators.append("enum_admin")  # Highest asset value
    if path.startswith("/api/"):
        asset = max(asset, 20); indicators.append("api_endpoint")

    # Threat — attack type detected by expert rules
    threat = 0
    if any(k in combined for k in HTTP_CMD_INJECTION_PATTERNS):
        threat += 40; indicators.append("command_injection_pattern")
    if any(k in combined for k in HTTP_SUSPICIOUS_KEYWORDS):
        threat += 30; indicators.append("suspicious_keywords")

    # Behavioral indicators
    ind = 0
    if method == "POST":         ind += 10; indicators.append("post_method")
    if len(query) >= 25:         ind += 10; indicators.append("long_query")
    if len(ua)    >= 120:        ind += 5;  indicators.append("long_user_agent")

    # Frequency — request rate over the last 60 seconds
    freq = 0
    if req_60s >= 20:   freq = 20; indicators.append("high_rate_20per60s")
    elif req_60s >= 10: freq = 10; indicators.append("rate_10per60s")

    # ML boost — +20 if Isolation Forest flags this event
    ml_boost = 0
    if ml_is_anomaly:
        ml_boost = 20; indicators.append("ml_anomaly")

    risk = clamp_0_100(base + threat + freq + asset + ind + ml_boost)
    components = {"base": base, "threat": threat, "frequency": freq,
                  "asset": asset, "indicators": ind, "ml_boost": ml_boost, "req_60s": req_60s}
    return risk, components, indicators


def compute_rba_ssh(ev: dict, fails_60s: int, ml_is_anomaly: int) -> tuple[int, dict, list]:
    """
    Compute the composite RBA score for a Cowrie SSH event.

    RBA = base(10) + threat(5-50) + frequency(0-40) + ml_boost(0|20)

    Returns: (risk clamped to [0,100], components dict, indicators list)
    """
    etype = ev.get("eventid", "")
    cmd   = (ev.get("input") or "").lower()
    indicators, base = [], 10

    # Threat — severity based on event type and command content
    threat = 0
    if etype == "cowrie.command.input":
        if any(k in cmd for k in SSH_POST_EXP_KW):
            threat = 50; indicators.append("post_exploitation_cmd")
        elif any(k in cmd for k in SSH_RECON_KW):
            threat = 30; indicators.append("recon_cmd")
        else:
            threat = 15; indicators.append("command_input")
    elif etype == "cowrie.login.failed":
        threat = 10; indicators.append("login_failed")
    elif etype == "cowrie.login.success":
        threat = 20; indicators.append("login_success")
    elif etype == "cowrie.command.failed":
        # Command unknown to Cowrie — typical of real attackers using non-standard tools
        if any(k in cmd for k in SSH_POST_EXP_KW):
            threat = 40; indicators.append("command_failed_post_exploitation")
        elif any(k in cmd for k in SSH_RECON_KW):
            threat = 25; indicators.append("command_failed_recon")
        else:
            threat = 30; indicators.append("command_failed_unknown")
    else:
        threat = 5; indicators.append("ssh_activity")

    # Frequency — brute-force detection via failed login rate
    freq = 0
    if fails_60s >= 10:   freq = 40; indicators.append("bruteforce_10fails_60s")
    elif fails_60s >= 5:  freq = 30; indicators.append("bruteforce_5fails_60s")

    # ML boost
    ml_boost = 0
    if ml_is_anomaly:
        ml_boost = 20; indicators.append("ml_anomaly")

    risk = clamp_0_100(base + threat + freq + ml_boost)
    components = {"base": base, "threat": threat, "frequency": freq,
                  "asset": 0, "indicators": 0, "ml_boost": ml_boost, "failed_60s": fails_60s}
    return risk, components, indicators


def severity_from_risk(risk: int) -> int:
    return int(risk)


# ── Read-position persistence ─────────────────────────────────────────────────

def get_file_size(path: str) -> int:
    try: return os.path.getsize(path)
    except OSError: return 0

def load_positions() -> dict:
    """
    Load saved byte offsets from POS_FILE and validate against current file sizes.
    Auto-resets any offset that exceeds the file size (log rotation detection).
    """
    try:
        with open(POS_FILE, "r") as f:
            pos = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        print("[collector] no saved positions — starting from offset 0")
        return {"http": 0, "ssh": 0}

    http_pos = pos.get("http", 0)
    ssh_pos  = pos.get("ssh",  0)

    if http_pos > get_file_size(HTTP_LOG):
        print(f"[collector] ⚠️  HTTP rotation detected → resetting offset to 0")
        http_pos = 0
    if ssh_pos > get_file_size(COWRIE_LOG):
        print(f"[collector] ⚠️  SSH rotation detected → resetting offset to 0")
        ssh_pos = 0

    print(f"[collector] positions loaded: http={http_pos}  ssh={ssh_pos}")
    return {"http": http_pos, "ssh": ssh_pos}

def save_positions(http_pos: int, ssh_pos: int):
    """Checkpoint read offsets after every loop iteration — guarantees safe restart."""
    try:
        with open(POS_FILE, "w") as f:
            json.dump({"http": http_pos, "ssh": ssh_pos}, f)
    except Exception as e:
        print(f"[collector] failed to save positions: {e}")


# ── Main loop ─────────────────────────────────────────────────────────────────

def main():
    """
    Entry point. Runs the infinite log-polling loop.

    Per-event pipeline:
        1. tail logs          → read new events
        2. classify label     → expert rules
        3. ml_predict         → Isolation Forest
        4. compute_rba        → hybrid score (rules + ML)
        5. insert_incident    → SQLite
        6. insert_ioc         → extract IOCs
        7. insert_alert       → fire alerts if thresholds exceeded
        8. save_positions     → checkpoint for safe restart
    """
    init_db()
    print("[collector] started")
    print("[collector] DB           :", DB_PATH)
    print("[collector] HTTP log     :", HTTP_LOG)
    print("[collector] SSH log      :", COWRIE_LOG)
    print("[collector] ML HTTP      :", ml_http_enabled(), "|", ML_HTTP_MODEL_PATH)
    print("[collector] ML SSH       :", ml_ssh_enabled(),  "|", ML_SSH_MODEL_PATH)
    print(f"[collector] flood cap    : max {MAX_INCIDENTS_PER_IP_60S} incidents/IP/{WINDOW_SECONDS}s")
    print(f"[collector] ML threshold : ML_CRITICAL_SCORE = {ML_CRITICAL_SCORE}")

    _pos = load_positions()

    # First start (no POS_FILE): jump to end of files to skip historical events
    if _pos["http"] == 0 and not os.path.exists(POS_FILE):
        _pos["http"] = get_file_size(HTTP_LOG)
        print(f"[collector] first start — HTTP offset → {_pos['http']} (end of file)")
    if _pos["ssh"] == 0 and not os.path.exists(POS_FILE):
        _pos["ssh"] = get_file_size(COWRIE_LOG)
        print(f"[collector] first start — SSH offset  → {_pos['ssh']} (end of file)")

    http_pos = _pos["http"]
    ssh_pos  = _pos["ssh"]

    # Sliding-window deques for per-IP frequency tracking
    http_hits = defaultdict(lambda: deque())  # IP → HTTP request timestamps (60s)
    ssh_fails = defaultdict(lambda: deque())  # IP → failed login timestamps (60s)

    while True:
        now = time.time()

        # ── HTTP ─────────────────────────────────────────────────────────────
        http_pos, http_events = tail_jsonl(HTTP_LOG, http_pos)

        for ev in http_events:
            ts = ev.get("timestamp") or (datetime.utcnow().isoformat() + "Z")
            ip = ev.get("source_ip") or ""

            # Update per-IP request frequency (sliding 60s window)
            req_60s = 0
            if ip:
                dq = http_hits[ip]
                dq.append(now)
                while dq and now - dq[0] > WINDOW_SECONDS: dq.popleft()
                req_60s = len(dq)

            if is_flood_ip(ip, _http_incident_counts, now):
                continue

            label         = classify_http_label(ev)
            ml_is_anomaly, ml_score = ml_predict_http(ev)
            risk, comp, indicators  = compute_rba_http(ev, req_60s, ml_is_anomaly)

            # Promote category if ML detects what rules did not classify
            category = label
            if ml_is_anomaly and category == "http_activity":
                category = "http_anomaly"

            incident_id = insert_incident(ts, ip, "http", category, risk, json.dumps(ev),
                                          ml_is_anomaly=ml_is_anomaly, ml_score=ml_score)
            insert_ioc(incident_id, "path",       ev.get("path"))
            insert_ioc(incident_id, "query",      ev.get("query"))
            insert_ioc(incident_id, "user_agent", ev.get("user_agent"))

            # Rule alerts
            if label == "command_injection" and should_alert(ip, "http_command_injection"):
                insert_alert(ts, ip, "http_command_injection", severity_from_risk(risk), {
                    "rba": {"risk": risk, "components": comp, "indicators": indicators},
                    "event": {"path": ev.get("path",""), "query": short(ev.get("query",""),180),
                              "method": ev.get("method",""), "user_agent": short(ev.get("user_agent",""),120)},
                    "category": label, "reason": "rule_match_command_injection"})

            if label == "injection_attempt" and should_alert(ip, "http_injection"):
                insert_alert(ts, ip, "http_injection", severity_from_risk(risk), {
                    "rba": {"risk": risk, "components": comp, "indicators": indicators},
                    "event": {"path": ev.get("path",""), "query": short(ev.get("query",""),180),
                              "method": ev.get("method",""), "user_agent": short(ev.get("user_agent",""),120)},
                    "category": label, "reason": "rule_match_injection"})

            # Critical ML anomaly — bypass cooldown for zero-day / multi-vector attacks
            is_critical_ml = ml_is_anomaly and ml_score < ML_CRITICAL_SCORE

            if ml_is_anomaly and (risk >= RBA_ALERT_MED or ml_score < -0.60):
                if is_critical_ml or should_alert(ip, "http_anomaly"):
                    insert_alert(ts, ip, "http_anomaly", severity_from_risk(risk), {
                        "rba": {"risk": risk, "components": comp, "indicators": indicators},
                        "ml":  {"is_anomaly": int(ml_is_anomaly), "ml_score": ml_score},
                        "event": {"path": ev.get("path",""), "query": short(ev.get("query",""),180),
                                  "method": ev.get("method",""), "user_agent": short(ev.get("user_agent",""),120)},
                        "category": label,
                        "note": "http_anomaly is generic; inspect details for contributing factors."})

            if risk >= RBA_ALERT_HIGH and should_alert(ip, "http_high_risk"):
                insert_alert(ts, ip, "http_high_risk", severity_from_risk(risk), {
                    "rba":      {"risk": risk, "components": comp, "indicators": indicators},
                    "event":    {"path": ev.get("path",""), "query": short(ev.get("query",""),180)},
                    "category": label})

        # ── SSH ──────────────────────────────────────────────────────────────
        ssh_pos, ssh_events = tail_cowrie_json(COWRIE_LOG, ssh_pos)

        for ev in ssh_events:
            ts    = ev.get("timestamp") or (datetime.utcnow().isoformat() + "Z")
            ip    = ev.get("src_ip") or ev.get("srcip") or ev.get("src") or ""
            etype = ev.get("eventid", "")

            if etype not in SSH_VALID_EVENTS:
                continue  # Discard noise (session.closed, direct-tcpip, etc.)

            # Track failed logins per IP for brute-force scoring
            fails_60s = 0
            if ip:
                dq = ssh_fails[ip]
                if etype == "cowrie.login.failed": dq.append(now)
                while dq and now - dq[0] > WINDOW_SECONDS: dq.popleft()
                fails_60s = len(dq)

            if is_flood_ip(ip, _ssh_incident_counts, now):
                continue

            label         = classify_ssh_label(ev)
            ml_is_anomaly, ml_score = ml_predict_ssh(ev, fails_60s)
            risk, comp, indicators  = compute_rba_ssh(ev, fails_60s, ml_is_anomaly)

            category = label
            if ml_is_anomaly and category in ("ssh_activity", "ssh_command"):
                category = "ssh_anomaly"

            incident_id = insert_incident(ts, ip, "ssh", category, risk, json.dumps(ev),
                                          ml_is_anomaly=ml_is_anomaly, ml_score=ml_score)
            insert_ioc(incident_id, "eventid",  ev.get("eventid"))
            insert_ioc(incident_id, "username", ev.get("username"))
            insert_ioc(incident_id, "password", ev.get("password"))
            insert_ioc(incident_id, "command",  ev.get("input"))

            if fails_60s >= 5 and should_alert(ip, "ssh_bruteforce"):
                insert_alert(ts, ip, "ssh_bruteforce", severity_from_risk(risk), {
                    "rba": {"risk": risk, "components": comp, "indicators": indicators},
                    "failed_60s": fails_60s, "reason": "frequency_failed_logins"})

            if label == "post_exploitation" and should_alert(ip, "ssh_post_exploitation"):
                insert_alert(ts, ip, "ssh_post_exploitation", severity_from_risk(risk), {
                    "rba":      {"risk": risk, "components": comp, "indicators": indicators},
                    "command":  short(ev.get("input",""), 180),
                    "username": ev.get("username",""),
                    "eventid":  ev.get("eventid",""),
                    "reason":   "rule_match_post_exploitation"})

            if ml_is_anomaly and risk >= RBA_ALERT_MED and should_alert(ip, "ssh_anomaly"):
                insert_alert(ts, ip, "ssh_anomaly", severity_from_risk(risk), {
                    "rba": {"risk": risk, "components": comp, "indicators": indicators},
                    "ml":  {"is_anomaly": int(ml_is_anomaly), "ml_score": ml_score},
                    "event": {"eventid": ev.get("eventid",""), "command": short(ev.get("input",""),180),
                              "username": ev.get("username",""), "failed_60s": fails_60s},
                    "category": label})

        # Checkpoint offsets — zero event loss on container restart
        save_positions(http_pos, ssh_pos)
        time.sleep(2)


if __name__ == "__main__":
    main()