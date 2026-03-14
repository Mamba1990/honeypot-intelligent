import os
import json
import sqlite3
import time
from datetime import datetime
from collections import defaultdict, deque

import joblib
import numpy as np

DB_PATH = "/db/incidents.db"

HTTP_LOG = "/web/logs/http_events.jsonl"
COWRIE_LOG = "/cowrie/var/log/cowrie/cowrie.json"

# ML models (2 modèles séparés)
ML_HTTP_MODEL_PATH = "/app/ml/model_http.joblib"
ML_SSH_MODEL_PATH = "/app/ml/model_ssh.joblib"
_ml_http = None
_ml_ssh = None

# Time windows
WINDOW_SECONDS = 60

# Alert anti-spam
ALERT_COOLDOWN_SECONDS = 60
_last_alert_time = {}  # (ip, alert_type) -> last_time_epoch

# --- RBA thresholds ---
RBA_ALERT_HIGH = 80   # critique
RBA_ALERT_MED = 60    # élevé

# HTTP indicators
HTTP_SUSPICIOUS_KEYWORDS = [
    "or 1=1",
    "' or 1=1",
    "union select",
    "<script",
    "../",
    "sleep(",
    "benchmark(",
    "xp_cmdshell",
]
HTTP_SENSITIVE_PATHS = ["/admin", "/.env", "/phpmyadmin", "/wp-login.php", "/wp-admin", "/login"]

# SSH indicators
SSH_POST_EXP_KW = ["wget", "curl", "chmod", "bash", "python", "nc ", "netcat", "perl", "sh "]
SSH_RECON_KW = ["uname", "whoami", "id", "cat /etc/passwd", "ip a", "ifconfig", "ps ", "netstat"]


# ---------------- DB ----------------
def init_db():
    os.makedirs("/db", exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        service TEXT,
        category TEXT,
        score INTEGER,
        raw TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id INTEGER,
        ioc_type TEXT,
        ioc_value TEXT,
        FOREIGN KEY(incident_id) REFERENCES incidents(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        alert_type TEXT,
        severity INTEGER,
        details TEXT
    )
    """)

    con.commit()
    ensure_columns(con)
    con.close()


def ensure_columns(con: sqlite3.Connection):
    cur = con.cursor()
    cur.execute("PRAGMA table_info(incidents)")
    cols = {row[1] for row in cur.fetchall()}

    if "ml_is_anomaly" not in cols:
        try:
            cur.execute("ALTER TABLE incidents ADD COLUMN ml_is_anomaly INTEGER DEFAULT 0")
        except Exception:
            pass

    if "ml_score" not in cols:
        try:
            cur.execute("ALTER TABLE incidents ADD COLUMN ml_score REAL DEFAULT 0")
        except Exception:
            pass

    con.commit()


def incidents_has_ml_columns(con: sqlite3.Connection) -> bool:
    cur = con.cursor()
    cur.execute("PRAGMA table_info(incidents)")
    cols = {row[1] for row in cur.fetchall()}
    return ("ml_is_anomaly" in cols) and ("ml_score" in cols)


def insert_incident(ts, ip, service, category, score, raw, ml_is_anomaly=0, ml_score=0.0) -> int:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    if incidents_has_ml_columns(con):
        cur.execute("""
            INSERT INTO incidents(timestamp, source_ip, service, category, score, raw, ml_is_anomaly, ml_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (ts, ip, service, category, int(score), raw, int(ml_is_anomaly), float(ml_score)))
    else:
        cur.execute("""
            INSERT INTO incidents(timestamp, source_ip, service, category, score, raw)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (ts, ip, service, category, int(score), raw))

    incident_id = cur.lastrowid
    con.commit()
    con.close()
    return incident_id


def insert_ioc(incident_id: int, ioc_type: str, ioc_value: str):
    if ioc_value is None:
        return
    ioc_value = str(ioc_value).strip()
    if not ioc_value:
        return

    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        INSERT INTO iocs(incident_id, ioc_type, ioc_value)
        VALUES (?, ?, ?)
    """, (incident_id, ioc_type, ioc_value))
    con.commit()
    con.close()


def insert_alert(ts: str, ip: str, alert_type: str, severity: int, details: dict):
    """
    On stocke toujours details en JSON string dans SQLite.
    L'API FastAPI doit faire json.loads(details) pour afficher proprement.
    """
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        INSERT INTO alerts(timestamp, source_ip, alert_type, severity, details)
        VALUES (?, ?, ?, ?, ?)
    """, (ts, ip, alert_type, int(severity), json.dumps(details)))
    con.commit()
    con.close()


def should_alert(ip: str, alert_type: str) -> bool:
    if not ip:
        return False
    now = time.time()
    key = (ip, alert_type)
    last = _last_alert_time.get(key, 0)
    if now - last < ALERT_COOLDOWN_SECONDS:
        return False
    _last_alert_time[key] = now
    return True


def clamp_0_100(x: float) -> int:
    return int(max(0, min(100, round(x))))


def short(s: str, n: int = 160) -> str:
    s = (s or "").replace("\n", " ").strip()
    return s if len(s) <= n else s[:n] + "…"


# ---------------- Tail readers ----------------
def tail_jsonl(filepath, last_pos):
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


# ---------------- ML ----------------
def _load_model(path: str):
    return joblib.load(path)


def ml_http_enabled() -> bool:
    return os.path.exists(ML_HTTP_MODEL_PATH)


def ml_ssh_enabled() -> bool:
    return os.path.exists(ML_SSH_MODEL_PATH)


def load_http_model():
    global _ml_http
    if _ml_http is None and ml_http_enabled():
        _ml_http = _load_model(ML_HTTP_MODEL_PATH)
    return _ml_http


def load_ssh_model():
    global _ml_ssh
    if _ml_ssh is None and ml_ssh_enabled():
        _ml_ssh = _load_model(ML_SSH_MODEL_PATH)
    return _ml_ssh


def featurize_http_for_ml(evt: dict) -> np.ndarray:
    path = (evt.get("path") or "")
    query = (evt.get("query") or "")
    ua = (evt.get("user_agent") or "")
    method = (evt.get("method") or "")

    qlow = query.lower()
    suspicious = any(s in qlow for s in ["or 1=1", "union select", "<script", "../", "sleep(", "benchmark("])
    sensitive_path = any(path.startswith(p) for p in HTTP_SENSITIVE_PATHS)

    x = np.array([[
        1.0 if method.upper() == "POST" else 0.0,
        float(len(query)),
        1.0 if suspicious else 0.0,
        1.0 if sensitive_path else 0.0,
        float(len(ua)),
    ]], dtype=float)
    return x


def ml_predict_http(evt: dict) -> tuple[int, float]:
    if not ml_http_enabled():
        return 0, 0.0
    model = load_http_model()
    X = featurize_http_for_ml(evt)
    score = float(model.score_samples(X)[0])
    pred = int(model.predict(X)[0])  # -1 anomalie, 1 normal
    return (1 if pred == -1 else 0), score


def featurize_ssh_for_ml(ev: dict, fails_60s: int) -> np.ndarray:
    etype = ev.get("eventid", "")
    cmd = (ev.get("input") or "").lower()
    user = (ev.get("username") or "")

    is_failed = 1.0 if etype == "cowrie.login.failed" else 0.0
    is_success = 1.0 if etype == "cowrie.login.success" else 0.0
    is_cmd = 1.0 if etype == "cowrie.command.input" else 0.0

    has_post = 1.0 if any(k in cmd for k in SSH_POST_EXP_KW) else 0.0
    has_recon = 1.0 if any(k in cmd for k in SSH_RECON_KW) else 0.0

    cmd_len = float(len(cmd))
    user_len = float(len(user))
    fail_rate = float(fails_60s)

    x = np.array([[
        is_failed, is_success, is_cmd,
        has_post, has_recon,
        cmd_len, user_len,
        fail_rate
    ]], dtype=float)
    return x


def ml_predict_ssh(ev: dict, fails_60s: int) -> tuple[int, float]:
    if not ml_ssh_enabled():
        return 0, 0.0
    model = load_ssh_model()
    X = featurize_ssh_for_ml(ev, fails_60s)
    score = float(model.score_samples(X)[0])
    pred = int(model.predict(X)[0])  # -1 anomalie
    return (1 if pred == -1 else 0), score


# ---------------- Labels (rule-based) ----------------
def classify_http_label(event: dict) -> str:
    path = event.get("path", "")
    q = (event.get("query") or "").lower()
    body = (event.get("body") or "").lower()

    is_injection = any(s in q or s in body for s in HTTP_SUSPICIOUS_KEYWORDS)
    if any(path.startswith(p) for p in HTTP_SENSITIVE_PATHS):
        return "enum_admin"
    if is_injection:
        return "injection_attempt"
    if path == "/upload":
        return "upload_probe"
    return "http_activity"


def classify_ssh_label(ev: dict) -> str:
    etype = ev.get("eventid", "")
    if etype == "cowrie.login.failed":
        return "ssh_login_failed"
    if etype == "cowrie.login.success":
        return "ssh_login_success"
    if etype == "cowrie.command.input":
        cmd = (ev.get("input") or "").lower()
        if any(x in cmd for x in SSH_POST_EXP_KW):
            return "post_exploitation"
        if any(x in cmd for x in SSH_RECON_KW):
            return "recon"
        return "ssh_command"
    return "ssh_activity"


# ---------------- RBA scoring ----------------
def compute_rba_http(event: dict, req_60s: int, ml_is_anomaly: int) -> tuple[int, dict, list]:
    method = (event.get("method") or "").upper()
    path = (event.get("path") or "")
    query = (event.get("query") or "")
    body = (event.get("body") or "")
    ua = (event.get("user_agent") or "")

    qlow = query.lower()
    blow = body.lower()

    indicators = []
    base = 10

    asset = 0
    if any(path.startswith(p) for p in HTTP_SENSITIVE_PATHS):
        asset = 20
        indicators.append("sensitive_path")

    threat = 0
    if any(k in qlow or k in blow for k in HTTP_SUSPICIOUS_KEYWORDS):
        threat += 30
        indicators.append("suspicious_keywords")

    ind = 0
    if method == "POST":
        ind += 10
        indicators.append("post_method")
    if len(query) >= 25:
        ind += 10
        indicators.append("long_query")
    if len(ua) >= 120:
        ind += 5
        indicators.append("long_user_agent")

    freq = 0
    if req_60s >= 20:
        freq = 20
        indicators.append("high_rate_20per60s")
    elif req_60s >= 10:
        freq = 10
        indicators.append("rate_10per60s")

    ml_boost = 0
    if ml_is_anomaly:
        ml_boost = 20
        indicators.append("ml_anomaly")

    risk = clamp_0_100(base + threat + freq + asset + ind + ml_boost)
    components = {
        "base": base, "threat": threat, "frequency": freq, "asset": asset,
        "indicators": ind, "ml_boost": ml_boost, "req_60s": req_60s
    }
    return risk, components, indicators


def compute_rba_ssh(ev: dict, fails_60s: int, ml_is_anomaly: int) -> tuple[int, dict, list]:
    etype = ev.get("eventid", "")
    cmd = (ev.get("input") or "").lower()

    indicators = []
    base = 10

    threat = 0
    if etype == "cowrie.command.input":
        if any(k in cmd for k in SSH_POST_EXP_KW):
            threat = 50
            indicators.append("post_exploitation_cmd")
        elif any(k in cmd for k in SSH_RECON_KW):
            threat = 30
            indicators.append("recon_cmd")
        else:
            threat = 15
            indicators.append("command_input")
    elif etype == "cowrie.login.failed":
        threat = 10
        indicators.append("login_failed")
    elif etype == "cowrie.login.success":
        threat = 20
        indicators.append("login_success")
    else:
        threat = 5
        indicators.append("ssh_activity")

    freq = 0
    if fails_60s >= 10:
        freq = 40
        indicators.append("bruteforce_10fails_60s")
    elif fails_60s >= 5:
        freq = 30
        indicators.append("bruteforce_5fails_60s")

    asset = 0

    ml_boost = 0
    if ml_is_anomaly:
        ml_boost = 20
        indicators.append("ml_anomaly")

    risk = clamp_0_100(base + threat + freq + asset + ml_boost)
    components = {
        "base": base, "threat": threat, "frequency": freq, "asset": asset,
        "indicators": 0, "ml_boost": ml_boost, "failed_60s": fails_60s
    }
    return risk, components, indicators


def severity_from_risk(risk: int) -> int:
    return int(risk)


# ---------------- Main loop ----------------
def main():
    init_db()
    print("[collector] started")
    print("[collector] DB:", DB_PATH)
    print("[collector] watching HTTP:", HTTP_LOG)
    print("[collector] watching SSH:", COWRIE_LOG)
    print("[collector] ML HTTP enabled:", ml_http_enabled(), "|", ML_HTTP_MODEL_PATH)
    print("[collector] ML SSH enabled :", ml_ssh_enabled(), "|", ML_SSH_MODEL_PATH)

    http_pos = 0
    ssh_pos = 0

    http_hits = defaultdict(lambda: deque())   # ip -> timestamps
    ssh_fails = defaultdict(lambda: deque())   # ip -> timestamps (failed logins)

    while True:
        now = time.time()

        # -------- HTTP --------
        http_pos, http_events = tail_jsonl(HTTP_LOG, http_pos)
        for ev in http_events:
            ts = ev.get("timestamp") or (datetime.utcnow().isoformat() + "Z")
            ip = ev.get("source_ip") or ""

            # rate window
            req_60s = 0
            if ip:
                dq = http_hits[ip]
                dq.append(now)
                while dq and now - dq[0] > WINDOW_SECONDS:
                    dq.popleft()
                req_60s = len(dq)

            label = classify_http_label(ev)

            ml_is_anomaly, ml_score = ml_predict_http(ev)
            risk, comp, indicators = compute_rba_http(ev, req_60s, ml_is_anomaly)

            category = label
            if ml_is_anomaly and category == "http_activity":
                category = "http_anomaly"

            incident_id = insert_incident(
                ts, ip, "http", category, risk, json.dumps(ev),
                ml_is_anomaly=ml_is_anomaly,
                ml_score=ml_score
            )

            insert_ioc(incident_id, "path", ev.get("path"))
            insert_ioc(incident_id, "query", ev.get("query"))
            insert_ioc(incident_id, "user_agent", ev.get("user_agent"))

            # Alerts: injection
            if label == "injection_attempt" and should_alert(ip, "http_injection"):
                insert_alert(ts, ip, "http_injection", severity_from_risk(risk), {
                    "rba": {"risk": risk, "components": comp, "indicators": indicators},
                    "event": {
                        "path": ev.get("path", ""),
                        "query": short(ev.get("query", ""), 180),
                        "method": ev.get("method", ""),
                        "user_agent": short(ev.get("user_agent", ""), 120),
                    },
                    "category": label,
                    "reason": "rule_match_injection"
                })

            # Alerts: ML anomaly (details riches)
            if ml_is_anomaly and risk >= RBA_ALERT_MED and should_alert(ip, "http_anomaly"):
                insert_alert(ts, ip, "http_anomaly", severity_from_risk(risk), {
                    "rba": {"risk": risk, "components": comp, "indicators": indicators},
                    "ml": {"is_anomaly": int(ml_is_anomaly), "ml_score": ml_score},
                    "event": {
                        "path": ev.get("path", ""),
                        "query": short(ev.get("query", ""), 180),
                        "method": ev.get("method", ""),
                        "user_agent": short(ev.get("user_agent", ""), 120),
                    },
                    "category": label,
                    "note": "http_anomaly is generic; details explain factors behind the risk."
                })

            # Alerts: high risk (toutes causes)
            if risk >= RBA_ALERT_HIGH and should_alert(ip, "http_high_risk"):
                insert_alert(ts, ip, "http_high_risk", severity_from_risk(risk), {
                    "rba": {"risk": risk, "components": comp, "indicators": indicators},
                    "event": {"path": ev.get("path", ""), "query": short(ev.get("query", ""), 180)},
                    "category": label
                })

        # -------- SSH --------
        ssh_pos, ssh_events = tail_cowrie_json(COWRIE_LOG, ssh_pos)
        for ev in ssh_events:
            ts = ev.get("timestamp") or (datetime.utcnow().isoformat() + "Z")
            ip = ev.get("src_ip") or ev.get("srcip") or ev.get("src") or ""
            etype = ev.get("eventid", "")

            # failed rate window
            fails_60s = 0
            if ip:
                dq = ssh_fails[ip]
                if etype == "cowrie.login.failed":
                    dq.append(now)
                while dq and now - dq[0] > WINDOW_SECONDS:
                    dq.popleft()
                fails_60s = len(dq)

            label = classify_ssh_label(ev)

            # ML SSH
            ml_is_anomaly, ml_score = ml_predict_ssh(ev, fails_60s)

            # RBA SSH
            risk, comp, indicators = compute_rba_ssh(ev, fails_60s, ml_is_anomaly)

            # if ML anomaly and label generic
            category = label
            if ml_is_anomaly and category in ("ssh_activity", "ssh_command"):
                category = "ssh_anomaly"

            incident_id = insert_incident(
                ts, ip, "ssh", category, risk, json.dumps(ev),
                ml_is_anomaly=ml_is_anomaly,
                ml_score=ml_score
            )

            insert_ioc(incident_id, "eventid", ev.get("eventid"))
            insert_ioc(incident_id, "username", ev.get("username"))
            insert_ioc(incident_id, "password", ev.get("password"))
            insert_ioc(incident_id, "command", ev.get("input"))

            # Alerts: bruteforce (rule/frequency)
            if fails_60s >= 5 and should_alert(ip, "ssh_bruteforce"):
                insert_alert(ts, ip, "ssh_bruteforce", severity_from_risk(risk), {
                    "rba": {"risk": risk, "components": comp, "indicators": indicators},
                    "failed_60s": fails_60s,
                    "reason": "frequency_failed_logins"
                })

            # Alerts: post exploitation (rule)
            if label == "post_exploitation" and should_alert(ip, "ssh_post_exploitation"):
                insert_alert(ts, ip, "ssh_post_exploitation", severity_from_risk(risk), {
                    "rba": {"risk": risk, "components": comp, "indicators": indicators},
                    "command": short(ev.get("input", ""), 180),
                    "reason": "rule_match_post_exploitation"
                })

            # Alerts: ML anomaly SSH (details riches)
            if ml_is_anomaly and risk >= RBA_ALERT_MED and should_alert(ip, "ssh_anomaly"):
                insert_alert(ts, ip, "ssh_anomaly", severity_from_risk(risk), {
                    "rba": {"risk": risk, "components": comp, "indicators": indicators},
                    "ml": {"is_anomaly": int(ml_is_anomaly), "ml_score": ml_score},
                    "event": {
                        "eventid": ev.get("eventid", ""),
                        "command": short(ev.get("input", ""), 180),
                        "username": ev.get("username", ""),
                        "failed_60s": fails_60s
                    },
                    "category": label
                })

        time.sleep(2)


if __name__ == "__main__":
    main()