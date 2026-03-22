import os
import json
import sqlite3
import time
from datetime import datetime

import joblib
import numpy as np

DB_PATH = "/db/incidents.db"

HTTP_LOG = "/web/logs/http_events.jsonl"
COWRIE_LOG = "/cowrie/var/log/cowrie/cowrie.json"

# ML
ML_HTTP_MODEL_PATH = "/app/ml/model_http.joblib"
ML_SSH_MODEL_PATH = "/app/ml/model_ssh.joblib"
_ml_http_model = None
_ml_ssh_model = None

# Alert anti-spam
ALERT_COOLDOWN_SECONDS = 60
_last_alert_time = {}  # (ip, alert_type) -> last_time_epoch


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

    existing_cols = set()
    try:
        cur.execute("PRAGMA table_info(incidents)")
        for row in cur.fetchall():
            existing_cols.add(row[1])
    except Exception:
        pass

    if "ml_is_anomaly" not in existing_cols:
        try:
            cur.execute("ALTER TABLE incidents ADD COLUMN ml_is_anomaly INTEGER DEFAULT 0")
        except Exception:
            pass

    if "ml_score" not in existing_cols:
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
        """, (ts, ip, service, category, score, raw, int(ml_is_anomaly), float(ml_score)))
    else:
        cur.execute("""
            INSERT INTO incidents(timestamp, source_ip, service, category, score, raw)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (ts, ip, service, category, score, raw))

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


def insert_alert(ts: str, ip: str, alert_type: str, severity: int, details: str):
    now = time.time()
    key = (ip, alert_type)
    last = _last_alert_time.get(key, 0)

    if now - last < ALERT_COOLDOWN_SECONDS:
        return

    _last_alert_time[key] = now

    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        INSERT INTO alerts(timestamp, source_ip, alert_type, severity, details)
        VALUES (?, ?, ?, ?, ?)
    """, (ts, ip, alert_type, severity, details))
    con.commit()
    con.close()


# ---------------- HTTP classification (Rules) ----------------
HTTP_SUSPICIOUS_KEYWORDS = [
    "' or 1=1", "or 1=1", "<script", "../", "union select",
    "sleep(", "benchmark(", "xp_cmdshell"
]

HTTP_CMD_INJECTION_PATTERNS = [
    ";", "&&", "|", "`", "$(",
    "cat /etc/passwd", "whoami", "id", "uname", "wget ", "curl ", "nc ", "bash "
]


def classify_http(event: dict):
    path = event.get("path", "")
    q = (event.get("query") or "").lower()
    body = (event.get("body") or "").lower()

    is_injection = any(s in q or s in body for s in HTTP_SUSPICIOUS_KEYWORDS)
    is_cmd_injection = any(s in q or s in body for s in HTTP_CMD_INJECTION_PATTERNS)

    if path in ["/admin", "/phpmyadmin", "/wp-login.php", "/.env", "/wp-admin"]:
        return ("enum_admin", 50)

    if is_cmd_injection:
        return ("command_injection", 80)

    if is_injection:
        return ("injection_attempt", 70)

    if path == "/upload":
        return ("upload_probe", 60)

    return ("http_activity", 20)


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


# ---------------- SSH classification ----------------
SSH_POST_EXP_KW = ["wget", "curl", "chmod", "bash", "python", "nc ", "netcat", "perl", "sh "]
SSH_RECON_KW = ["uname", "whoami", "id", "cat /etc/passwd", "ip a", "ifconfig", "ps ", "netstat"]


def classify_ssh(ev: dict):
    etype = ev.get("eventid", "")

    if etype == "cowrie.login.failed":
        return ("ssh_login_failed", 40)

    if etype == "cowrie.login.success":
        return ("ssh_login_success", 60)

    if etype == "cowrie.command.input":
        cmd = (ev.get("input") or "").lower()

        if any(x in cmd for x in SSH_POST_EXP_KW):
            return ("post_exploitation", 85)

        if any(x in cmd for x in SSH_RECON_KW):
            return ("recon", 70)

        return ("ssh_command", 50)

    return ("ssh_activity", 15)


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


# ---------------- ML (HTTP/SSH anomaly) ----------------
def ml_http_enabled() -> bool:
    return os.path.exists(ML_HTTP_MODEL_PATH)


def ml_ssh_enabled() -> bool:
    return os.path.exists(ML_SSH_MODEL_PATH)


def load_http_model():
    global _ml_http_model
    if _ml_http_model is None and ml_http_enabled():
        _ml_http_model = joblib.load(ML_HTTP_MODEL_PATH)
    return _ml_http_model


def load_ssh_model():
    global _ml_ssh_model
    if _ml_ssh_model is None and ml_ssh_enabled():
        _ml_ssh_model = joblib.load(ML_SSH_MODEL_PATH)
    return _ml_ssh_model


def featurize_http_for_ml(evt: dict) -> np.ndarray:
    path = (evt.get("path") or "")
    query = (evt.get("query") or "")
    ua = (evt.get("user_agent") or "")
    method = (evt.get("method") or "")

    qlow = query.lower()
    suspicious = any(s in qlow for s in HTTP_SUSPICIOUS_KEYWORDS)
    sensitive_path = path.startswith("/admin") or path.startswith("/login") or path.startswith("/.env")

    x = np.array([[
        1.0 if method.upper() == "POST" else 0.0,
        float(len(query)),
        1.0 if suspicious else 0.0,
        1.0 if sensitive_path else 0.0,
        float(len(ua)),
    ]], dtype=float)
    return x


def featurize_ssh_for_ml(ev: dict, fails_60s: int = 0) -> np.ndarray:
    etype = ev.get("eventid", "")
    cmd = (ev.get("input") or "").lower()
    user = (ev.get("username") or "")

    x = np.array([[
        1.0 if etype == "cowrie.login.failed" else 0.0,
        1.0 if etype == "cowrie.login.success" else 0.0,
        1.0 if etype == "cowrie.command.input" else 0.0,
        1.0 if any(k in cmd for k in SSH_POST_EXP_KW) else 0.0,
        1.0 if any(k in cmd for k in SSH_RECON_KW) else 0.0,
        float(len(cmd)),
        float(len(user)),
        float(fails_60s),
    ]], dtype=float)
    return x


def ml_predict_http(evt: dict) -> tuple[int, float]:
    if not ml_http_enabled():
        return 0, 0.0

    model = load_http_model()
    X = featurize_http_for_ml(evt)
    score = float(model.score_samples(X)[0])
    pred = int(model.predict(X)[0])
    return (1 if pred == -1 else 0), score


def ml_predict_ssh(ev: dict, fails_60s: int = 0) -> tuple[int, float]:
    if not ml_ssh_enabled():
        return 0, 0.0

    model = load_ssh_model()
    X = featurize_ssh_for_ml(ev, fails_60s=fails_60s)
    score = float(model.score_samples(X)[0])
    pred = int(model.predict(X)[0])
    return (1 if pred == -1 else 0), score


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

    req_by_ip = {}
    failed_logins = {}

    while True:
        # -------- HTTP --------
        http_pos, http_events = tail_jsonl(HTTP_LOG, http_pos)
        for ev in http_events:
            ts = ev.get("timestamp")
            if not ts:
                continue

            ip = ev.get("source_ip") or ""
            cat, score = classify_http(ev)

            now = time.time()
            req_by_ip.setdefault(ip, []).append(now)
            req_by_ip[ip] = [t for t in req_by_ip[ip] if now - t <= 60]
            req_60s = len(req_by_ip[ip])

            ml_is_anomaly, ml_score = ml_predict_http(ev)

            if ml_is_anomaly:
                score = min(100, score + 30)
                if cat == "http_activity":
                    cat = "http_anomaly"
                insert_alert(ts, ip, "http_anomaly", 70, f"ML anomaly detected (ml_score={ml_score:.4f})")

            if cat == "command_injection":
                insert_alert(ts, ip, "http_command_injection", 85, "HTTP command injection pattern detected")

            if cat == "injection_attempt":
                insert_alert(ts, ip, "http_injection", 75, "HTTP injection pattern detected")

            if cat == "enum_admin" and req_60s >= 10:
                insert_alert(ts, ip, "http_recon", 60, f"Sensitive path enumeration detected ({req_60s} req/60s)")

            incident_id = insert_incident(
                ts, ip, "http", cat, score, json.dumps(ev),
                ml_is_anomaly=ml_is_anomaly,
                ml_score=ml_score
            )

            insert_ioc(incident_id, "path", ev.get("path"))
            insert_ioc(incident_id, "query", ev.get("query"))
            insert_ioc(incident_id, "user_agent", ev.get("user_agent"))

        # -------- SSH --------
        ssh_pos, ssh_events = tail_cowrie_json(COWRIE_LOG, ssh_pos)
        for ev in ssh_events:
            ip = ev.get("src_ip") or ev.get("srcip") or ev.get("src") or ""
            ts = ev.get("timestamp")
            if not ts:
                continue

            fails_60s = 0
            if ev.get("eventid") == "cowrie.login.failed" and ip:
                now = time.time()
                failed_logins.setdefault(ip, []).append(now)
                failed_logins[ip] = [t for t in failed_logins[ip] if now - t <= 60]
                fails_60s = len(failed_logins[ip])

                if fails_60s >= 5:
                    insert_alert(ts, ip, "ssh_bruteforce", 80, f"{fails_60s} failed logins in 60s")

            cat, score = classify_ssh(ev)
            ml_is_anomaly, ml_score = ml_predict_ssh(ev, fails_60s=fails_60s)

            if ml_is_anomaly:
                score = min(100, score + 25)
                if cat == "ssh_activity":
                    cat = "ssh_anomaly"
                insert_alert(ts, ip, "ssh_anomaly", 70, f"ML anomaly detected (ml_score={ml_score:.4f})")

            if cat == "post_exploitation":
                insert_alert(ts, ip, "ssh_post_exploitation", 95, "Post-exploitation SSH command detected")

            if cat == "recon":
                insert_alert(ts, ip, "ssh_recon", 65, "SSH reconnaissance command detected")

            incident_id = insert_incident(
                ts, ip, "ssh", cat, score, json.dumps(ev),
                ml_is_anomaly=ml_is_anomaly,
                ml_score=ml_score
            )

            insert_ioc(incident_id, "eventid", ev.get("eventid"))
            insert_ioc(incident_id, "username", ev.get("username"))
            insert_ioc(incident_id, "password", ev.get("password"))
            insert_ioc(incident_id, "command", ev.get("input"))

        time.sleep(2)


if __name__ == "__main__":
    main()