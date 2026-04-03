import os
import sys
import json
import sqlite3
import time
from datetime import datetime
from collections import defaultdict, deque

import joblib
import numpy as np

# ✅ Import des features depuis feature_extraction.py
# Même vecteur utilisé à l'entraînement ET en inférence → cohérence garantie
sys.path.insert(0, "/app/ml")
from feature_extraction import featurize_http, featurize_ssh_cowrie

DB_PATH   = "/db/incidents.db"
POS_FILE  = "/db/collector_pos.json"  # ✅ Persistance des positions de lecture
HTTP_LOG = "/web/logs/http_events.jsonl"
COWRIE_LOG = "/cowrie/var/log/cowrie/cowrie.json"

# ML models
ML_HTTP_MODEL_PATH = "/app/ml/model_http.joblib"
ML_SSH_MODEL_PATH = "/app/ml/model_ssh.joblib"
_ml_http = None
_ml_ssh = None

# Time windows
WINDOW_SECONDS = 60

# Alert anti-spam
ALERT_COOLDOWN_SECONDS = 60
_last_alert_time = {}  # (ip, alert_type) -> last_time_epoch

# ✅ Cap flood : max incidents enregistrés par IP par fenêtre de 60s
MAX_INCIDENTS_PER_IP_60S = 10
_http_incident_counts = defaultdict(lambda: deque())
_ssh_incident_counts  = defaultdict(lambda: deque())

# RBA thresholds
RBA_ALERT_HIGH = 80
RBA_ALERT_MED = 60

# ✅ Seuil ML critique — bypass cooldown si anomalie tres forte
# En dessous de ce score, l'alerte est toujours declenchee meme si cooldown actif
ML_CRITICAL_SCORE = -0.62

# HTTP indicators
HTTP_SUSPICIOUS_KEYWORDS = [
    "or 1=1", "' or 1=1", "union select", "<script",
    "../", "sleep(", "benchmark(", "xp_cmdshell",
]

HTTP_CMD_INJECTION_PATTERNS = [
    "$(", "`", ";", "&&", "|", "whoami", "id",
    "uname", "cat ", "wget ", "curl ", "nc ", "bash ",
]

HTTP_SENSITIVE_PATHS = [
    "/admin", "/.env", "/phpmyadmin", "/wp-login.php",
    "/wp-admin", "/login", "/render", "/actuator",
]

# SSH indicators
SSH_POST_EXP_KW = ["wget", "curl", "chmod", "bash", "python", "nc ", "netcat", "perl", "sh "]
SSH_RECON_KW = ["uname", "whoami", "id", "cat /etc/passwd", "ip a", "ifconfig", "ps ", "netstat"]

# ✅ VALID_EVENTS SSH — aligné avec train_ssh.py
SSH_VALID_EVENTS = {
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.command.failed",   # commandes inconnues de Cowrie
}


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


def normalize_alert_details(details):
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
    """, (ts, ip, alert_type, int(severity), normalize_alert_details(details)))
    con.commit()
    con.close()


def should_alert(ip: str, alert_type: str) -> bool:
    if not ip:
        return False
    now = time.time()
    key = (ip, alert_type)
    last = _last_alert_time.get(key, 0)
    return (now - last) >= ALERT_COOLDOWN_SECONDS


def clamp_0_100(x: float) -> int:
    return int(max(0, min(100, round(x))))


def short(s: str, n: int = 160) -> str:
    s = (s or "").replace("\n", " ").strip()
    return s if len(s) <= n else s[:n] + "…"


# ✅ Cap flood
def is_flood_ip(ip: str, counts: dict, now: float) -> bool:
    if not ip:
        return False
    dq = counts[ip]
    dq.append(now)
    while dq and now - dq[0] > WINDOW_SECONDS:
        dq.popleft()
    return len(dq) > MAX_INCIDENTS_PER_IP_60S


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
def ml_http_enabled() -> bool:
    return os.path.exists(ML_HTTP_MODEL_PATH)


def ml_ssh_enabled() -> bool:
    return os.path.exists(ML_SSH_MODEL_PATH)


def load_http_model():
    global _ml_http
    if _ml_http is None and ml_http_enabled():
        _ml_http = joblib.load(ML_HTTP_MODEL_PATH)
    return _ml_http


def load_ssh_model():
    global _ml_ssh
    if _ml_ssh is None and ml_ssh_enabled():
        _ml_ssh = joblib.load(ML_SSH_MODEL_PATH)
    return _ml_ssh


def ml_predict_http(evt: dict) -> tuple[int, float]:
    """✅ Utilise featurize_http() — vecteur 16 dims depuis feature_extraction.py."""
    if not ml_http_enabled():
        return 0, 0.0
    try:
        model = load_http_model()
        X = np.array([featurize_http(evt)], dtype=float)
        score = float(model.score_samples(X)[0])
        pred = int(model.predict(X)[0])
        return (1 if pred == -1 else 0), score
    except Exception:
        return 0, 0.0


def ml_predict_ssh(ev: dict, fails_60s: int) -> tuple[int, float]:
    """✅ Utilise featurize_ssh_cowrie() — vecteur 12 dims depuis feature_extraction.py."""
    if not ml_ssh_enabled():
        return 0, 0.0
    try:
        model = load_ssh_model()
        X = np.array([featurize_ssh_cowrie(ev, fails_60s=fails_60s)], dtype=float)
        score = float(model.score_samples(X)[0])
        pred = int(model.predict(X)[0])
        return (1 if pred == -1 else 0), score
    except Exception:
        return 0, 0.0


# ---------------- Labels ----------------
def classify_http_label(event: dict) -> str:
    path = event.get("path", "")
    q = (event.get("query") or "").lower()
    body = (event.get("body") or "").lower()
    combined = q + " " + body

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
        # cowrie.command.failed = commande inconnue de Cowrie
        if etype == "cowrie.command.failed":
            return "ssh_command_failed"
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
    combined = qlow + " " + blow

    indicators = []
    base = 10

    asset = 0
    if any(path.startswith(p) for p in HTTP_SENSITIVE_PATHS):
        asset = 20
        indicators.append("sensitive_path")

    # ✅ Upload probe
    if path == "/upload":
        asset = max(asset, 15)
        indicators.append("upload_probe")

    # ✅ Admin enum — acces direct admin = toujours critique
    if path.startswith("/admin"):
        asset = max(asset, 35)
        indicators.append("enum_admin")

    # ✅ API endpoint — boost asset pour /api/*
    if path.startswith("/api/"):
        asset = max(asset, 20)
        indicators.append("api_endpoint")

    threat = 0
    if any(k in combined for k in HTTP_CMD_INJECTION_PATTERNS):
        threat += 40
        indicators.append("command_injection_pattern")
    if any(k in combined for k in HTTP_SUSPICIOUS_KEYWORDS):
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
        "base": base, "threat": threat, "frequency": freq,
        "asset": asset, "indicators": ind, "ml_boost": ml_boost,
        "req_60s": req_60s
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
    elif etype == "cowrie.command.failed":
        # ✅ Commande inconnue de Cowrie — signe d'un vrai attaquant
        if any(k in cmd for k in SSH_POST_EXP_KW):
            threat = 40
            indicators.append("command_failed_post_exploitation")
        elif any(k in cmd for k in SSH_RECON_KW):
            threat = 25
            indicators.append("command_failed_recon")
        else:
            threat = 30  # base=10 + threat=30 + ml_boost=20 = 60 -> seuil alerte atteint
            indicators.append("command_failed_unknown")
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

    ml_boost = 0
    if ml_is_anomaly:
        ml_boost = 20
        indicators.append("ml_anomaly")

    risk = clamp_0_100(base + threat + freq + ml_boost)
    components = {
        "base": base, "threat": threat, "frequency": freq,
        "asset": 0, "indicators": 0,
        "ml_boost": ml_boost, "failed_60s": fails_60s
    }
    return risk, components, indicators


def severity_from_risk(risk: int) -> int:
    return int(risk)


# ---------------- Position persistence ----------------
def load_positions() -> dict:
    """Charge les positions de lecture depuis le disque.
    Permet de reprendre exactement ou le collector s'est arrete
    apres un redemarrage ou un docker compose up --build."""
    try:
        with open(POS_FILE, "r") as f:
            pos = json.load(f)
            print(f"[collector] positions chargees: http={pos.get('http',0)} ssh={pos.get('ssh',0)}")
            return pos
    except (FileNotFoundError, json.JSONDecodeError):
        print("[collector] pas de positions sauvegardees — demarrage depuis la fin des logs")
        return {"http": 0, "ssh": 0}

def save_positions(http_pos: int, ssh_pos: int):
    """Sauvegarde les positions courantes sur le disque."""
    try:
        with open(POS_FILE, "w") as f:
            json.dump({"http": http_pos, "ssh": ssh_pos}, f)
    except Exception as e:
        print(f"[collector] erreur sauvegarde positions: {e}")

def get_file_size(path: str) -> int:
    """Retourne la taille du fichier ou 0 s'il n'existe pas."""
    try:
        return os.path.getsize(path)
    except OSError:
        return 0

# ---------------- Main loop ----------------
def main():
    init_db()
    print("[collector] started")
    print("[collector] DB:", DB_PATH)
    print("[collector] watching HTTP:", HTTP_LOG)
    print("[collector] watching SSH:", COWRIE_LOG)
    print("[collector] ML HTTP enabled:", ml_http_enabled(), "|", ML_HTTP_MODEL_PATH)
    print("[collector] ML SSH enabled :", ml_ssh_enabled(), "|", ML_SSH_MODEL_PATH)
    print(f"[collector] flood cap: max {MAX_INCIDENTS_PER_IP_60S} incidents/IP/{WINDOW_SECONDS}s")

    # ✅ Charger les positions depuis le disque
    # Si premier demarrage : partir de la fin des fichiers (ignorer anciens logs)
    # Si redemarrage : reprendre exactement ou on s'etait arrete
    _pos = load_positions()

    # Premier demarrage (pas de POS_FILE) → partir de la FIN pour ne pas rejouer les anciens logs
    if _pos["http"] == 0 and not os.path.exists(POS_FILE):
        _pos["http"] = get_file_size(HTTP_LOG)
        print(f"[collector] premier demarrage — HTTP pos initialisee a {_pos['http']} (fin du fichier)")
    if _pos["ssh"] == 0 and not os.path.exists(POS_FILE):
        _pos["ssh"] = get_file_size(COWRIE_LOG)
        print(f"[collector] premier demarrage — SSH pos initialisee a {_pos['ssh']} (fin du fichier)")

    http_pos = _pos["http"]
    ssh_pos  = _pos["ssh"]

    http_hits = defaultdict(lambda: deque())
    ssh_fails = defaultdict(lambda: deque())

    while True:
        now = time.time()

        # -------- HTTP --------
        http_pos, http_events = tail_jsonl(HTTP_LOG, http_pos)
        for ev in http_events:
            ts = ev.get("timestamp") or (datetime.utcnow().isoformat() + "Z")
            ip = ev.get("source_ip") or ""

            req_60s = 0
            if ip:
                dq = http_hits[ip]
                dq.append(now)
                while dq and now - dq[0] > WINDOW_SECONDS:
                    dq.popleft()
                req_60s = len(dq)

            if is_flood_ip(ip, _http_incident_counts, now):
                continue

            label = classify_http_label(ev)
            ml_is_anomaly, ml_score = ml_predict_http(ev)
            risk, comp, indicators = compute_rba_http(ev, req_60s, ml_is_anomaly)

            category = label
            if ml_is_anomaly and category == "http_activity":
                category = "http_anomaly"

            incident_id = insert_incident(
                ts, ip, "http", category, risk, json.dumps(ev),
                ml_is_anomaly=ml_is_anomaly, ml_score=ml_score
            )

            insert_ioc(incident_id, "path", ev.get("path"))
            insert_ioc(incident_id, "query", ev.get("query"))
            insert_ioc(incident_id, "user_agent", ev.get("user_agent"))

            if label == "command_injection" and should_alert(ip, "http_command_injection"):
                insert_alert(ts, ip, "http_command_injection", severity_from_risk(risk), {
                    "rba": {"risk": risk, "components": comp, "indicators": indicators},
                    "event": {
                        "path": ev.get("path", ""),
                        "query": short(ev.get("query", ""), 180),
                        "method": ev.get("method", ""),
                        "user_agent": short(ev.get("user_agent", ""), 120),
                    },
                    "category": label, "reason": "rule_match_command_injection"
                })

            if label == "injection_attempt" and should_alert(ip, "http_injection"):
                insert_alert(ts, ip, "http_injection", severity_from_risk(risk), {
                    "rba": {"risk": risk, "components": comp, "indicators": indicators},
                    "event": {
                        "path": ev.get("path", ""),
                        "query": short(ev.get("query", ""), 180),
                        "method": ev.get("method", ""),
                        "user_agent": short(ev.get("user_agent", ""), 120),
                    },
                    "category": label, "reason": "rule_match_injection"
                })

            # ✅ Bypass cooldown si anomalie ML critique (score < ML_CRITICAL_SCORE)
            # Une SSTI, Log4Shell ou autre attaque inconnue ne doit pas etre silenciee par le cooldown
            is_critical_ml = ml_is_anomaly and ml_score < ML_CRITICAL_SCORE
            if ml_is_anomaly and (risk >= RBA_ALERT_MED or ml_score < -0.60):
                if is_critical_ml or should_alert(ip, "http_anomaly"):
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

            if risk >= RBA_ALERT_HIGH and should_alert(ip, "http_high_risk"):
                insert_alert(ts, ip, "http_high_risk", severity_from_risk(risk), {
                    "rba": {"risk": risk, "components": comp, "indicators": indicators},
                    "event": {
                        "path": ev.get("path", ""),
                        "query": short(ev.get("query", ""), 180)
                    },
                    "category": label
                })

        # -------- SSH --------
        ssh_pos, ssh_events = tail_cowrie_json(COWRIE_LOG, ssh_pos)
        for ev in ssh_events:
            ts = ev.get("timestamp") or (datetime.utcnow().isoformat() + "Z")
            ip = ev.get("src_ip") or ev.get("srcip") or ev.get("src") or ""
            etype = ev.get("eventid", "")

            fails_60s = 0
            if ip:
                dq = ssh_fails[ip]
                if etype == "cowrie.login.failed":
                    dq.append(now)
                while dq and now - dq[0] > WINDOW_SECONDS:
                    dq.popleft()
                fails_60s = len(dq)

            if is_flood_ip(ip, _ssh_incident_counts, now):
                continue

            label = classify_ssh_label(ev)
            ml_is_anomaly, ml_score = ml_predict_ssh(ev, fails_60s)
            risk, comp, indicators = compute_rba_ssh(ev, fails_60s, ml_is_anomaly)

            category = label
            if ml_is_anomaly and category in ("ssh_activity", "ssh_command"):
                category = "ssh_anomaly"

            incident_id = insert_incident(
                ts, ip, "ssh", category, risk, json.dumps(ev),
                ml_is_anomaly=ml_is_anomaly, ml_score=ml_score
            )

            insert_ioc(incident_id, "eventid", ev.get("eventid"))
            insert_ioc(incident_id, "username", ev.get("username"))
            insert_ioc(incident_id, "password", ev.get("password"))
            insert_ioc(incident_id, "command", ev.get("input"))

            if fails_60s >= 5 and should_alert(ip, "ssh_bruteforce"):
                insert_alert(ts, ip, "ssh_bruteforce", severity_from_risk(risk), {
                    "rba": {"risk": risk, "components": comp, "indicators": indicators},
                    "failed_60s": fails_60s, "reason": "frequency_failed_logins"
                })

            if label == "post_exploitation" and should_alert(ip, "ssh_post_exploitation"):
                insert_alert(ts, ip, "ssh_post_exploitation", severity_from_risk(risk), {
                    "rba": {"risk": risk, "components": comp, "indicators": indicators},
                    "command": short(ev.get("input", ""), 180),
                    "username": ev.get("username", ""),
                    "eventid": ev.get("eventid", ""),
                    "reason": "rule_match_post_exploitation"
                })

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

        # ✅ Sauvegarder les positions a chaque iteration
        save_positions(http_pos, ssh_pos)
        time.sleep(2)


if __name__ == "__main__":
    main()