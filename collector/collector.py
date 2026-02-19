import os
import json
import sqlite3
import time
from datetime import datetime

DB_PATH = "/db/incidents.db"

HTTP_LOG = "/web/logs/http_events.jsonl"
COWRIE_LOG = "/cowrie/var/log/cowrie/cowrie.json"


# BD
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
    con.close()


def insert_incident(ts, ip, service, category, score, raw) -> int:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
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
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        INSERT INTO alerts(timestamp, source_ip, alert_type, severity, details)
        VALUES (?, ?, ?, ?, ?)
    """, (ts, ip, alert_type, severity, details))
    con.commit()
    con.close()


# ---------------- HTTP classification ----------------
def classify_http(event: dict):
    path = event.get("path", "")
    q = (event.get("query") or "").lower()
    body = (event.get("body") or "").lower()

    suspicious = ["' or 1=1", "<script", "../", "union select", "sleep(", "xp_cmdshell"]
    is_injection = any(s in q or s in body for s in suspicious)

    if path in ["/admin", "/phpmyadmin", "/wp-login.php"]:
        return ("enum_admin", 50)
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


# SSH (Cowrie) classification 
def classify_ssh(ev: dict):
    etype = ev.get("eventid", "")

    if etype == "cowrie.login.failed":
        return ("ssh_login_failed", 40)
    if etype == "cowrie.login.success":
        return ("ssh_login_success", 60)

    if etype == "cowrie.command.input":
        cmd = (ev.get("input") or "").lower()

        # "post exploitation" (téléchargement / exécution)
        if any(x in cmd for x in ["wget", "curl", "chmod", "bash", "python", "nc ", "netcat"]):
            return ("post_exploitation", 85)

        # reconnaissance
        if any(x in cmd for x in ["uname", "whoami", "id", "cat /etc/passwd"]):
            return ("recon", 70)

        return ("ssh_command", 50)

    return ("ssh_activity", 30)


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


# Main loop
def main():
    init_db()
    print("[collector] started")
    print("[collector] DB:", DB_PATH)
    print("[collector] watching HTTP:", HTTP_LOG)
    print("[collector] watching SSH:", COWRIE_LOG)

    http_pos = 0
    ssh_pos = 0

    # brute-force detection memory (simple)
    # ip -> list[timestamps epoch seconds] of failed logins
    failed_logins = {}

    while True:
        # HTTP
        http_pos, http_events = tail_jsonl(HTTP_LOG, http_pos)
        for ev in http_events:
            ts = ev.get("timestamp") or (datetime.utcnow().isoformat() + "Z")
            ip = ev.get("source_ip") or ""
            cat, score = classify_http(ev)

            incident_id = insert_incident(ts, ip, "http", cat, score, json.dumps(ev))

            # IOCs
            insert_ioc(incident_id, "path", ev.get("path"))
            insert_ioc(incident_id, "query", ev.get("query"))
            insert_ioc(incident_id, "user_agent", ev.get("user_agent"))

        # SSH / Cowrie
        ssh_pos, ssh_events = tail_cowrie_json(COWRIE_LOG, ssh_pos)
        for ev in ssh_events:
            ip = ev.get("src_ip") or ev.get("srcip") or ev.get("src") or ""
            ts = ev.get("timestamp") or (datetime.utcnow().isoformat() + "Z")

            # brute-force detect (>= 5 failed logins in 60 sec)
            if ev.get("eventid") == "cowrie.login.failed" and ip:
                now = time.time()
                failed_logins.setdefault(ip, []).append(now)
                failed_logins[ip] = [t for t in failed_logins[ip] if now - t <= 60]

                if len(failed_logins[ip]) >= 5:
                    insert_alert(ts, ip, "ssh_bruteforce", 80, f"{len(failed_logins[ip])} failed logins in 60s")
                    failed_logins[ip] = []  # reset to avoid spam

            cat, score = classify_ssh(ev)
            incident_id = insert_incident(ts, ip, "ssh", cat, score, json.dumps(ev))

            # IOCs
            insert_ioc(incident_id, "eventid", ev.get("eventid"))
            insert_ioc(incident_id, "username", ev.get("username"))
            insert_ioc(incident_id, "password", ev.get("password"))
            insert_ioc(incident_id, "command", ev.get("input"))

        time.sleep(2)


if __name__ == "__main__":
    main()
