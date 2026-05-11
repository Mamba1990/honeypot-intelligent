import json
import sqlite3
import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.responses import FileResponse
from fastapi.security import APIKeyHeader

DB_PATH = "/db/incidents.db"
BASE_DIR = Path(__file__).resolve().parent
DASHBOARD_HTML = BASE_DIR / "dashboard" / "index.html"

app = FastAPI(title="Honeypot Intelligent - API")

API_KEY = os.getenv("API_KEY", "honeypot-secret-key")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def check_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")


def get_con():
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def query_db(sql, params=()):
    con = get_con()
    cur = con.cursor()
    cur.execute(sql, params)
    rows = cur.fetchall()
    con.close()
    return [dict(r) for r in rows]


def parse_json_if_possible(value):
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    s = str(value).strip()
    if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
        try:
            return json.loads(s)
        except Exception:
            return value
    return value


def table_has_column(table_name: str, column_name: str) -> bool:
    con = get_con()
    cur = con.cursor()
    cur.execute(f"PRAGMA table_info({table_name})")
    cols = [row[1] for row in cur.fetchall()]
    con.close()
    return column_name in cols


@app.get("/")
def root():
    return {
        "service": "honeypot-intelligent-api",
        "message": "API active",
        "dashboard": "/dashboard",
        "endpoints": [
            "/incidents",
            "/incidents/{incident_id}",
            "/alerts",
            "/alerts/{alert_id}",
            "/stats",
            "/dashboard-data",
            "/dashboard",
            "/health",
            "/iocs/{incident_id}",
            "/ml/metrics"
        ]
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/dashboard")
def dashboard():
    if not DASHBOARD_HTML.exists():
        raise HTTPException(status_code=404, detail="dashboard file not found")
    return FileResponse(str(DASHBOARD_HTML))


# ── MODIFIED: added optional filters category, service, source_ip, ml_only ──
@app.get("/incidents")
def list_incidents(
    limit: int = 50,
    category: Optional[str] = None,
    service: Optional[str] = None,
    source_ip: Optional[str] = None,
    ml_only: Optional[int] = None,
    _=Depends(check_api_key)
):
    conditions = []
    params = []

    if category:
        conditions.append("category = ?")
        params.append(category)
    if service:
        conditions.append("service = ?")
        params.append(service)
    if source_ip:
        conditions.append("source_ip = ?")
        params.append(source_ip)
    if ml_only == 1 and table_has_column("incidents", "ml_is_anomaly"):
        conditions.append("ml_is_anomaly = 1")

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(limit)

    rows = query_db(
        f"SELECT id, timestamp, source_ip, service, category, score, ml_is_anomaly "
        f"FROM incidents {where} ORDER BY id DESC LIMIT ?",
        tuple(params)
    )
    return {"incidents": rows, "total": len(rows)}


@app.get("/incidents/{incident_id}")
def incident_detail(incident_id: int, _=Depends(check_api_key)):
    rows = query_db("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="not found")
    row = rows[0]
    row["raw"] = parse_json_if_possible(row.get("raw"))
    return row


# ── MODIFIED: added optional filter alert_type ──
@app.get("/alerts")
def list_alerts(
    limit: int = 50,
    alert_type: Optional[str] = None,
    _=Depends(check_api_key)
):
    conditions = []
    params = []

    if alert_type:
        conditions.append("alert_type = ?")
        params.append(alert_type)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(limit)

    rows = query_db(
        f"SELECT id, timestamp, source_ip, alert_type, severity, details "
        f"FROM alerts {where} ORDER BY id DESC LIMIT ?",
        tuple(params)
    )
    for r in rows:
        r["details"] = parse_json_if_possible(r.get("details"))
    return {"alerts": rows, "total": len(rows)}


@app.get("/alerts/{alert_id}")
def alert_detail(alert_id: int, _=Depends(check_api_key)):
    rows = query_db("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="not found")
    row = rows[0]
    row["details"] = parse_json_if_possible(row.get("details"))
    return row


@app.get("/stats")
def stats(_=Depends(check_api_key)):
    top_ips = query_db("""
        SELECT source_ip, COUNT(*) as cnt
        FROM incidents
        WHERE source_ip IS NOT NULL AND source_ip != ''
        GROUP BY source_ip
        ORDER BY cnt DESC
        LIMIT 10
    """)
    top_categories = query_db("""
        SELECT category, COUNT(*) as cnt
        FROM incidents
        GROUP BY category
        ORDER BY cnt DESC
        LIMIT 10
    """)
    return {"top_ips": top_ips, "top_categories": top_categories}


@app.get("/iocs/{incident_id}")
def incident_iocs(incident_id: int, _=Depends(check_api_key)):
    rows = query_db(
        "SELECT ioc_type, ioc_value FROM iocs WHERE incident_id = ? ORDER BY id ASC",
        (incident_id,)
    )
    return {"items": rows}


@app.get("/ml/metrics")
def ml_metrics(_=Depends(check_api_key)):
    path = "/db/ml_metrics.json"
    if not os.path.exists(path):
        return {"error": "ml_metrics.json not found"}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


@app.get("/dashboard-data")
def dashboard_data(_=Depends(check_api_key)):
    summary = {
        "total_incidents": 0,
        "total_alerts": 0,
        "http_incidents": 0,
        "ssh_incidents": 0,
        "ml_anomalies": 0,
    }

    total_incidents = query_db("SELECT COUNT(*) as cnt FROM incidents")
    total_alerts    = query_db("SELECT COUNT(*) as cnt FROM alerts")
    http_incidents  = query_db("SELECT COUNT(*) as cnt FROM incidents WHERE service = 'http'")
    ssh_incidents   = query_db("SELECT COUNT(*) as cnt FROM incidents WHERE service = 'ssh'")

    summary["total_incidents"] = total_incidents[0]["cnt"] if total_incidents else 0
    summary["total_alerts"]    = total_alerts[0]["cnt"]    if total_alerts    else 0
    summary["http_incidents"]  = http_incidents[0]["cnt"]  if http_incidents  else 0
    summary["ssh_incidents"]   = ssh_incidents[0]["cnt"]   if ssh_incidents   else 0

    if table_has_column("incidents", "ml_is_anomaly"):
        ml_rows = query_db("SELECT COUNT(*) as cnt FROM incidents WHERE ml_is_anomaly = 1")
        summary["ml_anomalies"] = ml_rows[0]["cnt"] if ml_rows else 0

    top_ips = query_db("""
        SELECT source_ip, COUNT(*) as cnt
        FROM incidents
        WHERE source_ip IS NOT NULL AND source_ip != ''
        GROUP BY source_ip ORDER BY cnt DESC LIMIT 8
    """)

    top_categories = query_db("""
        SELECT category, COUNT(*) as cnt
        FROM incidents
        GROUP BY category ORDER BY cnt DESC LIMIT 8
    """)

    recent_incidents = query_db("""
        SELECT id, timestamp, source_ip, service, category, score, ml_is_anomaly
        FROM incidents ORDER BY id DESC LIMIT 10
    """)

    recent_alerts = query_db("""
        SELECT id, timestamp, source_ip, alert_type, severity, details
        FROM alerts ORDER BY id DESC LIMIT 10
    """)
    for r in recent_alerts:
        r["details"] = parse_json_if_possible(r.get("details"))

    alert_types = query_db("""
        SELECT alert_type, COUNT(*) as cnt
        FROM alerts
        GROUP BY alert_type ORDER BY cnt DESC LIMIT 8
    """)

    return {
        "summary": summary,
        "top_ips": top_ips,
        "top_categories": top_categories,
        "recent_incidents": recent_incidents,
        "recent_alerts": recent_alerts,
        "alert_types": alert_types,
    }