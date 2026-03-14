import json
import sqlite3
import os
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import APIKeyHeader
from fastapi import Security

DB_PATH = "/db/incidents.db"

app = FastAPI(title="Honeypot Intelligent - API")

# ---- Simple API Key (MVP) ----
API_KEY = os.getenv("API_KEY", "honeypot-secret-key")

# 🔑 Déclare la clé API pour Swagger (bouton Authorize)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def check_api_key(api_key: str = Security(api_key_header)):
    """
    Vérifie la clé API envoyée via:
      X-API-Key: <clé>
    """
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
    """Transforme un champ TEXT contenant du JSON en dict/list."""
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


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/incidents")
def list_incidents(limit: int = 50, _=Depends(check_api_key)):
    rows = query_db(
        "SELECT id, timestamp, source_ip, service, category, score FROM incidents ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    return {"items": rows}


@app.get("/incidents/{incident_id}")
def incident_detail(incident_id: int, _=Depends(check_api_key)):
    rows = query_db("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="not found")

    row = rows[0]
    row["raw"] = parse_json_if_possible(row.get("raw"))
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


@app.get("/alerts")
def list_alerts(limit: int = 50, _=Depends(check_api_key)):
    rows = query_db(
        "SELECT id, timestamp, source_ip, alert_type, severity, details FROM alerts ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    # ✅ rendre details lisible (dict) au lieu d'une string JSON
    for r in rows:
        r["details"] = parse_json_if_possible(r.get("details"))
    return {"items": rows}


@app.get("/iocs/{incident_id}")
def incident_iocs(incident_id: int, _=Depends(check_api_key)):
    rows = query_db(
        "SELECT ioc_type, ioc_value FROM iocs WHERE incident_id = ? ORDER BY id ASC",
        (incident_id,)
    )
    return {"items": rows}

@app.get("/ml/metrics")
def ml_metrics(_=Depends(check_api_key)):
    path = "/db/ml_metrics.json"  # ou /app/ml/reports/ml_metrics.json selon montage
    if not os.path.exists(path):
        return {"error": "ml_metrics.json not found"}
    with open(path, "r") as f:
        return json.load(f)
