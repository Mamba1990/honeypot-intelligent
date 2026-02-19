import sqlite3
import json
from fastapi import FastAPI

DB_PATH = "/db/incidents.db"

app = FastAPI(title="Honeypot Intelligent - API")

def query_db(sql, params=()):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute(sql, params)
    rows = cur.fetchall()
    con.close()
    return [dict(r) for r in rows]

@app.get("/incidents")
def list_incidents(limit: int = 50):
    rows = query_db(
        "SELECT id, timestamp, source_ip, service, category, score FROM incidents ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    return {"items": rows}

@app.get("/incidents/{incident_id}")
def incident_detail(incident_id: int):
    rows = query_db("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    if not rows:
        return {"error": "not found"}
    row = rows[0]
    try:
        row["raw"] = json.loads(row["raw"])
    except Exception:
        pass
    return row

@app.get("/stats")
def stats():
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

# alerts
@app.get("/alerts")
def list_alerts(limit: int = 50):
    rows = query_db(
        "SELECT id, timestamp, source_ip, alert_type, severity, details FROM alerts ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    return {"items": rows}

# iocs for an incident
@app.get("/iocs/{incident_id}")
def incident_iocs(incident_id: int):
    rows = query_db(
        "SELECT ioc_type, ioc_value FROM iocs WHERE incident_id = ? ORDER BY id ASC",
        (incident_id,)
    )
    return {"items": rows}
