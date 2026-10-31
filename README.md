<div align="center">

# Honeypot Intelligent

### Hybrid HTTP & SSH Intrusion Detection: Expert Rules + Machine Learning

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Flask](https://img.shields.io/badge/Flask-HTTP%20Honeypot-lightgrey)
![Cowrie](https://img.shields.io/badge/Cowrie-SSH%20Honeypot-orange)
![FastAPI](https://img.shields.io/badge/FastAPI-REST%20API-009688)
![scikit-learn](https://img.shields.io/badge/scikit--learn-IsolationForest-F7931E)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED)
![License](https://img.shields.io/badge/License-Academic-green)

*Final project: Cybersecurity & Information Systems, Jobintech Class of 2026*
**Author: Hafsa Daoudim**

</div>

---

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Architecture](#architecture)
4. [Tech Stack](#tech-stack)
5. [Project Structure](#project-structure)
6. [Getting Started](#getting-started)
7. [Traffic Generation and Model Training](#traffic-generation-and-model-training)
8. [Detection Engine](#detection-engine)
9. [Validated Test Cases](#validated-test-cases)
10. [Model Evaluation](#model-evaluation)
11. [REST API](#rest-api)
12. [Network Security](#network-security)
13. [Troubleshooting](#troubleshooting)
14. [Limitations](#limitations)
15. [Roadmap](#roadmap)
16. [License](#license)

---

## Overview

**Honeypot Intelligent** is a modular intrusion detection system built around two deliberately vulnerable services: an HTTP web application and an SSH server. Every interaction is captured, enriched, scored and exposed through a REST API and a real-time dashboard.

Detection combines two complementary approaches:

- **Expert rules** catch known attack patterns (SQLi, command injection, bruteforce, post-exploitation).
- **Unsupervised Machine Learning** (Isolation Forest) flags statistically rare behavior that no rule covers (SSTI, obfuscated payloads, unknown commands).

A **Risk-Based Alerting (RBA)** score merges both signals so analysts see prioritized alerts instead of raw logs.

---

## Key Features

- **Dual-protocol capture**: Flask HTTP honeypot (13 exposed endpoints) and Cowrie SSH honeypot.
- **Hybrid detection**: rule engine and Isolation Forest working together, with three validated modes: rule-only, ML-only and hybrid.
- **16 HTTP features / 12 SSH features** extracted by one shared module, guaranteeing identical vectors at training and inference time.
- **Composite RBA scoring** (0-100) with configurable alert thresholds.
- **Cooldown with critical bypass**: 60 s anti-spam per (IP, alert type), bypassed when `ml_score < -0.62` so critical anomalies are never silenced.
- **Resilient log reading**: incremental `tail_jsonl` with read positions persisted across restarts.
- **Flood protection**: per-IP incident cap to prevent database saturation.
- **Network segmentation**: two Docker networks with a verified isolation test.
- **REST API and dashboard** with incidents, alerts, IOCs, KPIs and ML metrics.
- **Synthetic traffic generators** to bootstrap the ML models from day one.

---

## Architecture

```
                        honeypot-net (exposed zone)
 ┌──────────┐      ┌───────────────────────────────────┐
 │ Attacker │ ───► │ HTTP Honeypot (Flask  :8081)      │──► http_events.jsonl ─┐
 │          │ ───► │ SSH  Honeypot (Cowrie :2222)      │──► cowrie.json      ──┤
 └──────────┘      └───────────────────────────────────┘                       │
                                                                               ▼
                                     ┌──────────────────────────────────────────┐
                                     │ Collector (bridge between both networks) │
                                     │ rules → features → Isolation Forest → RBA│
                                     └──────────────────────┬───────────────────┘
                        internal-net (internal zone)        ▼
                     ┌─────────────────────────────────────────────────────────┐
                     │ SQLite (incidents, alerts, iocs)                        │
                     │      ▼                                                  │
                     │ FastAPI (127.0.0.1:8000)  ──►  Dashboard                │
                     └─────────────────────────────────────────────────────────┘
```

**Division of responsibilities**

| Component | Role | Analogy |
|-----------|------|---------|
| Honeypots | Capture everything, analyze nothing | The net |
| Collector | Classify, extract features, score, enrich | The processing plant |
| SQLite | Store enriched incidents | The warehouse |
| FastAPI | Read-only access to data | The service desk |
| Dashboard | Visualization for analysts | The control panel |

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| HTTP honeypot | Python, Flask |
| SSH honeypot | Cowrie |
| Collector | Python 3.11 |
| Machine Learning | scikit-learn (IsolationForest), NumPy, joblib |
| Database | SQLite |
| API | FastAPI, Uvicorn |
| Dashboard | HTML / JavaScript |
| Deployment | Docker, Docker Compose |

---

## Project Structure

```
honeypot-intelligent/
├── api/
│   ├── api.py                     # FastAPI application
│   └── Dockerfile
├── collector/
│   ├── collector.py               # Analysis engine (rules + ML + RBA)
│   ├── feature_extraction.py      # Copy of ml/feature_extraction.py (baked into the image)
│   └── Dockerfile
├── cowrie/
│   ├── cowrie.cfg                 # Cowrie configuration (JSON logging enabled)
│   └── userdb.txt                 # Accepted credentials
├── webhoneypot/
│   ├── app.py                     # Flask honeypot
│   └── Dockerfile
├── ml/
│   ├── feature_extraction.py      # Shared feature module (HTTP 16-d, SSH 12-d)
│   ├── train_http.py              # HTTP training script
│   ├── train_ssh.py               # SSH training script
│   ├── eval_http.py               # HTTP evaluation script
│   ├── eval_ssh.py                # SSH evaluation script
│   ├── model_http.joblib          # Trained HTTP model
│   └── model_ssh.joblib           # Trained SSH model
├── traffic_generator/
│   ├── http_generator.py          # HTTP traffic (normal / suspicious / mixed)
│   └── ssh_log_generator.py       # SSH sessions written in Cowrie JSON format
├── db/
│   ├── incidents.db               # SQLite database
│   └── collector_pos.json         # Persisted log read positions
├── docker-compose.yml
└── README.md
```

---

## Getting Started

### Prerequisites

- Docker and Docker Compose v2+
- Python 3.11+ (only for local training and evaluation)

### 1. Clone

```bash
git clone https://github.com/<your-username>/honeypot-intelligent.git
cd honeypot-intelligent
```

### 2. Start the stack

```bash
docker compose up -d --build
```

| Service | Address | Notes |
|---------|---------|-------|
| SSH honeypot (Cowrie) | `localhost:2222` | Exposed |
| HTTP honeypot (Flask) | `localhost:8081` | Exposed |
| REST API / Dashboard | `127.0.0.1:8000` | Localhost only |

The traffic generators sit behind a Compose profile, so a plain `docker compose up` never starts them.

### 3. Verify

```bash
curl http://127.0.0.1:8000/health      # {"status":"ok"}
curl http://localhost:8081/            # <h3>It works.</h3>
```

Open the dashboard at `http://127.0.0.1:8000/dashboard`.

---

## Traffic Generation and Model Training

A freshly deployed honeypot has no data, and public intrusion datasets (CICIDS, NSL-KDD, UNSW-NB15) do not match this project's log schema (`method`, `path`, `query`, `body`, `user_agent` for HTTP; `eventid`, `username`, `input`, `src_ip` for SSH). Two generators bootstrap the models instead.

```bash
# HTTP
docker compose --profile generator run --rm -e COUNT=1000 httpgen-normal
docker compose --profile generator run --rm -e COUNT=1000 httpgen-suspicious

# SSH
docker compose --profile generator run --rm -e COUNT=500 sshgen-normal
docker compose --profile generator run --rm -e COUNT=500 sshgen-suspicious
```

Generators add deliberate variability (random source IPs, diverse User-Agents, random delays, mixed command sets) so the model does not learn artificial regularities.

### Train and evaluate

```bash
cd ml
python3 train_http.py && python3 train_ssh.py
python3 eval_http.py  && python3 eval_ssh.py
```

**Training pipeline:** load, filter noise, deduplicate, drop NaN/Inf vectors, 80/20 split, train, evaluate, save with joblib.

**Filtered as noise:** static assets, HEAD/OPTIONS requests and empty payloads for HTTP; connection plumbing events (`session.connect`, `client.kex`, `client.version`, ...) for SSH. Only four SSH events are analyzed: `login.failed`, `login.success`, `command.input` and `command.failed`.

> **Note on retraining:** the Isolation Forest is a batch model. It predicts in real time but does not learn online. Improvement comes from explicit, periodic retraining on accumulated data, which keeps results reproducible and protects against data poisoning.

---

## Detection Engine

### Collector pipeline

1. **Read** new log lines incrementally (`tail_jsonl`, position persisted to disk).
2. **Classify** with expert rules (`classify_http_label`, `classify_ssh_label`).
3. **Predict** with Isolation Forest (`ml_predict_http`, `ml_predict_ssh`).
4. **Score** with RBA (`compute_rba_http`, `compute_rba_ssh`).
5. **Persist** incident, IOCs and alerts to SQLite.

### Rules

| Label | Trigger | Alert |
|-------|---------|-------|
| `injection_attempt` | `or 1=1`, `union select`, `<script`, `../` | `http_injection` |
| `command_injection` | `;`, `&&`, `\|`, `wget`, `curl`, `bash`, `nc` | `http_command_injection` |
| `upload_probe` | access to `/upload` | none (RBA boost) |
| `enum_admin` | `/admin`, `/wp-admin`, `/.env`, `/render`, ... | none (RBA boost) |
| `ssh_login_failed` | `fails_60s >= 5` | `ssh_bruteforce` |
| `post_exploitation` | `wget`, `curl`, `chmod`, `bash`, `nc` | `ssh_post_exploitation` |
| `ssh_command_failed` | `cowrie.command.failed` (unknown command) | `ssh_anomaly` when confirmed by ML |

### RBA score

```
Score = Base(10) + Threat(0-50) + Frequency(0-40) + Asset(0-35, HTTP)
        + Indicators(0-20, HTTP) + ML_Boost(0 or 20)        [capped at 100]
```

| Threshold | Value | Effect |
|-----------|-------|--------|
| `RBA_ALERT_MED` | 60 | Standard alerts |
| `RBA_ALERT_HIGH` | 80 | `http_high_risk` |
| `ML_CRITICAL_SCORE` | -0.62 | Bypasses the 60 s cooldown (HTTP) |
| Cooldown | 60 s | Per (IP, alert type) |
| Flood cap | 10 incidents / IP / 60 s | Protects the database |

The critical threshold sits at the 5th percentile of the observed score distribution, consistent with `contamination=0.05`.

### Features

**HTTP (16):** `is_post`, `query_len`, `has_suspicious_kw`, `is_sensitive_path`, `ua_len`, `body_len`, `has_encoded_chars`, `path_depth`, `ua_entropy`, `has_template_syntax`, `has_cmd_injection`, `query_entropy`, `has_ssrf`, `has_file_inclusion`, `has_xxe`, `body_entropy`

**SSH (12):** `is_login_failed`, `is_login_success`, `is_command`, `has_post_exploitation`, `has_recon`, `cmd_len`, `username_len`, `fails_60s`, `has_privesc`, `has_persistence`, `cmd_entropy`, `is_common_user`

### Exposed HTTP endpoints

`/admin`, `/wp-admin`, `/phpmyadmin`, `/wp-login.php`, `/login`, `/signin`, `/auth`, `/api/parse`, `/api/search`, `/render`, `/.env`, `/actuator`, `/upload`

---

## Validated Test Cases

Six live scenarios cover all three detection modes.

### HTTP

**1. XXE: hybrid (rule + ML), score 100**
```bash
curl -X POST http://localhost:8081/api/parse \
  -H "Content-Type: application/xml" \
  -d '<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>'
```
Alerts: `http_command_injection` + `http_anomaly` + `http_high_risk`

**2. SSTI: ML only with cooldown bypass, score 70**
```bash
curl -X POST -A "ScannerProbe-TemplateEngine-ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
  "http://localhost:8081/render?tpl=%7B%7B7*7%7D%7D" -d "name=test"
```
No SSTI rule exists. `ml_score = -0.6258` is below `-0.62`, so the alert fires immediately.

**3. SQL injection: rule only, score 60**
```bash
curl "http://localhost:8081/search?id=1'+UNION+SELECT+username,password+FROM+users--"
```
Alert: `http_command_injection`, `ml_is_anomaly = 0`.

### SSH

**4. Bruteforce: rule only, score 50**
```bash
for i in {1..6}; do
  sshpass -p wrongpass ssh -p 2222 -o StrictHostKeyChecking=no root@localhost
done
```
Alert: `ssh_bruteforce` (`fails_60s >= 5`).

**5. Privilege escalation: ML only, score 60**
```bash
ssh -p 2222 root@localhost     # then: usermod -aG sudo hacker
```
Unknown to Cowrie, so it becomes `cowrie.command.failed` with `has_privesc = 1`. Alert: `ssh_anomaly`.

**6. Privilege escalation after retraining: hybrid, score 60**
`base(10) + threat(30) + ml_boost(20) = 60`. The rule alone gives 40 and the ML alone gives 30; only the combination reaches the alert threshold.

---

## Model Evaluation

Latest runs of the evaluation scripts:

| Metric | HTTP | SSH |
|--------|------|-----|
| Samples | 6,094 | 1,518 |
| Features | 16 | 12 |
| Anomaly ratio | 13.77 % | 5.01 % |
| Score min | -0.6925 | -0.6179 |
| p05 | -0.6435 | -0.5973 |

The most anomalous HTTP events are path traversals to `/../../../etc/passwd` sent by scanners such as Nuclei and masscan. The HTTP anomaly ratio exceeds the `contamination` setting because an active honeypot receives far more attacks than the synthetic 5 % baseline.

Reference dashboard snapshot: 42,128 incidents, 5,352 alerts, 2,163 ML anomalies.

---

## REST API

Base URL: `http://127.0.0.1:8000` (interactive docs at `/docs`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Service status |
| GET | `/dashboard` | Dashboard page |
| GET | `/dashboard-data` | KPIs, top IPs, categories |
| GET | `/incidents` | Paginated incidents |
| GET | `/incidents/{id}` | Incident detail |
| GET | `/alerts` | Alerts by severity |
| GET | `/alerts/{id}` | Alert detail with RBA breakdown |
| GET | `/stats` | Global statistics |
| GET | `/iocs/{incident_id}` | Indicators of compromise |
| GET | `/ml/metrics` | ML model metrics |

Example alert:

```json
{
  "id": 3367,
  "alert_type": "http_command_injection",
  "severity": 60,
  "details": {
    "rba": {
      "risk": 60,
      "components": {
        "base": 10, "threat": 40, "frequency": 0,
        "asset": 0, "indicators": 10, "ml_boost": 0
      }
    },
    "reason": "rule_match_command_injection"
  }
}
```

---

## Network Security

The Compose file defines two networks:

```yaml
networks:
  honeypot-net:    # cowrie, webhoneypot, generators
  internal-net:    # api (the collector sits in both)
```

- The **collector** is the only bridge between the exposed and internal zones.
- The **API** is published on `127.0.0.1:8000` only.
- Cowrie **simulates** `wget` and `curl`, so no real outbound connection is made.

Isolation test:

```bash
docker exec cowrie python3 -c "
import urllib.request
try:
    urllib.request.urlopen('http://api:8000/health', timeout=3); print('PROBLEM')
except Exception:
    print('OK: isolation confirmed')"
```

> Production hardening (host firewall rules, API authentication, HTTPS, rate limiting) is listed in the roadmap.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| SSH events stop appearing | Cowrie rotated `cowrie.json`; the saved position is past the end of the file | Stop the collector, set `"ssh": 0` in `db/collector_pos.json` (may need `sudo`), restart |
| `No module named 'feature_extraction'` | Module missing from the collector image | Copy it into `collector/` and add `COPY feature_extraction.py /app/` to the Dockerfile |
| Dashboard unchanged after clearing logs | The dashboard reads SQLite, not log files | Delete rows from `incidents` / `alerts` from the collector container (the API mounts the DB read-only) |
| Few HTTP incidents from generators | Per-IP flood cap | Temporarily raise `MAX_INCIDENTS_PER_IP_60S` while generating training data |
| sklearn `InconsistentVersionWarning` | Model trained with a different version | Retrain inside the collector container |
| Port 8081 already in use | Stale container or process | `docker ps -a`, stop the owner, then `docker compose up -d` |

---

## Limitations

- Training data is synthetic; progressive retraining on real traffic is recommended.
- SQLite is sufficient at this scale (tens of thousands of incidents) but not for production volumes.
- The ML model is batch-trained and does not adapt online.
- Only HTTP and SSH are covered. HTTP request smuggling, HTTP/2 downgrade, WebSocket abuse and SFTP uploads are not captured.
- Some HTTP signals are not extracted yet: `Host`, `Referer` and `Cookie` headers, and case-insensitive path matching.
- The API has no authentication or HTTPS in the current prototype.

---

## Roadmap

- [ ] Migrate to PostgreSQL
- [ ] Real-time notifications (email, Slack, webhook)
- [ ] SIEM integration (Elasticsearch / Kibana, Splunk)
- [ ] Extract `Host`, `Referer`, `Cookie` features and normalize path matching
- [ ] Automatic detection of rotated Cowrie logs
- [ ] Scheduled retraining (cron) on recent real traffic
- [ ] Evaluate online anomaly detectors (Half-Space Trees, RRCF)
- [ ] API authentication, HTTPS and rate limiting
- [ ] Additional honeypots: FTP, Telnet, RDP, SMTP
- [ ] Threat-intelligence sharing (MISP, VirusTotal)

---

## License

Academic and educational project, non-commercial use only.

**Hafsa Daoudim** — Cybersecurity & Machine Learning
Jobintech, Class of 2026
