# 🍯 Honeypot Intelligent — HTTP & SSH

> Détection hybride d'intrusions par règles expertes et Machine Learning

Projet de fin de formation en Cybersécurité & Systèmes d'Informations — **Jobintech Promotion 2026**  
Réalisé par : **Hafsa Daoudim**

---

## 📌 Description

Système honeypot intelligent multi-protocoles capable de :

- **Capturer** le trafic malveillant HTTP et SSH en temps réel
- **Classifier** les attaques par règles expertes (SQLi, XSS, LFI, XXE, SSTI, bruteforce...)
- **Détecter** les comportements anormaux inconnus via Machine Learning (Isolation Forest)
- **Scorer** chaque événement avec un Risk-Based Alerting (RBA) composite
- **Alerter** et visualiser via une API REST et un dashboard temps réel

---

## 🏗️ Architecture

```
Attaquant
    │
    ├──► HTTP Honeypot (Flask :8081)  ──► http_events.jsonl ──┐
    │                                                          │
    └──► SSH Honeypot (Cowrie :2222)  ──► cowrie.json        ──┤
                                                               │
                                                     Collector (Règles + ML + RBA)
                                                               │
                                                         SQLite DB (/db/incidents.db)
                                                               │
                                                      API FastAPI (:8000)
                                                               │
                                                          Dashboard
```

**Deux réseaux Docker distincts pour l'isolation :**
- `honeypot-net` — zone exposée (cowrie, webhoneypot)
- `internal-net` — zone interne (collector, api, db)

---

## ⚙️ Stack Technologique

| Composant | Technologie | Rôle |
|-----------|-------------|------|
| Honeypot HTTP | Python / Flask | Capture requêtes HTTP malveillantes |
| Honeypot SSH | Cowrie | Émulation SSH basse interaction |
| Collector | Python 3.11 | Analyse, scoring RBA, persistance |
| Machine Learning | scikit-learn IsolationForest | Détection d'anomalies non supervisée |
| Base de données | SQLite | Stockage incidents, alertes, IOCs |
| API REST | FastAPI | Exposition des données aux clients |
| Dashboard | HTML / JS | Visualisation temps réel |
| Orchestration | Docker Compose | Déploiement multi-conteneurs |

---

## 📁 Structure du Projet

```
honeypot-intelligent/
│
├── api/
│   ├── api.py                    # API FastAPI
│   └── Dockerfile
│
├── collector/
│   ├── collector.py              # Moteur d'analyse (règles + ML + RBA)
│   └── Dockerfile
│
├── cowrie/
│   ├── cowrie.cfg                # Configuration Cowrie
│   └── userdb.txt                # Credentials acceptés par Cowrie
│
├── webhoneypot/
│   ├── app.py                    # Honeypot HTTP Flask
│   └── Dockerfile
│
├── ml/
│   ├── feature_extraction.py     # Extraction features HTTP (16 dims) et SSH (12 dims)
│   ├── train_http.py             # Entraînement modèle HTTP
│   ├── train_ssh.py              # Entraînement modèle SSH
│   ├── eval_http.py              # Évaluation modèle HTTP
│   ├── eval_ssh.py               # Évaluation modèle SSH
│   ├── model_http.joblib         # Modèle HTTP entraîné
│   └── model_ssh.joblib          # Modèle SSH entraîné
│
├── traffic_generator/
│   ├── http_generator.py         # Générateur trafic HTTP (normal/suspicious/mixed)
│   └── ssh_log_generator.py      # Générateur trafic SSH avec cowrie.command.failed
│
├── db/
│   └── incidents.db              # Base SQLite
│
├── docker-compose.yml
└── README.md
```

---

## 🚀 Installation et Démarrage

### Prérequis

- Docker Desktop
- Docker Compose v2+
- Python 3.11+ (pour l'entraînement ML en local)

### 1. Cloner le projet

```bash
git clone https://github.com/TON_USERNAME/honeypot-intelligent.git
cd honeypot-intelligent
```

### 2. Lancer le système

```bash
docker compose up -d
```

Services démarrés :

| Service | Port | Description |
|---------|------|-------------|
| SSH Honeypot (Cowrie) | 2222 | Piège SSH |
| HTTP Honeypot | 8081 | Piège HTTP |
| API FastAPI | 127.0.0.1:8000 | API REST (localhost uniquement) |

### 3. Vérifier que tout fonctionne

```bash
curl http://127.0.0.1:8000/health
# → {"status":"ok"}

curl http://localhost:8081/
# → <h3>It works.</h3>
```

---

## 🎯 Entraînement du Modèle ML

### Générer du trafic synthétique

```bash
# Trafic HTTP normal
docker compose --profile generator run --rm httpgen-normal

# Trafic HTTP suspect
docker compose --profile generator run --rm httpgen-suspicious

# Trafic SSH suspect (inclut cowrie.command.failed)
docker compose --profile generator run --rm sshgen-suspicious
```

### Entraîner les modèles

```bash
cd ml
python3 train_http.py   # → model_http.joblib (16 features)
python3 train_ssh.py    # → model_ssh.joblib  (12 features)
```

### Évaluer les modèles

```bash
python3 eval_http.py    # Métriques + histogramme http_scores_hist.png
python3 eval_ssh.py     # Métriques + histogramme ssh_scores_hist.png
```

---

## 🔬 Cas de Test Validés

### HTTP — SQLi UNION SELECT (règle pure)

```bash
curl "http://localhost:8081/search?id=1'+UNION+SELECT+username,password+FROM+users--"
# → http_command_injection | Score : 60 | ml_is_anomaly : 0
```

### HTTP — SSTI avec bypass cooldown (ML pur)

```bash
curl -X POST \
  -A "ScannerProbe-TemplateEngine-Check-ABCDEFGHIJKLMNOPQRSTUVWXYZ-1234567890" \
  "http://localhost:8081/render?tpl=%7B%7B7*7%7D%7D" \
  -d "name=test"
# → http_anomaly | Score : 70 | ml_score : -0.6258 | bypass cooldown actif
```

### HTTP — XXE (hybride règle + ML)

```bash
curl -X POST http://localhost:8081/api/parse \
  -H "Content-Type: application/xml" \
  -d '<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>'
# → http_command_injection + http_anomaly + http_high_risk | Score : 100
```

### SSH — Bruteforce (règle pure)

```bash
ssh -p 2222 test@localhost -o NumberOfPasswordPrompts=10
# 5+ échecs en 60s → ssh_bruteforce | Score : 50 | fails_60s : 5
```

### SSH — Escalade de privilèges via command.failed (ML pur)

```bash
ssh -p 2222 root@localhost
# Puis dans le shell Cowrie :
usermod -aG sudo hacker
# → cowrie.command.failed → ssh_anomaly | Score : 60 | has_privesc=1.0
```

### SSH — Hybride règle + ML (après réentraînement)

```bash
# Même commande après réentraînement avec cowrie.command.failed
# → base(10) + threat(30) + ml_boost(20) = 60 → ssh_anomaly
# Règle seule = 40 (sous seuil) | ML seul = 30 (sous seuil) | Combiné = 60 ✅
```

---

## 🧠 Machine Learning — Features

### Modèle HTTP (16 dimensions)

| # | Feature | Signal détecté |
|---|---------|----------------|
| 2 | `has_suspicious_kw` | SQLi / XSS |
| 9 | `has_template_syntax` | SSTI / Log4Shell |
| 10 | `has_cmd_injection` | Command Injection |
| 12 | `has_ssrf` | SSRF (169.254.169.254...) |
| 13 | `has_file_inclusion` | LFI / RFI |
| 14 | `has_xxe` | XXE |
| 8 | `ua_entropy` | Scanners HTTP |
| 11 | `query_entropy` | Payloads obfusqués |

### Modèle SSH (12 dimensions)

| # | Feature | Signal détecté |
|---|---------|----------------|
| 7 | `fails_60s` | Bruteforce fenêtre 60s |
| 8 | `has_privesc` | Escalade de privilèges (usermod, sudo...) |
| 9 | `has_persistence` | Persistence (crontab, authorized_keys...) |
| 3 | `has_post_exploitation` | wget, curl, bash, nc |
| 10 | `cmd_entropy` | Commandes obfusquées |

### Seuils de décision

```
ML_CRITICAL_SCORE = -0.62   → bypass cooldown http_anomaly
RBA_ALERT_MED     = 60      → http_anomaly, ssh_anomaly, ssh_bruteforce...
RBA_ALERT_HIGH    = 80      → http_high_risk
COOLDOWN          = 60s     → anti-spam entre alertes identiques
```

---

## 📊 API REST

Base URL : `http://127.0.0.1:8000`

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/health` | Statut du service |
| GET | `/dashboard` | Données agrégées dashboard |
| GET | `/dashboard-data` | KPI + top IPs + catégories |
| GET | `/incidents` | Liste paginée des incidents |
| GET | `/incidents/{id}` | Détail d'un incident |
| GET | `/alerts` | Liste des alertes par sévérité |
| GET | `/alerts/{id}` | Détail d'une alerte avec RBA |
| GET | `/stats` | Statistiques globales |
| GET | `/iocs/{incident_id}` | IOCs associés à un incident |
| GET | `/ml/metrics` | Métriques des modèles ML |

### Exemple d'alerte

```json
{
  "id": 3367,
  "timestamp": "2026-03-26T21:56:33Z",
  "source_ip": "172.20.0.1",
  "alert_type": "http_command_injection",
  "severity": 60,
  "details": {
    "rba": {
      "risk": 60,
      "components": {
        "base": 10,
        "threat": 40,
        "frequency": 0,
        "asset": 0,
        "indicators": 10,
        "ml_boost": 0
      }
    },
    "reason": "rule_match_command_injection"
  }
}
```

---

## 🔒 Sécurité Réseau

Segmentation réseau via Docker Compose — isolation entre zone exposée et zone interne :

```yaml
networks:
  honeypot-net:
    driver: bridge        # zone exposée — cowrie, webhoneypot
  internal-net:
    driver: bridge        # zone interne — collector, api
```

Vérifier l'isolation :

```bash
docker exec cowrie python3 -c "
import urllib.request
try:
    urllib.request.urlopen('http://api:8000/health', timeout=3)
    print('PROBLEME')
except:
    print('OK : isolation confirmee')
"
# → OK : isolation confirmee ✅
```

---

## ⚠️ Limites Identifiées

- Dataset ML synthétique — réentraînement avec vrai trafic recommandé progressivement
- SQLite non adapté à la production → migration PostgreSQL prévue
- Pas d'authentification API ni HTTPS en l'état actuel
- Couverture limitée à HTTP et SSH (FTP, Telnet, RDP non couverts)

---

## 🚀 Améliorations Futures

- [ ] Migration vers PostgreSQL
- [ ] Notifications temps réel (email, Slack, webhook)
- [ ] Intégration SIEM (Elasticsearch / Kibana)
- [ ] Authentification API + HTTPS
- [ ] Extension vers FTP, Telnet, RDP, SMTP
- [ ] Déploiement cloud multi-régions (AWS / GCP / Azure)
- [ ] Intégration Threat Intelligence (MISP, VirusTotal)
- [ ] Ajout de `docker`, `apt-get`, `yum` aux keywords SSH

---

## 🎓 Contexte Académique

Projet de fin de formation réalisé dans le cadre de la filière  
**Cybersécurité & Systèmes d'Informations — Jobintech Promotion 2026**

**Auteure :** Hafsa Daoudim

---

## 📜 Licence
