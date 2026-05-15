# 🐝 Honeypot Intelligent (SSH + HTTP + Machine Learning)

Projet de cybersécurité visant à concevoir un **honeypot intelligent multi-services** capable de :

- attirer des attaquants
- collecter leurs actions
- analyser les tentatives d'intrusion
- classifier les comportements malveillants
- générer des alertes basées sur le risque

Le système combine **honeypots, analyse par règles, scoring RBA et Machine Learning**.

---

# 📌 Objectifs du projet

Le projet vise à démontrer une architecture complète de détection d'attaques basée sur :

- Honeypots réseau
- Collecte et centralisation de logs
- Analyse comportementale
- Détection hybride **Règles + Machine Learning**
- API de consultation des incidents

---

# 🏗 Architecture du système


---

# ⚙️ Technologies utilisées

## Honeypots

- **Cowrie** → Honeypot SSH
- **Webhoneypot Python** → Simulation service HTTP vulnérable

## Analyse

- Python
- Machine Learning (**Isolation Forest**)
- Risk-Based Alerting (**RBA**)

## Backend

- **FastAPI**

## Base de données

- **SQLite**

## Containerisation

- **Docker**
- **Docker Compose**

---

# 📁 Structure du projet

honeypot-intelligent/
│
├── api/
│ ├── api.py
│ └── Dockerfile
│
├── collector/
│ ├── collector.py
│ └── Dockerfile
│
├── cowrie/
│ ├── cowrie.cfg
│ └── userdb.txt
│
├── webhoneypot/
│ ├── app.py
│ ├── logs/
│ └── Dockerfile
│
├── ml/
│ ├── feature_extraction.py
│ ├── train_http.py
│ ├── train_ssh.py
│ ├── eval_http.py
│ └── eval_ssh.py
│
├── db/
│ └── incidents.db
│
├── docker-compose.yml
│
└── README.md


---

# 🚀 Installation

## 1️⃣ Cloner le projet

```bash
git clone https://github.com/TON_USERNAME/honeypot-intelligent.git

cd honeypot-intelligent

## 1️⃣ Lancer le système

Les services démarrent :


| Service       | Port |
| ------------- | ---- |
| SSH Honeypot  | 2222 |
| HTTP Honeypot | 8081 |
| API           | 8000 |



 # ⚙️ Technologies utilisées
 ## SSH

```bash
 ssh root@localhost -p 2222

Exemples de commandes :

whoami
uname -a
cat /etc/passwd

## HTTP

Tester une injection SQL :

```bash

curl "http://localhost:8081/login?user=%27%20OR%201%3D1"

Tester un XSS:
```bash

curl "http://localhost:8081/search?q=%3Cscript%3Ealert(1)%3C/script%3E"

# API

Accéder aux données :

Incidents
GET /incidents

Exemple :

http://localhost:8000/incidents
Alertes
GET /alerts
http://localhost:8000/alerts
Statistiques
GET /stats
IOCs
GET /iocs/{incident_id}
# Machine Learning

Deux modèles sont entraînés :

HTTP

Détection d'anomalies dans les requêtes HTTP.

Features utilisées :

méthode HTTP

longueur de la requête

présence de signatures malveillantes

accès à des chemins sensibles

longueur du User-Agent

Modèle utilisé :

Isolation Forest
SSH

Analyse des comportements SSH :

Features :

nombre d'échecs d'authentification

type de commande

longueur de commande

fréquence des tentatives

🔎 Analyse des attaques

Le système combine :

1️⃣ Détection par règles

Exemples :

'or 1=1
<script>
union select
../

SSH :

wget
curl
bash
netcat
2️⃣ Risk Based Alerting (RBA)

Score calculé :

risk = base + threat + frequency + asset + indicators + ml_boost
3️⃣ Machine Learning

Détection d'anomalies pour identifier des attaques inconnues.

📦 Docker

Chaque composant fonctionne dans un container :

cowrie
webhoneypot
collector
api

Orchestration :

docker-compose
📈 Exemple d'alerte
{
"id": 45,
"timestamp": "2026-02-16T00:23:26.563351Z",
"source_ip": "172.20.0.1",
"alert_type": "http_high_risk",
"severity": 80,
"details": {
"rba": {
"risk": 80,
"components": {
"base": 10,
"threat": 0,
"frequency": 20,
"asset": 20,
"indicators": 10,
"ml_boost": 20
}
},
"event": {
"path": "/login",
"query": "user=' OR 1=1"
}
}
}
⚠️ Limites du projet

dataset ML limité

SQLite non scalable

pas de queue d'événements

dashboard minimal

peu de tests automatisés

# Améliorations futures

intégration ELK Stack

dashboard graphique

ajout honeypot FTP / SMB

base PostgreSQL

modèles ML plus avancés

🎓 Contexte académique

Projet réalisé dans le cadre d'une formation cybersécurité.

Objectif :

concevoir un honeypot intelligent capable de détecter et analyser les attaques réseau.

📜 Licence

Projet académique / éducatif.

👨‍💻 Auteur

Hafsa Daoudim

Projet Honeypot Intelligent
Cybersécurité & Machine Learning

