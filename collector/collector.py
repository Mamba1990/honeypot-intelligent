"""
collector.py — Honeypot Intelligent
=====================================
Composant central du pipeline de détection hybride.

Responsabilités :
    - Lire en continu les logs des honeypots HTTP et SSH
    - Extraire les features comportementales de chaque événement brut
    - Classifier les événements via des règles expertes déterministes
    - Détecter les anomalies via Isolation Forest (ML non supervisé)
    - Calculer un score de risque RBA combinant les deux couches
    - Persister incidents, IOCs et alertes dans la base SQLite

Architecture :
    webhoneypot (HTTP/Flask) ──┐
                                ├──► collector.py ──► SQLite ──► API FastAPI ──► Dashboard
    cowrie      (SSH)       ──┘

Le Collector est le seul composant connecté aux deux réseaux Docker :
    - honeypot-net  : lit les fichiers de logs produits par les honeypots (lecture seule)
    - internal-net  : écrit les résultats dans la base SQLite partagée

Auteure : Hafsa Daoudim
Projet  : Projet de Fin de Formation — JobInTech 2026
Filière : Cybersécurité & Ingénierie des Systèmes (CIS)
"""

import os
import sys

# feature_extraction.py est copié dans /app par le Dockerfile.
# Les deux entrées sys.path garantissent que le même module de featurization
# est trouvé que le fichier soit intégré à l'image ou monté en volume Docker.
# Cela assure la cohérence entraînement/inférence : le vecteur de 16 features
# (HTTP) et de 12 features (SSH) est identique dans train_*.py et ici.
sys.path.insert(0, "/app")
sys.path.insert(0, "/app/ml")  # fallback si monté via volume Docker

import json
import sqlite3
import time
from datetime import datetime
from collections import defaultdict, deque

import joblib
import numpy as np

# Même featurizer que celui utilisé à l'entraînement — cohérence garantie
from feature_extraction import featurize_http, featurize_ssh_cowrie

# ─────────────────────────────────────────────────────────────────────────────
# Chemins des fichiers
# ─────────────────────────────────────────────────────────────────────────────

DB_PATH    = "/db/incidents.db"
POS_FILE   = "/db/collector_pos.json"   # Offsets de lecture persistés entre redémarrages
HTTP_LOG   = "/web/logs/http_events.jsonl"
COWRIE_LOG = "/cowrie/var/log/cowrie/cowrie.json"

# Fichiers de modèles Isolation Forest produits par train_http.py / train_ssh.py
ML_HTTP_MODEL_PATH = "/app/ml/model_http.joblib"
ML_SSH_MODEL_PATH  = "/app/ml/model_ssh.joblib"

# Singletons de modèles — chargés au premier appel (lazy loading)
_ml_http = None
_ml_ssh  = None

# ─────────────────────────────────────────────────────────────────────────────
# Paramètres de détection et d'alerting
# ─────────────────────────────────────────────────────────────────────────────

# Durée de la fenêtre glissante pour le calcul de fréquence (Rate-Based Scoring)
WINDOW_SECONDS = 60

# Délai minimum entre deux alertes du même type pour la même IP source.
# Évite le spam d'alertes lors d'attaques en rafale ou de scans massifs.
ALERT_COOLDOWN_SECONDS = 60

# Registre en mémoire : (source_ip, alert_type) → timestamp epoch de la dernière alerte
_last_alert_time = {}

# Cap anti-flood : max incidents enregistrés par IP sur 60 secondes.
# Protège SQLite contre les générateurs runaway ou les scanners à très haut débit.
MAX_INCIDENTS_PER_IP_60S = 100
_http_incident_counts = defaultdict(lambda: deque())
_ssh_incident_counts  = defaultdict(lambda: deque())

# ── Seuils RBA ────────────────────────────────────────────────────────────────
# score >= RBA_ALERT_HIGH → alerte haute sévérité (http_high_risk, ssh_post_exploitation…)
# score >= RBA_ALERT_MED  → alerte moyenne sévérité (http_anomaly, ssh_anomaly, ssh_bruteforce…)
RBA_ALERT_HIGH = 80
RBA_ALERT_MED  = 60

# ── Seuil ML critique ─────────────────────────────────────────────────────────
# Calibré sur la distribution réelle des scores du modèle entraîné.
# Règle : correspondre au percentile 1–2% des scores les plus bas (eval_http.py).
#
# Comportement quand ml_score < ML_CRITICAL_SCORE :
#   → Événement marqué comme anomalie ML critique
#   → Bypass du cooldown d'alertes (alerte immédiate même si cooldown actif)
#   → Composante ML_Boost ajoute +20 pts au score RBA
#
# Historique :
#   -0.62  valeur initiale (petit dataset, baseline rapport)
#   -0.67  recalibré après réentraînement (p1=-0.6864, p2=-0.6763, min=-0.6925)
#
# Règle de recalibration : arrondir le percentile p1–p2 à 2 décimales
# et mettre à jour cette constante après chaque cycle de réentraînement.
ML_CRITICAL_SCORE = -0.67

# ─────────────────────────────────────────────────────────────────────────────
# Dictionnaires de règles expertes — HTTP
# ─────────────────────────────────────────────────────────────────────────────

# Marqueurs classiques de SQLi et XSS → catégorie : injection_attempt
HTTP_SUSPICIOUS_KEYWORDS = [
    "or 1=1", "' or 1=1", "union select", "<script",
    "../", "sleep(", "benchmark(", "xp_cmdshell",
]

# Patterns d'injection de commandes OS → catégorie : command_injection
# Couvre opérateurs shell, caractères de concaténation et binaires d'attaque courants
HTTP_CMD_INJECTION_PATTERNS = [
    "$(", "`", ";", "&&", "|", "whoami", "id",
    "uname", "cat ", "wget ", "curl ", "nc ", "bash ",
]

# Chemins ciblés lors de la reconnaissance web → déclenche enum_admin
# et booste la composante asset du score RBA
HTTP_SENSITIVE_PATHS = [
    "/admin", "/.env", "/phpmyadmin", "/wp-login.php",
    "/wp-admin", "/login", "/render", "/actuator",
]

# ─────────────────────────────────────────────────────────────────────────────
# Dictionnaires de règles expertes — SSH (Cowrie)
# ─────────────────────────────────────────────────────────────────────────────

# Commandes indiquant que l'attaquant établit de la persistance ou exfiltre des données
SSH_POST_EXP_KW = [
    "wget", "curl", "chmod", "bash", "python",
    "nc ", "netcat", "perl", "sh "
]

# Commandes indiquant que l'attaquant cartographie l'environnement après connexion
SSH_RECON_KW = [
    "uname", "whoami", "id", "cat /etc/passwd",
    "ip a", "ifconfig", "ps ", "netstat"
]

# Types d'événements Cowrie traités par ce collector.
# Aligné avec le filtre de train_ssh.py pour maintenir la parité entraînement/inférence.
# Les événements hors de cet ensemble (session.closed, direct-tcpip…) sont écartés comme bruit.
SSH_VALID_EVENTS = {
    "cowrie.login.failed",    # Tentative d'authentification échouée
    "cowrie.login.success",   # Connexion réussie — l'attaquant est dans le shell
    "cowrie.command.input",   # Commande exécutée dans l'environnement émulé
    "cowrie.command.failed",  # Commande inconnue de Cowrie — signe d'un vrai attaquant
}


# ─────────────────────────────────────────────────────────────────────────────
# Couche base de données
# ─────────────────────────────────────────────────────────────────────────────

def init_db():
    """
    Initialise SQLite et crée les trois tables principales si elles n'existent pas.

    Schéma :
        incidents  — chaque événement analysé, enrichi du score RBA et du résultat ML
        iocs       — indicateurs de compromission liés à chaque incident
        alerts     — notifications haute/moyenne sévérité générées par le pipeline
    """
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
    """
    Migration de schéma sans rupture : ajoute les colonnes ML si elles sont absentes.

    Permet de mettre à niveau une base créée avant l'introduction du module ML,
    sans supprimer ni recréer les données existantes.
    """
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
    """Retourne True si les deux colonnes ML sont présentes dans la table incidents."""
    cur = con.cursor()
    cur.execute("PRAGMA table_info(incidents)")
    cols = {row[1] for row in cur.fetchall()}
    return ("ml_is_anomaly" in cols) and ("ml_score" in cols)


def insert_incident(
    ts, ip, service, category, score, raw,
    ml_is_anomaly=0, ml_score=0.0
) -> int:
    """
    Persiste un incident enrichi dans SQLite et retourne son identifiant auto-incrémenté.

    Le champ `raw` stocke la ligne de log originale en JSON string.
    Conserver l'événement source non modifié garantit la non-répudiation forensique :
    les analystes peuvent toujours reconstruire exactement ce qui a été capturé,
    indépendamment de toute normalisation appliquée aux colonnes structurées.
    Même pattern que le champ _source d'Elasticsearch et _raw de Splunk.

    Retourne :
        int : identifiant auto-incrémenté de l'incident inséré
    """
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
    """
    Enregistre un indicateur de compromission (IOC) lié à un incident.

    Types d'IOC extraits par service :
        HTTP → path, query (payload brut), user_agent (empreinte scanner)
        SSH  → eventid, username, password, command (commande exécutée)
    """
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
    """
    Normalise le payload details en JSON string valide avant l'insertion.
    Accepte dict, list, JSON string ou texte arbitraire.
    """
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
    """
    Insère une alerte dans SQLite en respectant le cooldown par (IP, type).

    Le cooldown évite les doublons d'alertes lors d'attaques en rafale.
    Il est court-circuité uniquement quand l'appelant a vérifié que
    ml_score < ML_CRITICAL_SCORE (anomalie critique confirmée par Isolation Forest).
    """
    now = time.time()
    key = (ip, alert_type)
    last = _last_alert_time.get(key, 0)
    if now - last < ALERT_COOLDOWN_SECONDS:
        return  # Cooldown toujours actif — alerte supprimée
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
    """
    Retourne True si le cooldown est expiré pour ce couple (IP, type d'alerte),
    indiquant qu'une nouvelle alerte peut être insérée sans spam.
    """
    if not ip:
        return False
    now = time.time()
    key = (ip, alert_type)
    last = _last_alert_time.get(key, 0)
    return (now - last) >= ALERT_COOLDOWN_SECONDS


def clamp_0_100(x: float) -> int:
    """Borne un score RBA flottant à l'intervalle entier [0, 100]."""
    return int(max(0, min(100, round(x))))


def short(s: str, n: int = 160) -> str:
    """Tronque une chaîne à n caractères maximum pour éviter les valeurs trop longues en base."""
    s = (s or "").replace("\n", " ").strip()
    return s if len(s) <= n else s[:n] + "…"


def is_flood_ip(ip: str, counts: dict, now: float) -> bool:
    """
    Détecte si une IP source dépasse MAX_INCIDENTS_PER_IP_60S sur les 60 dernières secondes.

    Implémenté comme une deque à fenêtre glissante amortie en O(1).
    Retourne True si l'IP doit être ignorée pour cette itération (protection flood).
    """
    if not ip:
        return False
    dq = counts[ip]
    dq.append(now)
    while dq and now - dq[0] > WINDOW_SECONDS:
        dq.popleft()
    return len(dq) > MAX_INCIDENTS_PER_IP_60S


# ─────────────────────────────────────────────────────────────────────────────
# Lecteurs de logs non bloquants (tail)
# ─────────────────────────────────────────────────────────────────────────────

def tail_jsonl(filepath, last_pos):
    """
    Lit toutes les nouvelles lignes ajoutées à un fichier JSONL depuis le dernier appel.
    Utilisé pour consommer http_events.jsonl produit par le webhoneypot Flask.

    Args :
        filepath : chemin absolu vers le fichier JSONL
        last_pos : offset en octets où la lecture précédente s'est arrêtée

    Retourne :
        new_pos (int)  : nouvel offset après cette lecture
        events  (list) : liste des dicts JSON parsés avec succès
    """
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
    """
    Lit toutes les nouvelles lignes ajoutées à cowrie.json depuis le dernier appel.
    Logique identique à tail_jsonl — séparée pour la lisibilité et les extensions futures.

    Args :
        filepath : chemin absolu vers cowrie.json
        last_pos : offset en octets où la lecture précédente s'est arrêtée

    Retourne :
        new_pos (int)  : nouvel offset
        events  (list) : liste des dicts d'événements Cowrie parsés
    """
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


# ─────────────────────────────────────────────────────────────────────────────
# Isolation Forest — chargement des modèles et inférence
# ─────────────────────────────────────────────────────────────────────────────

def ml_http_enabled() -> bool:
    """Retourne True si un fichier de modèle HTTP entraîné est présent sur le disque."""
    return os.path.exists(ML_HTTP_MODEL_PATH)


def ml_ssh_enabled() -> bool:
    """Retourne True si un fichier de modèle SSH entraîné est présent sur le disque."""
    return os.path.exists(ML_SSH_MODEL_PATH)


def load_http_model():
    """
    Charge le modèle HTTP Isolation Forest en mémoire au premier appel (lazy loading).
    Les appels suivants retournent l'instance mise en cache pour éviter
    les lectures disque répétées dans la boucle principale de traitement.
    """
    global _ml_http
    if _ml_http is None and ml_http_enabled():
        _ml_http = joblib.load(ML_HTTP_MODEL_PATH)
    return _ml_http


def load_ssh_model():
    """
    Charge le modèle SSH Isolation Forest en mémoire au premier appel (lazy loading).
    Même stratégie de cache que load_http_model().
    """
    global _ml_ssh
    if _ml_ssh is None and ml_ssh_enabled():
        _ml_ssh = joblib.load(ML_SSH_MODEL_PATH)
    return _ml_ssh


def ml_predict_http(evt: dict) -> tuple[int, float]:
    """
    Exécute l'inférence Isolation Forest sur un événement HTTP.

    Appelle featurize_http() pour construire le vecteur de 16 features
    identique à celui utilisé à l'entraînement — aucune dérive de features.

    Retourne :
        ml_is_anomaly (int)   : 1 si le modèle signale une anomalie, 0 sinon
        ml_score      (float) : score brut d'anomalie ; proche de -1 = très anormal
    """
    if not ml_http_enabled():
        return 0, 0.0
    try:
        model = load_http_model()
        X = np.array([featurize_http(evt)], dtype=float)
        score = float(model.score_samples(X)[0])
        pred  = int(model.predict(X)[0])
        return (1 if pred == -1 else 0), score
    except Exception:
        return 0, 0.0


def ml_predict_ssh(ev: dict, fails_60s: int) -> tuple[int, float]:
    """
    Exécute l'inférence Isolation Forest sur un événement SSH Cowrie.

    Appelle featurize_ssh_cowrie() pour construire le vecteur de 12 features
    identique à celui utilisé à l'entraînement, incluant la feature de fréquence fails_60s.

    Args :
        ev        : dict d'événement Cowrie brut
        fails_60s : nombre de connexions échouées de cette IP sur les 60 dernières secondes

    Retourne :
        ml_is_anomaly (int)   : 1 si anomalie détectée, 0 sinon
        ml_score      (float) : score brut Isolation Forest
    """
    if not ml_ssh_enabled():
        return 0, 0.0
    try:
        model = load_ssh_model()
        X = np.array([featurize_ssh_cowrie(ev, fails_60s=fails_60s)], dtype=float)
        score = float(model.score_samples(X)[0])
        pred  = int(model.predict(X)[0])
        return (1 if pred == -1 else 0), score
    except Exception:
        return 0, 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Classification par règles expertes
# ─────────────────────────────────────────────────────────────────────────────

def classify_http_label(event: dict) -> str:
    """
    Classifie un événement HTTP en catégorie via des règles expertes déterministes.

    Ordre de priorité (première correspondance gagne) :
        1. enum_admin        — chemin sensible accédé (/admin, /.env, /wp-admin…)
        2. command_injection — patterns shell/OS détectés dans query ou body
        3. injection_attempt — SQLi, XSS ou traversal de chemin classiques
        4. upload_probe      — endpoint d'upload de fichier ciblé
        5. http_activity     — trafic HTTP bénin ou non reconnu

    Retourne :
        str : label de catégorie utilisé pour l'incident et le scoring RBA
    """
    path     = event.get("path", "")
    q        = (event.get("query") or "").lower()
    body     = (event.get("body")  or "").lower()
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
    """
    Classifie un événement SSH Cowrie en catégorie via des règles expertes déterministes.

    Mapping :
        cowrie.login.failed   → ssh_login_failed
        cowrie.login.success  → ssh_login_success
        cowrie.command.input  → post_exploitation | recon | ssh_command
        cowrie.command.failed → ssh_command_failed (commande inconnue de l'émulateur)

    Retourne :
        str : label de catégorie pour l'incident et le scoring RBA
    """
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
        # cowrie.command.failed = Cowrie n'a pas d'émulation pour cette commande
        # — typique des vrais attaquants utilisant des outils non standard
        if etype == "cowrie.command.failed":
            return "ssh_command_failed"
        return "ssh_command"
    return "ssh_activity"


# ─────────────────────────────────────────────────────────────────────────────
# Moteur de scoring RBA (Risk-Based Alerting)
# ─────────────────────────────────────────────────────────────────────────────

def compute_rba_http(
    event: dict, req_60s: int, ml_is_anomaly: int
) -> tuple[int, dict, list]:
    """
    Calcule un score de risque RBA composite pour un événement HTTP.

    Formule :
        RBA = base + threat + frequency + asset + indicators + ml_boost

    Détail des composantes :
        base       (10 pts)    Score plancher appliqué à chaque événement.
        threat     (0–40 pts)  Sévérité de l'attaque selon les patterns matchés.
        frequency  (0–20 pts)  Taux de requêtes de cette IP sur les 60 dernières secondes.
        asset      (0–35 pts)  Criticité du chemin accédé (maximum pour /admin).
        indicators (0–15 pts)  Signaux secondaires : méthode POST, query longue, UA long.
        ml_boost   (0|20 pts)  Bonus si Isolation Forest signale une anomalie.

    Retourne :
        risk       (int)  : score RBA final, borné à [0, 100]
        components (dict) : détail de chaque composante pour transparence et audit
        indicators (list) : labels lisibles de chaque signal déclenché
    """
    method = (event.get("method") or "").upper()
    path   = (event.get("path")   or "")
    query  = (event.get("query")  or "")
    body   = (event.get("body")   or "")
    ua     = (event.get("user_agent") or "")

    qlow     = query.lower()
    blow     = body.lower()
    combined = qlow + " " + blow

    indicators = []
    base = 10

    # ── Asset : criticité du chemin accédé ───────────────────────────────────
    asset = 0
    if any(path.startswith(p) for p in HTTP_SENSITIVE_PATHS):
        asset = 20
        indicators.append("sensitive_path")
    if path == "/upload":
        asset = max(asset, 15)
        indicators.append("upload_probe")
    if path.startswith("/admin"):
        asset = max(asset, 35)   # Valeur asset maximale — accès direct admin
        indicators.append("enum_admin")
    if path.startswith("/api/"):
        asset = max(asset, 20)
        indicators.append("api_endpoint")

    # ── Threat : type d'attaque détecté par les règles expertes ──────────────
    threat = 0
    if any(k in combined for k in HTTP_CMD_INJECTION_PATTERNS):
        threat += 40
        indicators.append("command_injection_pattern")
    if any(k in combined for k in HTTP_SUSPICIOUS_KEYWORDS):
        threat += 30
        indicators.append("suspicious_keywords")

    # ── Indicateurs comportementaux ───────────────────────────────────────────
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

    # ── Fréquence : taux de requêtes sur les 60 dernières secondes ───────────
    freq = 0
    if req_60s >= 20:
        freq = 20
        indicators.append("high_rate_20per60s")
    elif req_60s >= 10:
        freq = 10
        indicators.append("rate_10per60s")

    # ── ML boost : +20 si Isolation Forest confirme une anomalie ─────────────
    ml_boost = 0
    if ml_is_anomaly:
        ml_boost = 20
        indicators.append("ml_anomaly")

    risk = clamp_0_100(base + threat + freq + asset + ind + ml_boost)
    components = {
        "base": base, "threat": threat, "frequency": freq,
        "asset": asset, "indicators": ind,
        "ml_boost": ml_boost, "req_60s": req_60s
    }
    return risk, components, indicators


def compute_rba_ssh(
    ev: dict, fails_60s: int, ml_is_anomaly: int
) -> tuple[int, dict, list]:
    """
    Calcule un score de risque RBA composite pour un événement SSH Cowrie.

    Formule :
        RBA = base + threat + frequency + ml_boost

    Détail des composantes SSH :
        base       (10 pts)    Score plancher pour chaque événement SSH.
        threat     (5–50 pts)  Sévérité selon le type d'événement et le contenu de la commande.
        frequency  (0–40 pts)  Nombre d'échecs de connexion de cette IP sur 60 secondes.
        ml_boost   (0|20 pts)  Bonus si Isolation Forest signale une anomalie.

    Retourne :
        risk       (int)  : score RBA final, borné à [0, 100]
        components (dict) : détail de chaque composante
        indicators (list) : labels lisibles de chaque signal déclenché
    """
    etype = ev.get("eventid", "")
    cmd   = (ev.get("input") or "").lower()

    indicators = []
    base = 10

    # ── Threat : sévérité selon le type d'événement et la commande ───────────
    threat = 0
    if etype == "cowrie.command.input":
        if any(k in cmd for k in SSH_POST_EXP_KW):
            threat = 50                       # Post-exploitation active en cours
            indicators.append("post_exploitation_cmd")
        elif any(k in cmd for k in SSH_RECON_KW):
            threat = 30                       # Attaquant cartographiant l'environnement
            indicators.append("recon_cmd")
        else:
            threat = 15                       # Commande non classifiée
            indicators.append("command_input")
    elif etype == "cowrie.login.failed":
        threat = 10
        indicators.append("login_failed")
    elif etype == "cowrie.login.success":
        threat = 20                           # L'attaquant est authentifié
        indicators.append("login_success")
    elif etype == "cowrie.command.failed":
        # Commande non reconnue par l'émulateur Cowrie — typique d'un vrai attaquant
        # utilisant des outils ou payloads que Cowrie ne peut pas simuler
        if any(k in cmd for k in SSH_POST_EXP_KW):
            threat = 40
            indicators.append("command_failed_post_exploitation")
        elif any(k in cmd for k in SSH_RECON_KW):
            threat = 25
            indicators.append("command_failed_recon")
        else:
            # base=10 + threat=30 = 40 → atteint le seuil d'alerte avec ml_boost
            threat = 30
            indicators.append("command_failed_unknown")
    else:
        threat = 5
        indicators.append("ssh_activity")

    # ── Fréquence : détection de bruteforce par taux d'échecs ────────────────
    freq = 0
    if fails_60s >= 10:
        freq = 40
        indicators.append("bruteforce_10fails_60s")
    elif fails_60s >= 5:
        freq = 30
        indicators.append("bruteforce_5fails_60s")

    # ── ML boost : +20 si Isolation Forest confirme une anomalie ─────────────
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
    """Convertit un score RBA en sévérité d'alerte (mapping 1:1 pour l'instant)."""
    return int(risk)


# ─────────────────────────────────────────────────────────────────────────────
# Persistance des positions de lecture
# ─────────────────────────────────────────────────────────────────────────────

def load_positions() -> dict:
    """
    Charge les offsets de lecture sauvegardés depuis POS_FILE et les valide.

    Détection de rotation des logs :
        Si un offset sauvegardé dépasse la taille actuelle du fichier,
        le log a été roté ou tronqué (ex : redémarrage Docker, logrotate).
        L'offset concerné est automatiquement réinitialisé à 0 pour
        éviter de manquer de nouveaux événements.

    Retourne :
        dict avec les clés 'http' et 'ssh' contenant les derniers offsets valides
    """
    try:
        with open(POS_FILE, "r") as f:
            pos = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        print("[collector] aucune position sauvegardée — démarrage à l'offset 0")
        return {"http": 0, "ssh": 0}

    http_size = get_file_size(HTTP_LOG)
    ssh_size  = get_file_size(COWRIE_LOG)
    http_pos  = pos.get("http", 0)
    ssh_pos   = pos.get("ssh",  0)

    # Rotation détectée : l'offset sauvegardé dépasse la fin du fichier actuel
    if http_pos > http_size:
        print(f"[collector] ⚠️  rotation HTTP détectée (pos={http_pos} > size={http_size}) → reset à 0")
        http_pos = 0
    if ssh_pos > ssh_size:
        print(f"[collector] ⚠️  rotation SSH détectée (pos={ssh_pos} > size={ssh_size}) → reset à 0")
        ssh_pos = 0

    print(f"[collector] positions chargées : http={http_pos}  ssh={ssh_pos}")
    return {"http": http_pos, "ssh": ssh_pos}


def save_positions(http_pos: int, ssh_pos: int):
    """
    Persiste les offsets de lecture courants dans POS_FILE après chaque itération.
    Garantit qu'un redémarrage du conteneur reprend exactement là où le traitement s'est arrêté.
    """
    try:
        with open(POS_FILE, "w") as f:
            json.dump({"http": http_pos, "ssh": ssh_pos}, f)
    except Exception as e:
        print(f"[collector] échec de la sauvegarde des positions : {e}")


def get_file_size(path: str) -> int:
    """Retourne la taille du fichier en octets, ou 0 si le fichier n'existe pas."""
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# Boucle de traitement principale
# ─────────────────────────────────────────────────────────────────────────────

def main():
    """
    Point d'entrée — démarre la boucle infinie de lecture des logs.

    Pipeline de traitement par événement :
        1. tail_jsonl / tail_cowrie_json  →  lire les nouveaux événements dans les logs
        2. classify_http/ssh_label        →  règles expertes  →  label de catégorie
        3. ml_predict_http/ssh            →  Isolation Forest  →  flag anomalie + score
        4. compute_rba_http/ssh           →  score RBA hybride (règles × ML combinés)
        5. insert_incident                →  persister l'événement enrichi dans SQLite
        6. insert_ioc                     →  extraire et stocker les artefacts IOC
        7. insert_alert                   →  déclencher les alertes si seuils dépassés
        8. save_positions                 →  sauvegarder les offsets pour redémarrage sûr
    """
    init_db()

    print("[collector] démarré")
    print("[collector] DB           :", DB_PATH)
    print("[collector] log HTTP     :", HTTP_LOG)
    print("[collector] log SSH      :", COWRIE_LOG)
    print("[collector] ML HTTP      :", ml_http_enabled(), "|", ML_HTTP_MODEL_PATH)
    print("[collector] ML SSH       :", ml_ssh_enabled(),  "|", ML_SSH_MODEL_PATH)
    print(f"[collector] cap flood    : max {MAX_INCIDENTS_PER_IP_60S} incidents / IP / {WINDOW_SECONDS}s")
    print(f"[collector] seuil ML     : ML_CRITICAL_SCORE = {ML_CRITICAL_SCORE}")

    _pos = load_positions()

    # Premier démarrage (POS_FILE absent) : sauter à la FIN de chaque fichier
    # pour ne pas rejouer les événements historiques déjà traités avant ce démarrage.
    if _pos["http"] == 0 and not os.path.exists(POS_FILE):
        _pos["http"] = get_file_size(HTTP_LOG)
        print(f"[collector] premier démarrage — offset HTTP initialisé à {_pos['http']} (fin du fichier)")
    if _pos["ssh"] == 0 and not os.path.exists(POS_FILE):
        _pos["ssh"] = get_file_size(COWRIE_LOG)
        print(f"[collector] premier démarrage — offset SSH initialisé à {_pos['ssh']} (fin du fichier)")

    http_pos = _pos["http"]
    ssh_pos  = _pos["ssh"]

    # Deques à fenêtre glissante pour le suivi de fréquence par IP
    http_hits = defaultdict(lambda: deque())  # source_ip → timestamps requêtes HTTP (60s)
    ssh_fails = defaultdict(lambda: deque())  # source_ip → timestamps échecs SSH (60s)

    while True:
        now = time.time()

        # ════════════════════════════════════════════════════
        # Traitement des événements HTTP
        # ════════════════════════════════════════════════════
        http_pos, http_events = tail_jsonl(HTTP_LOG, http_pos)

        for ev in http_events:
            ts = ev.get("timestamp") or (datetime.utcnow().isoformat() + "Z")
            ip = ev.get("source_ip") or ""

            # Mise à jour du compteur de fréquence par IP (fenêtre glissante 60s)
            req_60s = 0
            if ip:
                dq = http_hits[ip]
                dq.append(now)
                while dq and now - dq[0] > WINDOW_SECONDS:
                    dq.popleft()
                req_60s = len(dq)

            # Ignorer l'événement si cette IP dépasse le cap anti-flood
            if is_flood_ip(ip, _http_incident_counts, now):
                continue

            # Étape 1 — Classification par règles expertes
            label = classify_http_label(ev)

            # Étape 2 — Détection d'anomalie par Isolation Forest
            ml_is_anomaly, ml_score = ml_predict_http(ev)

            # Étape 3 — Scoring RBA hybride (règles + ML)
            risk, comp, indicators = compute_rba_http(ev, req_60s, ml_is_anomaly)

            # Promouvoir la catégorie si le ML détecte ce que les règles n'ont pas classifié
            category = label
            if ml_is_anomaly and category == "http_activity":
                category = "http_anomaly"

            # Étape 4 — Persistance de l'incident et des IOCs extraits
            incident_id = insert_incident(
                ts, ip, "http", category, risk, json.dumps(ev),
                ml_is_anomaly=ml_is_anomaly, ml_score=ml_score
            )
            insert_ioc(incident_id, "path",       ev.get("path"))
            insert_ioc(incident_id, "query",      ev.get("query"))
            insert_ioc(incident_id, "user_agent", ev.get("user_agent"))

            # Étape 5 — Génération des alertes

            # Alerte par règle : patterns d'injection de commandes OS détectés
            if label == "command_injection" and should_alert(ip, "http_command_injection"):
                insert_alert(ts, ip, "http_command_injection", severity_from_risk(risk), {
                    "rba": {"risk": risk, "components": comp, "indicators": indicators},
                    "event": {
                        "path":       ev.get("path", ""),
                        "query":      short(ev.get("query", ""), 180),
                        "method":     ev.get("method", ""),
                        "user_agent": short(ev.get("user_agent", ""), 120),
                    },
                    "category": label, "reason": "rule_match_command_injection"
                })

            # Alerte par règle : SQLi, XSS ou traversal de chemin
            if label == "injection_attempt" and should_alert(ip, "http_injection"):
                insert_alert(ts, ip, "http_injection", severity_from_risk(risk), {
                    "rba": {"risk": risk, "components": comp, "indicators": indicators},
                    "event": {
                        "path":       ev.get("path", ""),
                        "query":      short(ev.get("query", ""), 180),
                        "method":     ev.get("method", ""),
                        "user_agent": short(ev.get("user_agent", ""), 120),
                    },
                    "category": label, "reason": "rule_match_injection"
                })

            # Bypass du cooldown pour les anomalies ML critiques confirmées.
            # Les attaques zero-day ou multi-vecteurs (SSTI, Log4Shell, XXE+SSRF…)
            # ne doivent jamais être silenciées par le cooldown standard de 60 secondes.
            is_critical_ml = ml_is_anomaly and ml_score < ML_CRITICAL_SCORE

            # Alerte ML : anomalie Isolation Forest au-dessus du seuil moyen
            if ml_is_anomaly and (risk >= RBA_ALERT_MED or ml_score < -0.60):
                if is_critical_ml or should_alert(ip, "http_anomaly"):
                    insert_alert(ts, ip, "http_anomaly", severity_from_risk(risk), {
                        "rba": {"risk": risk, "components": comp, "indicators": indicators},
                        "ml":  {"is_anomaly": int(ml_is_anomaly), "ml_score": ml_score},
                        "event": {
                            "path":       ev.get("path", ""),
                            "query":      short(ev.get("query", ""), 180),
                            "method":     ev.get("method", ""),
                            "user_agent": short(ev.get("user_agent", ""), 120),
                        },
                        "category": label,
                        "note": "http_anomaly is generic; inspect details for contributing factors."
                    })

            # Alerte haute sévérité : score RBA atteint ou dépasse RBA_ALERT_HIGH
            if risk >= RBA_ALERT_HIGH and should_alert(ip, "http_high_risk"):
                insert_alert(ts, ip, "http_high_risk", severity_from_risk(risk), {
                    "rba":      {"risk": risk, "components": comp, "indicators": indicators},
                    "event":    {"path": ev.get("path", ""), "query": short(ev.get("query", ""), 180)},
                    "category": label
                })

        # ════════════════════════════════════════════════════
        # Traitement des événements SSH (Cowrie)
        # ════════════════════════════════════════════════════
        ssh_pos, ssh_events = tail_cowrie_json(COWRIE_LOG, ssh_pos)

        for ev in ssh_events:
            ts    = ev.get("timestamp") or (datetime.utcnow().isoformat() + "Z")
            ip    = ev.get("src_ip") or ev.get("srcip") or ev.get("src") or ""
            etype = ev.get("eventid", "")

            # Écarter les événements Cowrie hors de l'ensemble valide (réduction du bruit)
            if etype not in SSH_VALID_EVENTS:
                continue

            # Suivi des échecs de connexion par IP pour le scoring de bruteforce (60s)
            fails_60s = 0
            if ip:
                dq = ssh_fails[ip]
                if etype == "cowrie.login.failed":
                    dq.append(now)
                while dq and now - dq[0] > WINDOW_SECONDS:
                    dq.popleft()
                fails_60s = len(dq)

            # Ignorer l'événement si cette IP dépasse le cap anti-flood
            if is_flood_ip(ip, _ssh_incident_counts, now):
                continue

            # Étape 1 — Classification par règles expertes
            label = classify_ssh_label(ev)

            # Étape 2 — Détection d'anomalie par Isolation Forest
            ml_is_anomaly, ml_score = ml_predict_ssh(ev, fails_60s)

            # Étape 3 — Scoring RBA hybride
            risk, comp, indicators = compute_rba_ssh(ev, fails_60s, ml_is_anomaly)

            # Promouvoir la catégorie si le ML détecte ce que les règles n'ont pas flagué
            category = label
            if ml_is_anomaly and category in ("ssh_activity", "ssh_command"):
                category = "ssh_anomaly"

            # Étape 4 — Persistance de l'incident et des IOCs extraits
            incident_id = insert_incident(
                ts, ip, "ssh", category, risk, json.dumps(ev),
                ml_is_anomaly=ml_is_anomaly, ml_score=ml_score
            )
            insert_ioc(incident_id, "eventid",  ev.get("eventid"))
            insert_ioc(incident_id, "username", ev.get("username"))
            insert_ioc(incident_id, "password", ev.get("password"))
            insert_ioc(incident_id, "command",  ev.get("input"))

            # Étape 5 — Génération des alertes

            # Alerte fréquentielle : bruteforce SSH détecté
            if fails_60s >= 5 and should_alert(ip, "ssh_bruteforce"):
                insert_alert(ts, ip, "ssh_bruteforce", severity_from_risk(risk), {
                    "rba":        {"risk": risk, "components": comp, "indicators": indicators},
                    "failed_60s": fails_60s,
                    "reason":     "frequency_failed_logins"
                })

            # Alerte par règle : commande de post-exploitation détectée
            if label == "post_exploitation" and should_alert(ip, "ssh_post_exploitation"):
                insert_alert(ts, ip, "ssh_post_exploitation", severity_from_risk(risk), {
                    "rba":      {"risk": risk, "components": comp, "indicators": indicators},
                    "command":  short(ev.get("input", ""), 180),
                    "username": ev.get("username", ""),
                    "eventid":  ev.get("eventid", ""),
                    "reason":   "rule_match_post_exploitation"
                })

            # Alerte ML : anomalie SSH Isolation Forest au-dessus du seuil moyen
            if ml_is_anomaly and risk >= RBA_ALERT_MED and should_alert(ip, "ssh_anomaly"):
                insert_alert(ts, ip, "ssh_anomaly", severity_from_risk(risk), {
                    "rba": {"risk": risk, "components": comp, "indicators": indicators},
                    "ml":  {"is_anomaly": int(ml_is_anomaly), "ml_score": ml_score},
                    "event": {
                        "eventid":    ev.get("eventid", ""),
                        "command":    short(ev.get("input", ""), 180),
                        "username":   ev.get("username", ""),
                        "failed_60s": fails_60s
                    },
                    "category": label
                })

        # Sauvegarde des offsets à la fin de chaque itération —
        # aucun événement perdu si le conteneur est redémarré à tout moment
        save_positions(http_pos, ssh_pos)
        time.sleep(2)


if __name__ == "__main__":
    main()