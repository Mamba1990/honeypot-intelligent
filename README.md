# Honeypot Intelligent (SSH + HTTP) — JobInTech

Projet de cybersécurité : déployer une **honeynet simplifiée** (honeypots SSH/HTTP) capable de **capturer**, **centraliser**, **analyser** et **classifier** des tentatives d’attaques (bruteforce, reconnaissance, injections), puis de les exposer via une **API FastAPI** (et une interface/dashboard à finaliser).

---

## Objectifs

- Attirer des tentatives d’attaque sur **SSH** et **HTTP**
- Enregistrer les événements (logs)
- Centraliser les données dans une base (SQLite)
- Classifier automatiquement les attaques + calculer un score de risque
- Exposer incidents et alertes via une API REST (FastAPI)

---

## Stack / Technologies

- **Docker & Docker Compose** (déploiement automatisé / isolation)
- **Cowrie** (honeypot SSH)
- **Web Honeypot** (HTTP) — application Python
- **Collector** Python (analyse, scoring, règles, centralisation)
- **SQLite** (base de données)
- **FastAPI** (API REST)
- (Option) Dashboard Web (à finaliser)

---

## Architecture (Honeynet simplifiée)



