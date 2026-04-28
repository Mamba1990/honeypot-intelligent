#!/bin/bash
set -e

echo "[INFO] Retraining ML models (offline)..."

PROJECT_ROOT=$(pwd)

HTTP_DATA="$PROJECT_ROOT/ml/data/http_events.jsonl"
SSH_DATA="$PROJECT_ROOT/ml/data/cowrie.json"

echo "[INFO] Exporting logs from containers..."

docker cp webhoneypot:/app/logs/http_events.jsonl "$HTTP_DATA"
docker cp cowrie:/cowrie/var/log/cowrie/cowrie.json "$SSH_DATA"

echo "[INFO] Training models..."

cd ml

echo "[INFO] Training HTTP model..."
python3 train_http.py

echo "[INFO] Training SSH model..."
python3 train_ssh.py

cd ..

echo "[INFO] Restarting collector..."
docker compose restart collector

echo "[INFO] Done."
