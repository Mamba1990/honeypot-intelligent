# ml/eval_ssh.py
import json
import os
import numpy as np
import joblib
import matplotlib.pyplot as plt

from feature_extraction import featurize_ssh_cowrie

DATA_PATH = os.path.join("data", "cowrie.json")
MODEL_PATH = "model_ssh.joblib"


def load_X():
    """
    Charge cowrie.json (jsonl) et produit:
      - X : matrice features
      - raw : liste des events bruts
    """
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Fichier introuvable: {DATA_PATH}")

    X, raw = [], []
    with open(DATA_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue

            # offline: fails_60s inconnu -> 0
            feats = featurize_ssh_cowrie(ev, fails_60s=0)
            X.append(feats)
            raw.append(ev)

    return np.array(X, dtype=float), raw


def describe_scores(scores: np.ndarray, name: str = "scores"):
    print(f"[EVAL] {name}: mean={scores.mean():.4f} min={scores.min():.4f} max={scores.max():.4f}")
    for q in [1, 5, 10, 25, 50, 75, 90, 95, 99]:
        print(f"[EVAL] {name} p{q:02d} = {np.percentile(scores, q):.4f}")


def pretty_event(ev: dict) -> str:
    """
    Résumé lisible d'un event Cowrie (best effort).
    """
    eventid = ev.get("eventid", "")
    ip = ev.get("src_ip") or ev.get("srcip") or ev.get("src") or ""
    user = ev.get("username", "")
    cmd = (ev.get("input") or "").replace("\n", " ").strip()

    parts = [f"eventid={eventid}"]
    if ip:
        parts.append(f"ip={ip}")
    if user:
        parts.append(f"user={user}")
    if cmd:
        # limite longueur
        if len(cmd) > 160:
            cmd = cmd[:160] + "…"
        parts.append(f"cmd={cmd}")
    return " | ".join(parts)


def main():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"{MODEL_PATH} introuvable. Lance d'abord: python3 train_ssh.py")

    X, raw = load_X()
    model = joblib.load(MODEL_PATH)

    scores = model.score_samples(X)
    preds = model.predict(X)  # -1 anomalie, 1 normal

    anomaly_ratio = float((preds == -1).sum()) / float(len(preds))

    print("=== SSH ML METRICS (IsolationForest) ===")
    print("samples:", len(X))
    print("anomaly_ratio:", round(anomaly_ratio, 4))
    describe_scores(scores, "score_samples")

    # Top 10 anomalies = scores les plus bas
    idx_sorted = np.argsort(scores)  # ascending
    topk = 10 if len(idx_sorted) >= 10 else len(idx_sorted)

    print(f"\nTop {topk} anomalies (most suspicious):")
    for i in idx_sorted[:topk]:
        print("-", pretty_event(raw[i]), "| score=", float(scores[i]))

    # Histogram plot
    plt.figure()
    plt.hist(scores, bins=50)
    plt.title("SSH score_samples distribution (IsolationForest)")
    plt.xlabel("score_samples")
    plt.ylabel("count")
    plt.tight_layout()
    out = "ssh_scores_hist.png"
    plt.savefig(out)
    print(f"\nSaved graph -> {out}")


if __name__ == "__main__":
    main()