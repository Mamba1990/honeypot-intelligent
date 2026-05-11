# ml/eval_ssh.py
import json
import os
import numpy as np
import joblib
import matplotlib.pyplot as plt

from feature_extraction import featurize_ssh_cowrie

DATA_PATH  = os.path.join("data", "cowrie.json")
MODEL_PATH = "model_ssh.joblib"
ML_METRICS_PATH = "/db/ml_metrics.json"

# ✅ Même filtre que train_ssh.py — sans déduplication
VALID_EVENTS = {
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input"
}
MIN_CMD_LENGTH = 2


def is_valid_ssh_event(ev: dict) -> bool:
    eventid = ev.get("eventid")
    if eventid not in VALID_EVENTS:
        return False
    if eventid == "cowrie.command.input":
        cmd = (ev.get("input") or "").strip()
        if len(cmd) < MIN_CMD_LENGTH:
            return False
    return True


def load_X():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Fichier introuvable: {DATA_PATH}")

    X, raw = [], []
    kept = skipped = 0

    with open(DATA_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                skipped += 1
                continue

            # ✅ Filtre bruit — même périmètre que train_ssh
            if not is_valid_ssh_event(ev):
                skipped += 1
                continue

            try:
                feats = featurize_ssh_cowrie(ev, fails_60s=0)
                if not np.all(np.isfinite(feats)):
                    skipped += 1
                    continue
                X.append(feats)
                raw.append(ev)
                kept += 1
            except Exception:
                skipped += 1
                continue

    print(f"[eval_ssh] events kept={kept} skipped={skipped}")
    return np.array(X, dtype=float), raw


def describe_scores(scores: np.ndarray, name: str = "scores"):
    print(f"[EVAL] {name}: mean={scores.mean():.4f} min={scores.min():.4f} max={scores.max():.4f}")
    for q in [1, 5, 10, 25, 50, 75, 90, 95, 99]:
        print(f"[EVAL] {name} p{q:02d} = {np.percentile(scores, q):.4f}")


def pretty_event(ev: dict) -> str:
    eventid = ev.get("eventid", "")
    ip      = ev.get("src_ip") or ev.get("srcip") or ev.get("src") or ""
    user    = ev.get("username", "")
    cmd     = (ev.get("input") or "").replace("\n", " ").strip()
    parts   = [f"eventid={eventid}"]
    if ip:   parts.append(f"ip={ip}")
    if user: parts.append(f"user={user}")
    if cmd:  parts.append(f"cmd={cmd[:160] + '…' if len(cmd) > 160 else cmd}")
    return " | ".join(parts)


def save_metrics(X, scores, preds, anomaly_ratio):
    """Sauvegarde les métriques SSH dans /db/ml_metrics.json pour l'API."""
    metrics_ssh = {
        "total": int(len(X)),
        "anomalies": int((preds == -1).sum()),
        "normaux": int((preds == 1).sum()),
        "anomaly_ratio": round(float(anomaly_ratio), 4),
        "score_mean": round(float(scores.mean()), 4),
        "score_min":  round(float(scores.min()),  4),
        "score_max":  round(float(scores.max()),  4),
        "percentile_1":  round(float(np.percentile(scores, 1)),  4),
        "percentile_5":  round(float(np.percentile(scores, 5)),  4),
        "percentile_10": round(float(np.percentile(scores, 10)), 4),
        "percentile_50": round(float(np.percentile(scores, 50)), 4),
        "percentile_95": round(float(np.percentile(scores, 95)), 4),
        "ml_critical_score": -0.62,
    }

    # Lire l'existant (HTTP peut déjà avoir été calculé)
    existing = {}
    try:
        with open(ML_METRICS_PATH, "r") as f:
            existing = json.load(f)
    except Exception:
        pass

    existing["ssh"] = metrics_ssh

    os.makedirs(os.path.dirname(ML_METRICS_PATH), exist_ok=True)
    with open(ML_METRICS_PATH, "w") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False)

    print(f"\n✅ ml_metrics.json mis à jour (ssh) → {ML_METRICS_PATH}")


def main():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"{MODEL_PATH} introuvable. Lance: python3 train_ssh.py")

    X, raw = load_X()

    if len(X) == 0:
        print("[eval_ssh] Aucun event apres filtrage.")
        return

    model = joblib.load(MODEL_PATH)

    # ✅ Verification coherence dimensions
    expected = model.n_features_in_
    if X.shape[1] != expected:
        raise ValueError(
            f"Incompatibilite : X a {X.shape[1]} dims "
            f"mais le modele attend {expected} dims. "
            f"Reentraine avec train_ssh.py."
        )

    scores = model.score_samples(X)
    preds  = model.predict(X)   # -1 anomalie

    anomaly_ratio = float((preds == -1).sum()) / float(len(preds))

    print("=== SSH ML METRICS (IsolationForest) ===")
    print(f"samples       : {len(X)}")
    print(f"features      : {X.shape[1]}")
    print(f"anomaly_ratio : {round(anomaly_ratio, 4)}")
    describe_scores(scores, "score_samples")

    # Top 10 anomalies
    idx_sorted = np.argsort(scores)
    topk = min(10, len(idx_sorted))
    print(f"\nTop {topk} anomalies (most suspicious):")
    for i in idx_sorted[:topk]:
        print(f"  score={scores[i]:.4f} | {pretty_event(raw[i])}")

    # ✅ Histogramme avec 2 couleurs
    plt.figure(figsize=(10, 5))
    plt.hist(scores[preds == 1],  bins=40, alpha=0.7, color="#2980b9", label="Normal")
    plt.hist(scores[preds == -1], bins=40, alpha=0.7, color="#e74c3c", label="Anomalie")
    threshold = np.percentile(scores, 5)
    plt.axvline(threshold, color="orange", linestyle="--", linewidth=1.5,
                label=f"p5 = {threshold:.3f}")
    plt.title("SSH score_samples distribution (IsolationForest)")
    plt.xlabel("score_samples")
    plt.ylabel("count")
    plt.legend()
    plt.tight_layout()
    plt.savefig("ssh_scores_hist.png")
    print("\nSaved graph -> ssh_scores_hist.png")

    # ✅ Sauvegarde métriques pour l'API /ml/metrics
    save_metrics(X, scores, preds, anomaly_ratio)


if __name__ == "__main__":
    main()