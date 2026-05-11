import json
import os
import numpy as np
import joblib
import matplotlib.pyplot as plt

from feature_extraction import featurize_http

DATA_PATH  = os.path.join("data", "http_events.jsonl")
MODEL_PATH = "model_http.joblib"
#ML_METRICS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ml_metrics.json")
ML_METRICS_PATH = "/db/ml_metrics.json"

# ✅ Même filtre que train_http.py — retire le bruit inutile
# ❌ Pas de déduplication — on veut la vraie distribution de production
BORING_PATHS = {
    "/", "/index.html", "/about", "/contact", "/api/health"
}
STATIC_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".ico", ".woff", ".woff2", ".ttf"
)
IGNORED_METHODS = {"HEAD", "OPTIONS"}


def is_boring_http_event(evt: dict) -> bool:
    path   = (evt.get("path")       or "").strip().lower()
    method = (evt.get("method")     or "").strip().upper()
    query  = (evt.get("query")      or "").strip()
    body   = (evt.get("body")       or "").strip()
    ua     = (evt.get("user_agent") or "").strip()

    if not path:
        return True
    if method in IGNORED_METHODS:
        return True
    if path.endswith(STATIC_EXTENSIONS):
        return True
    if path in BORING_PATHS and not query and not body:
        return True
    if not ua and not query and not body:
        return True
    return False


def load_X():
    """
    Charge tous les events HTTP filtrés (sans déduplication).
    Filtrés  → métriques cohérentes avec ce que le modèle sait évaluer.
    Non dédupliqués → distribution réelle de production conservée.
    """
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
                evt = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            # ✅ Filtre bruit — même logique que train_http
            if is_boring_http_event(evt):
                skipped += 1
                continue

            try:
                feats = featurize_http(evt)
                if not np.all(np.isfinite(feats)):
                    skipped += 1
                    continue
                X.append(feats)
                raw.append(evt)
                kept += 1
            except Exception:
                skipped += 1
                continue

    print(f"[eval_http] events kept={kept} skipped={skipped}")
    return np.array(X, dtype=float), raw


def save_metrics(n, scores, preds, anomaly_ratio):
    """Sauvegarde les métriques HTTP dans /db/ml_metrics.json pour l'API."""
    metrics_http = {
        "total": int(n),
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

    # Lire l'existant (SSH peut déjà avoir été calculé)
    existing = {}
    try:
        with open(ML_METRICS_PATH, "r") as f:
            existing = json.load(f)
    except Exception:
        pass

    existing["http"] = metrics_http

    os.makedirs(os.path.dirname(ML_METRICS_PATH), exist_ok=True)
    with open(ML_METRICS_PATH, "w") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False)

    print(f"\n✅ ml_metrics.json mis à jour (http) → {ML_METRICS_PATH}")


def main():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("model_http.joblib introuvable. Lance train_http.py d'abord.")

    X, raw = load_X()
    n = len(X)

    if n == 0:
        print("[eval_http] Aucun event apres filtrage.")
        return

    model = joblib.load(MODEL_PATH)

    # ✅ Verification coherence dimensions
    expected = model.n_features_in_
    if X.shape[1] != expected:
        raise ValueError(
            f"Incompatibilite features : X a {X.shape[1]} dims "
            f"mais le modele attend {expected} dims. "
            f"Reentraine le modele avec train_http.py."
        )

    scores = model.score_samples(X)
    preds  = model.predict(X)   # -1 anomalie, 1 normal

    anomaly_ratio = (preds == -1).sum() / len(preds)

    print("\n=== HTTP ML METRICS ===")
    print(f"samples           : {n}")
    print(f"features          : {X.shape[1]}")
    print(f"anomaly_ratio     : {round(anomaly_ratio, 4)}")
    print(f"score mean        : {scores.mean():.4f}")
    print(f"score min         : {scores.min():.4f}")
    print(f"score max         : {scores.max():.4f}")

    print("\nPercentiles:")
    for p in [1, 5, 10, 25, 50, 75, 90, 95, 99]:
        print(f"  p{p:02d} = {np.percentile(scores, p):.4f}")

    # Top 5 anomalies
    idx = np.argsort(scores)[:5]
    print("\nTop 5 anomalies (scores les plus bas):")
    for i in idx:
        evt = raw[i]
        print(
            f"  score={scores[i]:.4f}"
            f"  path={evt.get('path', '')}"
            f"  query={str(evt.get('query', ''))[:60]}"
            f"  ua={str(evt.get('user_agent', ''))[:40]}"
        )

    # ✅ Histogramme avec seuil visuel
    threshold = np.percentile(scores, 5)  # ~5% anomalies
    plt.figure(figsize=(10, 5))
    plt.hist(scores[preds == 1],  bins=40, alpha=0.7, color="#2980b9", label="Normal")
    plt.hist(scores[preds == -1], bins=40, alpha=0.7, color="#e74c3c", label="Anomalie")
    plt.axvline(threshold, color="orange", linestyle="--", linewidth=1.5,
                label=f"p5 = {threshold:.3f}")
    plt.title("HTTP score_samples distribution (IsolationForest)")
    plt.xlabel("score_samples")
    plt.ylabel("count")
    plt.legend()
    plt.tight_layout()
    plt.savefig("http_scores_hist.png")
    print("\nSaved graph -> http_scores_hist.png")

    # ✅ Sauvegarde métriques pour l'API /ml/metrics
    save_metrics(n, scores, preds, anomaly_ratio)


if __name__ == "__main__":
    main()