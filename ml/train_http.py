import json
import os
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

from feature_extraction import featurize_http

DATA_PATH = os.path.join("data", "http_events.jsonl")
MODEL_OUT = "model_http.joblib"

# Endpoints/pages trop peu informatifs
BORING_PATHS = {
    "/", "/index.html", "/about", "/contact", "/api/health"
}

# Extensions statiques à ignorer
STATIC_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".ico", ".woff", ".woff2", ".ttf"
)

# Méthodes qu'on préfère ignorer pour le ML MVP
IGNORED_METHODS = {"HEAD", "OPTIONS"}


def is_boring_http_event(evt: dict) -> bool:
    path = (evt.get("path") or "").strip().lower()
    method = (evt.get("method") or "").strip().upper()
    query = (evt.get("query") or "").strip()
    body = (evt.get("body") or "").strip()
    ua = (evt.get("user_agent") or "").strip()

    # Event vide ou presque
    if not path:
        return True

    # Méthodes peu utiles pour ce modèle MVP
    if method in IGNORED_METHODS:
        return True

    # Fichiers statiques
    if path.endswith(STATIC_EXTENSIONS):
        return True

    # Pages très banales sans query/body
    if path in BORING_PATHS and not query and not body:
        return True

    # User-Agent totalement absent + pas de contenu utile
    if not ua and not query and not body:
        return True

    return False


def make_dedup_key(evt: dict) -> tuple:
    """
    ✅ Clé de déduplication exacte HTTP.
    Basée sur le contenu uniquement (sans IP) car en entraînement
    offline le trafic synthétique vient souvent de la même IP Docker.
    Même méthode + même path + même query + même body → doublon.
    """
    return (
        (evt.get("method") or "").upper(),
        (evt.get("path") or "").strip().lower(),
        (evt.get("query") or "").strip(),
        (evt.get("body") or "").strip()[:200],
    )


def load_http_events(path: str) -> np.ndarray:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Fichier introuvable: {path}")

    X = []
    kept = 0
    skipped = 0

    # ✅ Déduplication exacte
    seen_keys: set = set()

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            if is_boring_http_event(evt):
                skipped += 1
                continue

            # ✅ Dédup exacte
            key = make_dedup_key(evt)
            if key in seen_keys:
                skipped += 1
                continue
            seen_keys.add(key)

            try:
                feats = featurize_http(evt)

                # ✅ Protection NaN / Inf
                if not np.all(np.isfinite(feats)):
                    skipped += 1
                    continue

                X.append(feats)
                kept += 1
            except Exception:
                skipped += 1
                continue

    print(f"[train_http] events kept={kept} skipped={skipped} unique_keys={len(seen_keys)}")
    return np.array(X, dtype=float)


def describe_scores(scores: np.ndarray, name: str = "scores"):
    print(f"[EVAL] {name}: mean={scores.mean():.4f} min={scores.min():.4f} max={scores.max():.4f}")
    for q in [1, 5, 10, 25, 50, 75, 90, 95, 99]:
        print(f"[EVAL] {name} p{q:02d} = {np.percentile(scores, q):.4f}")


def main():
    X = load_http_events(DATA_PATH)
    n = len(X)

    if n < 30:
        print(f"[train_http] Pas assez de données ({n}) après nettoyage. Génère plus de logs HTTP.")
        return

    # Split
    X_train, X_test = train_test_split(X, test_size=0.2, random_state=42)
    print(f"[train_http] samples={n} train={len(X_train)} test={len(X_test)}")

    # Train
    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42
    )
    model.fit(X_train)

    # Eval simple
    pred_test = model.predict(X_test)  # -1 anomalie, 1 normal
    anomaly_ratio = float((pred_test == -1).sum()) / float(len(pred_test))
    print(f"[EVAL] anomaly_ratio_test={anomaly_ratio:.3f}  (contamination=0.05)")

    scores_test = model.score_samples(X_test)
    describe_scores(scores_test, "score_samples_test")

    # 5 plus anormaux
    idx_sorted = np.argsort(scores_test)
    print("[EVAL] 5 most anomalous test samples (feature vectors):")
    for i in idx_sorted[:5]:
        print("  ", X_test[i].tolist(), " score=", float(scores_test[i]))

    # Save
    joblib.dump(model, MODEL_OUT)
    print(f"[train_http] Modèle sauvegardé -> {MODEL_OUT}")


if __name__ == "__main__":
    main()