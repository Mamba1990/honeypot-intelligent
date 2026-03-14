# ml/train_ssh.py
import json
import os
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

from feature_extraction import featurize_ssh_cowrie

DATA_PATH = os.path.join("data", "cowrie.json")
MODEL_OUT = "model_ssh.joblib"


def load_cowrie_events(path: str) -> np.ndarray:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Fichier introuvable: {path}")

    X = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            # offline: fails_60s inconnu -> 0
            X.append(featurize_ssh_cowrie(ev, fails_60s=0))

    return np.array(X, dtype=float)


def describe_scores(scores: np.ndarray, name: str = "scores"):
    print(f"[EVAL] {name}: mean={scores.mean():.4f} min={scores.min():.4f} max={scores.max():.4f}")
    for q in [1, 5, 10, 25, 50, 75, 90, 95, 99]:
        print(f"[EVAL] {name} p{q:02d} = {np.percentile(scores, q):.4f}")


def main():
    X = load_cowrie_events(DATA_PATH)
    n = len(X)
    if n < 50:
        print(f"[train_ssh] Pas assez de données ({n}). Génère plus d'events Cowrie.")
        return

    # Split
    X_train, X_test = train_test_split(X, test_size=0.2, random_state=42)
    print(f"[train_ssh] samples={n} train={len(X_train)} test={len(X_test)}")

    # Train
    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42
    )
    model.fit(X_train)

    # Eval simple
    pred_test = model.predict(X_test)
    anomaly_ratio = float((pred_test == -1).sum()) / float(len(pred_test))
    print(f"[EVAL] anomaly_ratio_test={anomaly_ratio:.3f}  (contamination=0.05)")

    scores_test = model.score_samples(X_test)
    describe_scores(scores_test, "score_samples_test")

    # Examples: 5 plus "anormaux"
    idx_sorted = np.argsort(scores_test)
    print("[EVAL] 5 most anomalous SSH test samples (feature vectors):")
    for i in idx_sorted[:5]:
        print("  ", X_test[i].tolist(), " score=", float(scores_test[i]))

    # Save
    joblib.dump(model, MODEL_OUT)
    print(f"[train_ssh] Modèle sauvegardé -> {MODEL_OUT}")


if __name__ == "__main__":
    main()