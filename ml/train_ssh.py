import json
import os
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

from feature_extraction import featurize_ssh_cowrie

DATA_PATH = os.path.join("data", "cowrie.json")
MODEL_OUT = "model_ssh.joblib"

# 🎯 événements utiles uniquement
VALID_EVENTS = {
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.command.failed",   # ✅ commandes inconnues de Cowrie — vrai attaquant
}

# 🎯 mots clés utiles pour filtrer commandes vides
MIN_CMD_LENGTH = 2


def is_valid_ssh_event(ev: dict) -> bool:
    eventid = ev.get("eventid")

    # ❌ ignorer tout le bruit
    if eventid not in VALID_EVENTS:
        return False

    # ❌ ignorer commandes vides (input et failed)
    if eventid in ("cowrie.command.input", "cowrie.command.failed"):
        cmd = (ev.get("input") or "").strip()
        if len(cmd) < MIN_CMD_LENGTH:
            return False

    return True


def make_dedup_key(ev: dict) -> tuple:
    """
    ✅ Clé de déduplication exacte SSH.
    Même IP + même type d'event + même commande/user → doublon.
    """
    return (
        ev.get("src_ip") or ev.get("srcip") or "",
        ev.get("eventid", ""),
        (ev.get("input") or "").strip(),
        (ev.get("username") or "").strip(),
    )


def load_cowrie_events(path: str) -> np.ndarray:
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
                ev = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            if not is_valid_ssh_event(ev):
                skipped += 1
                continue

            # ✅ Dédup exacte
            key = make_dedup_key(ev)
            if key in seen_keys:
                skipped += 1
                continue
            seen_keys.add(key)

            try:
                # offline → fails_60s inconnu
                feats = featurize_ssh_cowrie(ev, fails_60s=0)

                # ✅ Protection NaN / Inf
                if not np.all(np.isfinite(feats)):
                    skipped += 1
                    continue

                X.append(feats)
                kept += 1
            except Exception:
                skipped += 1
                continue

    print(f"[train_ssh] events kept={kept} skipped={skipped} unique_keys={len(seen_keys)}")
    return np.array(X, dtype=float)


def describe_scores(scores: np.ndarray, name: str = "scores"):
    print(f"[EVAL] {name}: mean={scores.mean():.4f} min={scores.min():.4f} max={scores.max():.4f}")
    for q in [1, 5, 10, 25, 50, 75, 90, 95, 99]:
        print(f"[EVAL] {name} p{q:02d} = {np.percentile(scores, q):.4f}")


def main():
    X = load_cowrie_events(DATA_PATH)
    n = len(X)

    if n < 50:
        print(f"[train_ssh] Pas assez de données ({n}) après nettoyage. Génère plus d'events SSH.")
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

    # Eval
    pred_test = model.predict(X_test)
    anomaly_ratio = float((pred_test == -1).sum()) / float(len(pred_test))
    print(f"[EVAL] anomaly_ratio_test={anomaly_ratio:.3f}")

    scores_test = model.score_samples(X_test)
    describe_scores(scores_test, "score_samples_test")

    # Top anomalies
    idx_sorted = np.argsort(scores_test)
    print("[EVAL] 5 most anomalous SSH samples:")
    for i in idx_sorted[:5]:
        print("  ", X_test[i].tolist(), " score=", float(scores_test[i]))

    # Save
    joblib.dump(model, MODEL_OUT)
    print(f"[train_ssh] Modèle sauvegardé -> {MODEL_OUT}")


if __name__ == "__main__":
    main()