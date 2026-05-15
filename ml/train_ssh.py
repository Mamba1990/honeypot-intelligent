"""
train_http.py — Honeypot Intelligent
======================================
Trains an Isolation Forest model on HTTP honeypot events.

Pipeline:
    1. Load http_events.jsonl
    2. Filter noise (static files, boring paths, HEAD/OPTIONS)
    3. Deduplicate by content (method + path + query + body)
    4. Featurize via featurize_http() → 16-dim vector
    5. Train IsolationForest (200 trees, contamination=5%)
    6. Evaluate on hold-out test set and print score distribution
    7. Save model to model_http.joblib

Run inside the collector container:
    python3 train_http.py

Author  : Hafsa Daoudim
Project : Final Training Project — JobInTech 2026
"""

import json
import os
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

from feature_extraction import featurize_http

DATA_PATH = os.path.join("data", "http_events.jsonl")
MODEL_OUT  = "model_http.joblib"

# ── Noise filters ─────────────────────────────────────────────────────────────

# Paths that carry no attack signal — excluded before training
BORING_PATHS = {
    "/", "/index.html", "/about", "/contact", "/api/health"
}

# Static asset extensions — irrelevant for behavioral anomaly detection
STATIC_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".ico", ".woff", ".woff2", ".ttf"
)

# HTTP methods that produce no useful features for this model
IGNORED_METHODS = {"HEAD", "OPTIONS"}


def is_boring_http_event(evt: dict) -> bool:
    """Return True if the event should be excluded from training."""
    path   = (evt.get("path")       or "").strip().lower()
    method = (evt.get("method")     or "").strip().upper()
    query  = (evt.get("query")      or "").strip()
    body   = (evt.get("body")       or "").strip()
    ua     = (evt.get("user_agent") or "").strip()

    if not path:                                          return True  # Empty path
    if method in IGNORED_METHODS:                         return True  # Useless method
    if path.endswith(STATIC_EXTENSIONS):                  return True  # Static file
    if path in BORING_PATHS and not query and not body:   return True  # Blank page hit
    if not ua and not query and not body:                 return True  # Content-free event
    return False


def make_dedup_key(evt: dict) -> tuple:
    """
    Content-based deduplication key (IP excluded).

    Synthetic traffic generated during the cold-start phase often shares the
    same Docker source IP. Deduplicating on content prevents the model from
    over-fitting to repeated identical payloads while preserving real diversity.
    """
    return (
        (evt.get("method") or "").upper(),
        (evt.get("path")   or "").strip().lower(),
        (evt.get("query")  or "").strip(),
        (evt.get("body")   or "").strip()[:200],  # Capped to avoid huge keys
    )


def load_http_events(path: str) -> np.ndarray:
    """
    Load, filter, deduplicate and featurize HTTP events from a JSONL file.

    Returns a float32 array of shape (n_samples, n_features).
    Rows with NaN or Inf values are dropped to prevent model corruption.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Data file not found: {path}")

    X, seen_keys = [], set()
    kept = skipped = 0

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

            # Step 1 — noise filter
            if is_boring_http_event(evt):
                skipped += 1
                continue

            # Step 2 — exact deduplication
            key = make_dedup_key(evt)
            if key in seen_keys:
                skipped += 1
                continue
            seen_keys.add(key)

            # Step 3 — featurization + NaN/Inf guard
            try:
                feats = featurize_http(evt)
                if not np.all(np.isfinite(feats)):
                    skipped += 1
                    continue
                X.append(feats)
                kept += 1
            except Exception:
                skipped += 1
                continue

    print(f"[train_http] kept={kept}  skipped={skipped}  unique_keys={len(seen_keys)}")
    return np.array(X, dtype=float)


def describe_scores(scores: np.ndarray, name: str = "scores"):
    """Print score statistics and key percentiles for threshold calibration."""
    print(f"[EVAL] {name}: mean={scores.mean():.4f}  min={scores.min():.4f}  max={scores.max():.4f}")
    for q in [1, 5, 10, 25, 50, 75, 90, 95, 99]:
        print(f"[EVAL] {name} p{q:02d} = {np.percentile(scores, q):.4f}")


def main():
    X = load_http_events(DATA_PATH)
    n = len(X)

    if n < 30:
        print(f"[train_http] Not enough samples ({n}) after filtering. Generate more HTTP logs.")
        return

    # 80/20 train-test split — fixed seed for reproducibility
    X_train, X_test = train_test_split(X, test_size=0.2, random_state=42)
    print(f"[train_http] total={n}  train={len(X_train)}  test={len(X_test)}")

    # Train Isolation Forest
    # 200 trees balances detection quality and inference speed.
    # contamination=0.05 tells the model ~5% of training samples are anomalies.
    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42       # Ensures reproducible score distribution
    )
    model.fit(X_train)

    # Evaluate on hold-out test set
    pred_test    = model.predict(X_test)       # -1 = anomaly, 1 = normal
    anomaly_ratio = (pred_test == -1).sum() / len(pred_test)
    print(f"[EVAL] anomaly_ratio_test={anomaly_ratio:.3f}  (expected ≈ contamination=0.05)")

    scores_test = model.score_samples(X_test)
    describe_scores(scores_test, "score_samples_test")

    # Inspect the 5 most anomalous test samples
    # Useful for calibrating ML_CRITICAL_SCORE in collector.py
    idx_sorted = np.argsort(scores_test)
    print("[EVAL] 5 most anomalous test samples (feature vectors):")
    for i in idx_sorted[:5]:
        print(f"  score={scores_test[i]:.4f}  features={X_test[i].tolist()}")

    # Persist model — loaded by collector.py at runtime (lazy loading)
    joblib.dump(model, MODEL_OUT)
    print(f"[train_http] model saved → {MODEL_OUT}")


if __name__ == "__main__":
    main()