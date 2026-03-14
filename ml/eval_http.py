import json, os
import numpy as np
import joblib
import matplotlib.pyplot as plt
from feature_extraction import featurize_http

DATA_PATH = os.path.join("data", "http_events.jsonl")
MODEL_PATH = "model_http.joblib"

def load_X():
    X, raw = [], []
    with open(DATA_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line=line.strip()
            if not line: 
                continue
            try:
                evt = json.loads(line)
            except:
                continue
            X.append(featurize_http(evt))
            raw.append(evt)
    return np.array(X, dtype=float), raw

def main():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("model_http.joblib introuvable. Lance train_http.py d'abord.")
    X, raw = load_X()
    model = joblib.load(MODEL_PATH)

    scores = model.score_samples(X)
    preds = model.predict(X)  # -1 anomalie

    anomaly_ratio = (preds == -1).sum() / len(preds)

    print("=== HTTP ML METRICS ===")
    print("samples:", len(X))
    print("anomaly_ratio:", round(anomaly_ratio, 4))
    print("score mean/min/max:", float(scores.mean()), float(scores.min()), float(scores.max()))
    print("percentiles:", {p: float(np.percentile(scores, p)) for p in [1,5,10,25,50,75,90,95,99]})

    # top 5 anomalies
    idx = np.argsort(scores)[:5]
    print("\nTop 5 anomalies:")
    for i in idx:
        evt = raw[i]
        print("-", "path=", evt.get("path"), "query=", evt.get("query"), "score=", float(scores[i]))

    # plot histogram
    plt.figure()
    plt.hist(scores, bins=50)
    plt.title("HTTP score_samples distribution (IsolationForest)")
    plt.xlabel("score_samples")
    plt.ylabel("count")
    plt.tight_layout()
    plt.savefig("http_scores_hist.png")
    print("\nSaved graph -> http_scores_hist.png")

if __name__ == "__main__":
    main()