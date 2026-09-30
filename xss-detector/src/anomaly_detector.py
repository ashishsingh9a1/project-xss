"""
anomaly_detector.py

Trains an IsolationForest ONLY on benign input. It never sees a single
malicious example during training. The idea: instead of learning what
attacks look like (that's what a classifier would do), this learns what
NORMAL input looks like, and flags anything that deviates from it --
including attack styles it has never seen, as long as they are
statistically unusual.

This is what lets the system catch something the regex rules miss:
no rule needs to exist for a pattern, as long as the pattern looks
"weird" compared to ordinary text.
"""

import csv
import joblib
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest

from features import extract, FEATURE_NAMES

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "anomaly_model.joblib"


def load_dataset(csv_path: Path):
    texts, labels = [], []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            texts.append(row["text"])
            labels.append(int(row["label"]))
    return texts, labels


def train(csv_path: Path, contamination: float = 0.05):
    texts, labels = load_dataset(csv_path)

    # Train ONLY on benign (label == 0) samples -- this is the whole point.
    benign_texts = [t for t, l in zip(texts, labels) if l == 0]
    X_benign = np.array([extract(t) for t in benign_texts])

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
    )
    model.fit(X_benign)

    MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"Trained on {len(benign_texts)} benign samples only.")
    print(f"Saved model to {MODEL_PATH}")
    return model


def load_model():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"No trained model at {MODEL_PATH}. Run: python anomaly_detector.py train"
        )
    return joblib.load(MODEL_PATH)


def score(text: str, model=None) -> dict:
    """
    Score one piece of text.

    Returns:
      {
        "is_anomaly": bool,       # model's own decision boundary
        "anomaly_score": float,   # raw decision_function score; more
                                   # negative = more anomalous
      }
    """
    if model is None:
        model = load_model()
    vec = np.array([extract(text)])
    is_anomaly = model.predict(vec)[0] == -1  # -1 = anomaly, 1 = normal
    raw_score = float(model.decision_function(vec)[0])
    return {"is_anomaly": is_anomaly, "anomaly_score": raw_score}


def evaluate(csv_path: Path, model=None):
    """
    Evaluate against the FULL dataset (benign + malicious), even though
    training only used benign data. This tells us: of the attacks in our
    set, how many does the anomaly detector catch on its own, purely by
    virtue of looking statistically unusual?
    """
    if model is None:
        model = load_model()
    texts, labels = load_dataset(csv_path)

    tp = fp = tn = fn = 0
    caught_malicious = []
    missed_malicious = []

    for text, label in zip(texts, labels):
        result = score(text, model)
        predicted = 1 if result["is_anomaly"] else 0
        if predicted == 1 and label == 1:
            tp += 1
            caught_malicious.append((text, result["anomaly_score"]))
        elif predicted == 1 and label == 0:
            fp += 1
        elif predicted == 0 and label == 0:
            tn += 1
        else:
            fn += 1
            missed_malicious.append(text)

    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0

    print(f"Anomaly detector evaluated on {total} samples (trained on benign only)")
    print(f"  Accuracy:  {accuracy:.2%}")
    print(f"  Precision: {precision:.2%}")
    print(f"  Recall:    {recall:.2%}")
    print(f"  TP={tp}  FP={fp}  TN={tn}  FN={fn}")

    if caught_malicious:
        print(f"\nMalicious inputs caught (never trained on any attack example):")
        for text, s in caught_malicious:
            print(f"  score={s:+.3f}  {text}")


if __name__ == "__main__":
    import sys

    dataset_path = Path(__file__).resolve().parent.parent / "data" / "xss_dataset.csv"

    if len(sys.argv) > 1 and sys.argv[1] == "train":
        train(dataset_path)
    else:
        model = load_model() if MODEL_PATH.exists() else train(dataset_path)
        print()
        evaluate(dataset_path, model)
