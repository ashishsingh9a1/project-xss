"""
evaluate.py  (Day 4)

Held-out evaluation of the three detectors on data/xss_dataset_v2.csv:
  1. rules only      (rule_based_detector.scan)
  2. anomaly only    (IsolationForest, trained on BENIGN train rows only)
  3. hybrid          (rule hit -> BLOCK, anomaly-only -> FLAG; both count as "detected")

Protocol:
  - fit on benign `train` rows only (no attack example is ever used)
  - choose the anomaly `contamination` on `val`
  - report once on `test` (in-distribution) and `stress` (unseen benign
    categories + unseen attack families)
  - rules are never tuned on this data

Run:  python src/evaluate.py            # evaluate only, writes docs/evaluation_results.md
      python src/evaluate.py --save-model   # also save the model to models/anomaly_model.joblib
"""

import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

import rule_based_detector as rules
from features import extract

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "xss_dataset_v2.csv"
OUT_MD = ROOT / "docs" / "evaluation_results.md"
MODEL_PATH = ROOT / "models" / "anomaly_model.joblib"


def feats(texts):
    return np.array([extract(t) for t in texts])


def metrics(y, p):
    y, p = np.asarray(y), np.asarray(p)
    tp = int(((p == 1) & (y == 1)).sum()); fp = int(((p == 1) & (y == 0)).sum())
    tn = int(((p == 0) & (y == 0)).sum()); fn = int(((p == 0) & (y == 1)).sum())
    n = tp + fp + tn + fn
    acc = (tp + tn) / n if n else 0
    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    return dict(acc=acc, prec=prec, rec=rec, f1=f1, tp=tp, fp=fp, tn=tn, fn=fn)


def predict_all(df, model):
    texts = df.text.tolist()
    rule_hit = np.array([1 if rules.scan(t)["flagged"] else 0 for t in texts])
    anom = (model.predict(feats(texts)) == -1).astype(int)
    hybrid = ((rule_hit == 1) | (anom == 1)).astype(int)
    return rule_hit, anom, hybrid


def fit(train_benign, contamination):
    m = IsolationForest(n_estimators=200, contamination=contamination, random_state=42)
    m.fit(feats(train_benign))
    return m


def row(name, m):
    return (f"| {name} | {m['acc']:.1%} | {m['prec']:.1%} | {m['rec']:.1%} | {m['f1']:.1%} | "
            f"{m['fp']} | {m['fn']} | {m['tp']}/{m['fp']}/{m['tn']}/{m['fn']} |")


HEAD = ("| Detector | Accuracy | Precision | Recall | F1 | False pos. | False neg. | TP/FP/TN/FN |\n"
        "|---|---|---|---|---|---|---|---|")


def main():
    save = "--save-model" in sys.argv
    df = pd.read_csv(DATA)
    train_b = df[(df.split == "train") & (df.label == 0)].text.tolist()
    val, test, stress = (df[df.split == s].reset_index(drop=True) for s in ("val", "test", "stress"))

    # ---- choose contamination on VAL only (best hybrid F1) ----
    best = None
    tuning = []
    for c in (0.01, 0.02, 0.03, 0.05, 0.08, 0.10):
        m = fit(train_b, c)
        _, _, h = predict_all(val, m)
        f1 = metrics(val.label, h)["f1"]
        fp = metrics(val.label, h)["fp"]
        tuning.append((c, f1, fp))
        if best is None or f1 > best[1]:
            best = (c, f1, m)
    contamination, _, model = best

    out = []
    out.append("# Held-out evaluation results\n")
    out.append(f"Dataset: `data/xss_dataset_v2.csv`, {len(df)} unique rows. Anomaly model trained on "
               f"**{len(train_b)} benign train rows only**; contamination chosen on the validation split "
               f"(**{contamination}**). Rules were not tuned on this data. \"Detected\" for the hybrid means "
               f"BLOCK or FLAG.\n")
    out.append("Contamination tuning on validation split:\n")
    out.append("| contamination | hybrid F1 | false positives |\n|---|---|---|")
    for c, f1, fp in tuning:
        out.append(f"| {c} | {f1:.1%} | {fp} |")
    out.append("")

    for title, part in (("Test split (in-distribution, never used for tuning)", test),
                        ("Stress split (unseen benign categories and unseen attack families)", stress)):
        r, a, h = predict_all(part, model)
        out.append(f"## {title}\n")
        n_b, n_m = int((part.label == 0).sum()), int((part.label == 1).sum())
        out.append(f"{len(part)} rows: {n_b} benign, {n_m} malicious.\n")
        out.append(HEAD)
        out.append(row("Rules only", metrics(part.label, r)))
        out.append(row("Anomaly only", metrics(part.label, a)))
        out.append(row("**Hybrid (rules + anomaly)**", metrics(part.label, h)))
        out.append("")

        # per-family recall for malicious
        mal = part[part.label == 1].copy()
        mal["rules"], mal["anomaly"], mal["hybrid"] = r[part.label == 1], a[part.label == 1], h[part.label == 1]
        g = mal.groupby("family")[["rules", "anomaly", "hybrid"]].mean().mul(100).round(1)
        g["n"] = mal.groupby("family").size()
        out.append("Recall by attack family (% detected):\n")
        out.append("| Family | n | Rules | Anomaly | Hybrid |\n|---|---|---|---|---|")
        for fam, rr in g.iterrows():
            out.append(f"| {fam} | {int(rr['n'])} | {rr['rules']}% | {rr['anomaly']}% | {rr['hybrid']}% |")
        out.append("")

        # false positives by category (hybrid)
        ben = part[part.label == 0].copy()
        ben["fp"] = h[part.label == 0]
        fpc = ben.groupby("category")["fp"].agg(["sum", "count"])
        fpc = fpc[fpc["sum"] > 0].sort_values("sum", ascending=False)
        out.append("False positives by benign category (hybrid):\n")
        if len(fpc):
            out.append("| Category | False positives | Rows |\n|---|---|---|")
            for cat, rr in fpc.iterrows():
                out.append(f"| {cat} | {int(rr['sum'])} | {int(rr['count'])} |")
            ex = ben[ben.fp == 1].text.head(6).tolist()
            out.append("\nExamples of wrongly flagged benign input:\n")
            out += [f"- `{t}`" for t in ex]
        else:
            out.append("None.")
        out.append("")

        # blocks vs flags
        blocks = int(r.sum()); flags = int(((a == 1) & (r == 0)).sum())
        out.append(f"Hybrid verdict mix on this split: {blocks} BLOCK (rule hit), {flags} FLAG (anomaly only).\n")

        # missed attacks
        missed = mal[mal.hybrid == 0].text.head(8).tolist()
        out.append(f"Attacks missed by the hybrid ({int((mal.hybrid == 0).sum())} total), examples:\n")
        out += ([f"- `{t}`" for t in missed] or ["None."])
        out.append("")

    OUT_MD.parent.mkdir(exist_ok=True)
    OUT_MD.write_text("\n".join(out), encoding="utf-8")
    print("\n".join(out))
    print(f"\nWrote {OUT_MD}")
    if save:
        MODEL_PATH.parent.mkdir(exist_ok=True)
        joblib.dump(model, MODEL_PATH)
        print(f"Saved model to {MODEL_PATH}")


if __name__ == "__main__":
    main()
