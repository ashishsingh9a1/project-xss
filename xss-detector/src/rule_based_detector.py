"""
rule_based_detector.py

Week 2: A regex-based XSS detector (v1).

Given a piece of text (e.g. user input from a form field), this flags
whether it looks like an XSS payload based on known-malicious patterns:
script tags, event handlers (onerror, onload, etc.), javascript: URIs,
and common encoded/obfuscated variants.

This is intentionally simple — it's your baseline. Week 3 adds an ML
layer on top to catch what regex misses and reduce false positives.
"""

import csv
import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Detection patterns, grouped by what they catch. Kept as separate compiled
# patterns (not one giant regex) so you can see/report *which* rule fired --
# useful for your write-up and for debugging false positives/negatives.
# ---------------------------------------------------------------------------
PATTERNS = {
    "script_tag": re.compile(r"<\s*script\b", re.IGNORECASE),
    "event_handler": re.compile(
        r"on(error|load|focus|mouseover|toggle|start)\s*=", re.IGNORECASE
    ),
    "javascript_uri": re.compile(r"javascript\s*:", re.IGNORECASE),
    "iframe_or_object": re.compile(r"<\s*(iframe|object|embed)\b", re.IGNORECASE),
    "svg_or_img_vector": re.compile(r"<\s*(svg|img)\b[^>]*on\w+\s*=", re.IGNORECASE),
    "html_entity_encoded": re.compile(r"&#x?[0-9a-f]+;", re.IGNORECASE),
    "url_encoded_script": re.compile(r"%3C\s*script", re.IGNORECASE),
    "eval_or_document": re.compile(r"\b(eval|document\.cookie|fetch)\s*\(", re.IGNORECASE),
}


def scan(text: str) -> dict:
    """
    Scan a piece of text for XSS indicators.

    Returns a dict:
      {
        "flagged": bool,
        "matched_rules": [list of pattern names that fired]
      }
    """
    matched = [name for name, pattern in PATTERNS.items() if pattern.search(text)]
    return {"flagged": len(matched) > 0, "matched_rules": matched}


def evaluate_dataset(csv_path: Path):
    """
    Run the detector against the labeled dataset and report accuracy,
    precision, recall, and false positives/negatives -- so you have real
    numbers to cite, not just "it works."
    """
    tp = fp = tn = fn = 0
    false_negatives = []
    false_positives = []

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            text = row["text"]
            true_label = int(row["label"])
            result = scan(text)
            predicted = 1 if result["flagged"] else 0

            if predicted == 1 and true_label == 1:
                tp += 1
            elif predicted == 1 and true_label == 0:
                fp += 1
                false_positives.append(text)
            elif predicted == 0 and true_label == 0:
                tn += 1
            else:
                fn += 1
                false_negatives.append(text)

    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0

    print(f"Evaluated {total} samples")
    print(f"  Accuracy:  {accuracy:.2%}")
    print(f"  Precision: {precision:.2%}")
    print(f"  Recall:    {recall:.2%}")
    print(f"  TP={tp}  FP={fp}  TN={tn}  FN={fn}")

    if false_negatives:
        print(f"\nMissed payloads (false negatives) -- {len(false_negatives)}:")
        for text in false_negatives:
            print(f"  - {text}")

    if false_positives:
        print(f"\nWrongly flagged benign text (false positives) -- {len(false_positives)}:")
        for text in false_positives:
            print(f"  - {text}")


if __name__ == "__main__":
    # Quick manual sanity check
    samples = [
        "<script>alert(1)</script>",
        "Great article, thanks for sharing!",
        "<img src=x onerror=alert(1)>",
        "My order number is 48213.",
    ]
    print("Manual sanity check:")
    for s in samples:
        result = scan(s)
        print(f"  {s[:50]!r:55} -> flagged={result['flagged']}  rules={result['matched_rules']}")

    print("\nFull dataset evaluation:")
    dataset_path = Path(__file__).resolve().parent.parent / "data" / "xss_dataset.csv"
    evaluate_dataset(dataset_path)
