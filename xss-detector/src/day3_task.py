"""
day3_task.py

Runs the "Detection Stage Task | ABES - Ashish Singh" deliverables
(trainer email, Wed Sep 30 2026):

  Step 1 proof -> evidence/day3_detector_start.txt
  Step 2 proof -> evidence/day3_three_verdicts.txt
  Step 3 proof -> evidence/day3_negative_control.txt

NOTE on the trainer's suggested code: the email's "CODE TO RUN" block
gives a minimal starter RULES list (3 patterns) and FEATURES list (4
features) as an example of what a Day 3 detector.py might look like.
This project's detector.py already has a more developed rule engine
(8 patterns, in rule_based_detector.PATTERNS) and feature set (7
features, in features.FEATURE_NAMES) from Week 2/3 work, already
evaluated at 98.3% / 96.7% accuracy. Rather than hardcode a second,
smaller RULES/FEATURES list here that could drift out of sync with
what the code actually runs, this script prints the real ones,
straight from those modules -- same effect (rules and features
visible at the top of the run) with one source of truth.

Trainer's fixed-seed request (Step 2, "IF IT BREAKS") is already
satisfied: anomaly_detector.py trains IsolationForest with
random_state=42.
"""

import csv
import sys
from pathlib import Path

import detector
import anomaly_detector as anomaly
import rule_based_detector as rules
from features import FEATURE_NAMES

EVIDENCE_DIR = Path(__file__).resolve().parent.parent / "evidence"
DAY2_LOG = EVIDENCE_DIR / "day2_log.csv"


def _tee(*parts, file_handle):
    """Print to console and write the same line to the evidence file."""
    line = " ".join(str(p) for p in parts)
    print(line)
    file_handle.write(line + "\n")


# ---------------------------------------------------------------------------
# Step 1: finalise rules + features, train on normal input only, confirm load
# ---------------------------------------------------------------------------
def step1():
    path = EVIDENCE_DIR / "day3_detector_start.txt"
    with open(path, "w", encoding="utf-8") as f:
        _tee("STEP 1: finalise rules + features, train on normal input only", file_handle=f)
        _tee("=" * 60, file_handle=f)

        _tee("\nRULES (rule_based_detector.PATTERNS):", file_handle=f)
        for name, pattern in rules.PATTERNS.items():
            _tee(f"  {name:20s} {pattern.pattern}", file_handle=f)

        _tee("\nFEATURES (features.FEATURE_NAMES):", file_handle=f)
        for name in FEATURE_NAMES:
            _tee(f"  {name}", file_handle=f)

        _tee("\nTraining IsolationForest on benign-only samples "
             "(xss_dataset.csv, label == 0), random_state=42 ...", file_handle=f)
        dataset_path = Path(__file__).resolve().parent.parent / "data" / "xss_dataset.csv"
        model = anomaly.train(dataset_path)
        _tee("Model trained and fit without error.", file_handle=f)

        _tee("\nSanity check -- one test string:", file_handle=f)
        test_input = "test input"
        result = detector.detect(test_input, source_id="day3-step1", target_field="test", anomaly_model=model)
        _tee(f"  input:    {test_input!r}", file_handle=f)
        _tee(f"  verdict:  {result['verdict']}", file_handle=f)
        _tee(f"  reason:   {result['reason']}", file_handle=f)
        _tee(f"  anomaly_score: {result['anomaly_score']:+.3f}", file_handle=f)

    print(f"\nWrote {path}")
    return model


# ---------------------------------------------------------------------------
# Step 2: run the pipeline against yesterday's three logged rows
# ---------------------------------------------------------------------------
def step2(model):
    path = EVIDENCE_DIR / "day3_three_verdicts.txt"
    expected = {
        "normal": "ALLOW",
        "rule_match": "BLOCK",
        "no_rule": "FLAG",
    }

    if not DAY2_LOG.exists():
        raise FileNotFoundError(
            f"{DAY2_LOG} not found -- run day2_task.py first to produce yesterday's evidence."
        )

    rows = []
    with open(DAY2_LOG, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    with open(path, "w", encoding="utf-8") as f:
        _tee("STEP 2: verdicts on yesterday's three logged rows "
             f"(from {DAY2_LOG.relative_to(DAY2_LOG.parent.parent)})", file_handle=f)
        _tee("=" * 60, file_handle=f)

        all_ok = True
        # DAY2_LOG has columns: timestamp,input,verdict,reason -- it doesn't
        # carry the original label (normal/rule_match/no_rule), so re-derive
        # it from payloads.TESTS by matching on the input text, the same
        # three strings day2_task.py logged.
        from payloads import TESTS
        label_by_text = {text: label for label, text in TESTS}

        for row in rows:
            text = row["input"]
            label = label_by_text.get(text, "?")
            result = detector.detect(text, source_id="day3-step2", target_field="replay", anomaly_model=model)
            exp = expected.get(label, "?")
            ok = result["verdict"] == exp
            all_ok &= ok

            _tee(f"\n[{label}] input: {text}", file_handle=f)
            _tee(f"  expected: {exp}   got: {result['verdict']}   {'OK' if ok else 'MISMATCH'}", file_handle=f)
            if result["reason"].startswith("rule:"):
                _tee(f"  reason: rule reason -- matched {result['reason'].replace('rule:', '')}", file_handle=f)
            elif result["reason"] == "anomaly_only":
                _tee(f"  reason: anomaly reason -- IsolationForest score={result['anomaly_score']:+.3f}", file_handle=f)
            else:
                _tee(f"  reason: {result['reason']}", file_handle=f)

        _tee("\n" + ("All three verdicts correct." if all_ok else "MISMATCH found -- see above."), file_handle=f)

    print(f"Wrote {path}")
    return all_ok


# ---------------------------------------------------------------------------
# Step 3: negative control -- a fresh, never-seen normal input
# ---------------------------------------------------------------------------
def step3(model):
    path = EVIDENCE_DIR / "day3_negative_control.txt"
    fresh_input = "Meeting at 5pm with the team"

    with open(path, "w", encoding="utf-8") as f:
        _tee("STEP 3: negative control -- fresh normal input, never seen in training", file_handle=f)
        _tee("=" * 60, file_handle=f)
        result = detector.detect(fresh_input, source_id="day3-step3", target_field="test", anomaly_model=model)
        _tee(f"\ninput:    {fresh_input!r}", file_handle=f)
        _tee(f"verdict:  {result['verdict']}", file_handle=f)
        _tee(f"reason:   {result['reason']}", file_handle=f)
        _tee(f"anomaly_score: {result['anomaly_score']:+.3f}", file_handle=f)
        ok = result["verdict"] == "ALLOW"
        _tee("\n" + ("PASS: fresh normal input allowed, no false flag." if ok
                      else "FAIL: fresh normal input was NOT allowed -- see IF IT BREAKS notes."),
             file_handle=f)

    print(f"Wrote {path}")
    return result["verdict"] == "ALLOW"


def main():
    EVIDENCE_DIR.mkdir(exist_ok=True)
    model = step1()
    print()
    ok2 = step2(model)
    print()
    ok3 = step3(model)

    print("\n" + "=" * 60)
    print("DEFINITION OF DONE:", "ALL CHECKS PASSED" if (ok2 and ok3) else "CHECK MISMATCHES ABOVE")
    if not (ok2 and ok3):
        sys.exit(1)


if __name__ == "__main__":
    main()
