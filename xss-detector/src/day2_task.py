"""
day2_task.py

Runs the exact "Attack Stage Task | ABES - Ashish Singh" deliverables:

  Step 2 proof -> evidence/day2_payloads.txt
  Step 3 proof -> evidence/day2_log.csv   (timestamp, input, verdict, reason)
  Step 4 proof -> evidence/day2_verdicts.txt

Step 1 (DVWA screenshot) is not produced here -- that has to be captured
live in the browser and saved as evidence/day2_dvwa.png.

Uses this project's real hybrid detector (rules + anomaly detection) --
not a placeholder -- so the verdicts and reasons are genuine pipeline
output, not hand-written.
"""

import csv
import datetime
from pathlib import Path

import detector
import anomaly_detector as anomaly
from payloads import TESTS

EVIDENCE_DIR = Path(__file__).resolve().parent.parent / "evidence"


def reason_for_humans(result: dict) -> str:
    """Turn the pipeline's reason code into a phrase that names which
    detector fired, exactly as the trainer's Step 4 requires."""
    reason = result["reason"]
    if reason.startswith("rule:"):
        rule_names = reason.replace("rule:", "")
        return f"rule reason: matched {rule_names}"
    if reason == "anomaly_only":
        return f"anomaly reason: IsolationForest score={result['anomaly_score']:+.3f}"
    return "clean: no rule or anomaly signal"


def main():
    EVIDENCE_DIR.mkdir(exist_ok=True)
    model = anomaly.load_model()

    # ---- Step 2 proof: the three payloads, written out -------------------
    payloads_path = EVIDENCE_DIR / "day2_payloads.txt"
    with open(payloads_path, "w", encoding="utf-8") as f:
        f.write("Day 2 test inputs (src/payloads.py)\n")
        f.write("=" * 40 + "\n\n")
        for label, text in TESTS:
            f.write(f"{label}: {text}\n")
        f.write(
            "\nNote: no_rule payload swapped from the suggested "
            "<svg onload=alert(1)> per the task's own fallback instruction "
            "(this project's rules already match that string via "
            "event_handler and svg_or_img_vector). Swapped for a payload "
            "this project's rule engine genuinely misses: "
            "';alert(String.fromCharCode(88,83,83))//\n"
        )

    # ---- Steps 3 & 4: run each through the real detector ------------------
    log_path = EVIDENCE_DIR / "day2_log.csv"
    verdicts_path = EVIDENCE_DIR / "day2_verdicts.txt"

    rows = []
    for label, text in TESTS:
        # source_id/target_field are this project's own richer schema;
        # source is simulated since there's no live web server in front
        # of the detector yet.
        result = detector.detect(text, source_id="127.0.0.1", target_field="test", anomaly_model=model)
        reason = reason_for_humans(result)
        timestamp = datetime.datetime.now().isoformat()
        rows.append((timestamp, text, result["verdict"], reason, label))

    with open(log_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "input", "verdict", "reason"])
        for ts, text, verdict, reason, _label in rows:
            writer.writerow([ts, text, verdict, reason])

    expected = {"normal": "ALLOW", "rule_match": "BLOCK", "no_rule": "FLAG"}
    with open(verdicts_path, "w", encoding="utf-8") as f:
        f.write("Day 2 verdict confirmation\n")
        f.write("=" * 40 + "\n\n")
        all_ok = True
        for ts, text, verdict, reason, label in rows:
            exp = expected[label]
            ok = verdict == exp
            all_ok &= ok
            f.write(f"[{label}] input: {text}\n")
            f.write(f"  expected: {exp}   got: {verdict}   {'OK' if ok else 'MISMATCH'}\n")
            f.write(f"  reason: {reason}\n\n")
        f.write("All three verdicts correct.\n" if all_ok else "MISMATCH found -- see above.\n")

    # ---- console summary ---------------------------------------------------
    print(f"Wrote:\n  {payloads_path}\n  {log_path}\n  {verdicts_path}\n")
    print(f"{'LABEL':<12} {'VERDICT':<8} REASON")
    for ts, text, verdict, reason, label in rows:
        print(f"{label:<12} {verdict:<8} {reason}")


if __name__ == "__main__":
    main()
