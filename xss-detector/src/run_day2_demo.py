"""
run_day2_demo.py

Today's goal: log a normal input, a rule-matched payload, and a no-rule
payload, and confirm each gets the right verdict.

This sends exactly three inputs through the hybrid detector and writes
one row per input to data/xss_log.csv, matching the Day 2 checklist:

    normal input      -> ALLOW
    rule-matched       -> BLOCK (rule reason)
    no-rule payload    -> FLAG  (anomaly reason)

NOTE on payload choice: the original checklist suggested <svg onload=
alert(1)> as the "no-rule payload". In THIS project's rule set, that
string actually matches two rules (event_handler, svg_or_img_vector),
so it would come back BLOCK, not FLAG -- it's not a valid no-rule
example here. Swapped in the payload this project's own evaluation
already showed the rule engine misses:
    ';alert(String.fromCharCode(88,83,83))//
This is also a better choice for the demo because it's a documented,
measured result, not a hypothetical.
"""

import csv
from pathlib import Path

import detector

CSV_PATH = Path(__file__).resolve().parent.parent / "data" / "xss_log.csv"

TEST_INPUTS = [
    ("normal input", "203.0.113.7", "comment", "Great article, thanks for sharing!"),
    ("rule-matched", "198.51.100.23", "comment", "<script>alert(1)</script>"),
    ("no-rule payload", "192.0.2.55", "comment", "';alert(String.fromCharCode(88,83,83))//"),
]


def main():
    model = None
    try:
        import anomaly_detector as anomaly
        model = anomaly.load_model()
    except FileNotFoundError:
        print("No trained anomaly model found -- run: python anomaly_detector.py train")
        return

    rows = []
    for label, source_id, field, text in TEST_INPUTS:
        result = detector.detect(text, source_id, field, anomaly_model=model)
        reason = result["reason"]
        if reason.startswith("rule:"):
            reason_display = "rule reason: " + reason.replace("rule:", "")
        elif reason == "anomaly_only":
            reason_display = f"anomaly reason: score={result['anomaly_score']:+.3f}"
        else:
            reason_display = "clean"

        rows.append({
            "case": label,
            "source_ip": source_id,
            "target_field": field,
            "input": text,
            "verdict": result["verdict"],
            "attack_type": result["attack_type"] or "-",
            "severity": result["severity"] or "-",
            "reason": reason_display,
        })

    CSV_PATH.parent.mkdir(exist_ok=True)
    write_header = not CSV_PATH.exists()
    with open(CSV_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        if write_header:
            writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {CSV_PATH}\n")
    print(f"{'CASE':<18} {'VERDICT':<8} {'ATTACK TYPE':<38} {'REASON'}")
    for r in rows:
        print(f"{r['case']:<18} {r['verdict']:<8} {r['attack_type']:<38} {r['reason']}")

    # Quick self-check against the expected verdicts from the checklist.
    expected = {"normal input": "ALLOW", "rule-matched": "BLOCK", "no-rule payload": "FLAG"}
    print("\nVerification:")
    all_ok = True
    for r in rows:
        exp = expected[r["case"]]
        ok = r["verdict"] == exp
        all_ok &= ok
        print(f"  {r['case']:<18} expected={exp:<7} got={r['verdict']:<7} {'OK' if ok else 'MISMATCH'}")
    print("\nAll verdicts correct." if all_ok else "\nSome verdicts did not match -- check above.")


if __name__ == "__main__":
    main()
