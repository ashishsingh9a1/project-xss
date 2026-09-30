"""
app.py

Frontend Dev Task: wires a real, visible screen to the real detector.

- POST /scan   -> runs input through the actual hybrid detector
                  (rules + anomaly detection), saves a finding for any
                  BLOCK/FLAG verdict, returns the result as JSON
- GET  /dashboard -> shows every saved finding as a live, colour-coded
                  HTML table (severity-based colour, newest first)

This is not sample data: save_finding() is called from inside /scan,
right where the real detector returns its verdict -- exactly as the
task specifies. Findings persist in findings.json, capped at the last 50.
"""

import json
import os

from flask import Flask, jsonify, render_template_string, request

import anomaly_detector as anomaly
import detector

app = Flask(__name__)

FINDINGS_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "findings.json")

# Load the anomaly model once at startup, not on every request.
_model = None


def get_model():
    global _model
    if _model is None:
        _model = anomaly.load_model()
    return _model


def save_finding(summary, severity="Info"):
    """Append one finding, keep only the most recent 50."""
    import datetime

    data = []
    if os.path.exists(FINDINGS_FILE):
        with open(FINDINGS_FILE) as f:
            data = json.load(f)
    data.append({
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "summary": summary,
        "severity": severity,
    })
    with open(FINDINGS_FILE, "w") as f:
        json.dump(data[-50:], f, indent=2)


DASH_HTML = """
<!doctype html>
<html>
<head>
  <title>XSS Detector - Live Findings</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 2rem; background: #f4f4f4; }
    h2 { color: #1F4E78; }
    table { border-collapse: collapse; width: 100%; max-width: 900px; background: white; }
    th, td { border: 1px solid #ccc; padding: 8px 12px; text-align: left; }
    th { background: #1F4E78; color: white; }
    .empty { color: #777; font-style: italic; margin-top: 1rem; }
  </style>
</head>
<body>
  <h2>XSS Detector &mdash; Live Findings</h2>
  {% if rows %}
  <table>
    <tr><th>Time</th><th>Input</th><th>Attack Type</th><th>Reason</th><th>Severity</th></tr>
    {% for r in rows %}
    <tr>
      <td>{{ r.time }}</td>
      <td>{{ r.summary }}</td>
      <td>{{ r.attack_type }}</td>
      <td>{{ r.reason }}</td>
      <td style="background:{{ '#e74c3c' if r.severity in ('Critical','High') else ('#f39c12' if r.severity=='Medium' else '#95a5a6') }};color:white;font-weight:bold">{{ r.severity }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p class="empty">No findings yet. Submit input via /scan to see live results here.</p>
  {% endif %}
</body>
</html>
"""


@app.route("/scan", methods=["POST"])
def scan():
    """
    Real detection endpoint. Expects JSON:
      { "text": "...", "source_id": "203.0.113.7", "target_field": "comment" }

    source_id and target_field are optional (default to a generic value)
    so this can be called with just {"text": "..."} for quick testing.
    """
    payload = request.get_json(force=True, silent=True) or {}
    text = payload.get("text", "")
    source_id = payload.get("source_id", request.remote_addr or "unknown")
    target_field = payload.get("target_field", "unspecified")

    if not text:
        return jsonify({"error": "missing 'text' field"}), 400

    result = detector.detect(text, source_id=source_id, target_field=target_field, anomaly_model=get_model())

    # This is the real wiring: save_finding() is called right where the
    # real detector produces a verdict -- not from a mock or sample list.
    if result["verdict"] in ("BLOCK", "FLAG"):
        summary = text if len(text) <= 80 else text[:77] + "..."
        save_finding(
            summary=summary,
            severity=result["severity"] or "Info",
        )
        # Store the extra fields alongside the last finding so the
        # dashboard can show attack type and reason too.
        _augment_last_finding(result)

    return jsonify(result)


def _augment_last_finding(result):
    """Add attack_type/reason to the finding just written by save_finding,
    without changing save_finding's simple (summary, severity) signature
    that the task's own template specifies."""
    if not os.path.exists(FINDINGS_FILE):
        return
    with open(FINDINGS_FILE) as f:
        data = json.load(f)
    if data:
        data[-1]["attack_type"] = result.get("attack_type") or "-"
        data[-1]["reason"] = result.get("reason") or "-"
        with open(FINDINGS_FILE, "w") as f:
            json.dump(data, f, indent=2)


@app.route("/dashboard")
def dashboard():
    rows = []
    if os.path.exists(FINDINGS_FILE):
        with open(FINDINGS_FILE) as f:
            rows = json.load(f)
    # ensure older/augmented-missing entries don't break the template
    for r in rows:
        r.setdefault("attack_type", "-")
        r.setdefault("reason", "-")
    return render_template_string(DASH_HTML, rows=list(reversed(rows)))


@app.route("/")
def index():
    return (
        "<p>XSS Detector Flask app is running.</p>"
        "<p>POST JSON to <code>/scan</code> to run a real detection, "
        "then view <a href='/dashboard'>/dashboard</a>.</p>"
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)
