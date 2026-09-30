import os
import sys
import json
import datetime
from flask import Flask, render_template_string, jsonify, request

app = Flask(__name__)
FINDINGS_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "findings.json")

def get_findings():
    if os.path.exists(FINDINGS_FILE):
        try:
            with open(FINDINGS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_finding(summary, attack_type="XSS Attempt", reason="rule_match", severity="Medium"):
    findings = get_findings()
    new_entry = {
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "summary": summary,
        "attack_type": attack_type,
        "reason": reason,
        "severity": severity
    }
    findings.append(new_entry)
    
    os.makedirs(os.path.dirname(FINDINGS_FILE), exist_ok=True)
    with open(FINDINGS_FILE, "w") as f:
        json.dump(findings[-50:], f, indent=2)

DASH_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>XSS Detector — Live Security Dashboard</title>
    <style>
        * { box-sizing: border-box; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        body { background-color: #f4f7f6; margin: 0; padding: 25px; color: #333; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        h2 { margin: 0; color: #1F4E78; font-size: 26px; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 25px; }
        .stat-card { background: #fff; padding: 15px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); border-left: 5px solid #1F4E78; }
        .stat-card.danger { border-left-color: #e74c3c; }
        .stat-card.warning { border-left-color: #f39c12; }
        .stat-card.info { border-left-color: #3498db; }
        .stat-number { font-size: 24px; font-weight: bold; margin-top: 5px; }
        .controls { display: flex; gap: 12px; margin-bottom: 15px; align-items: center; background: #fff; padding: 12px 15px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }
        .controls input[type="text"] { flex: 1; padding: 8px 12px; border: 1px solid #ccc; border-radius: 5px; font-size: 14px; }
        .btn { padding: 8px 14px; border: none; border-radius: 5px; cursor: pointer; font-weight: 600; font-size: 13px; background: #e0e0e0; color: #333; }
        .btn.active { background: #1F4E78; color: #fff; }
        table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }
        th { background: #1F4E78; color: white; padding: 12px; text-align: left; font-size: 14px; }
        td { padding: 12px; border-bottom: 1px solid #eee; font-size: 14px; word-break: break-all; }
        tr:hover { background-color: #f9f9f9; }
        .badge { padding: 4px 10px; border-radius: 12px; color: white; font-weight: bold; font-size: 12px; display: inline-block; text-align: center; }
        .bg-critical, .bg-high { background-color: #e74c3c; }
        .bg-medium { background-color: #f39c12; }
        .bg-low, .bg-info { background-color: #95a5a6; }
    </style>
</head>
<body>
    <div class="header">
        <h2>XSS Detector — Live Findings</h2>
        <div>
            <label style="font-size:14px; cursor:pointer;">
                <input type="checkbox" id="autoRefresh" checked> Auto-refresh (5s)
            </label>
        </div>
    </div>
    <div class="stats-grid">
        <div class="stat-card"><div>Total Incidents</div><div class="stat-number" id="count-total">0</div></div>
        <div class="stat-card danger"><div>High / Critical</div><div class="stat-number" id="count-high">0</div></div>
        <div class="stat-card warning"><div>Medium Severity</div><div class="stat-number" id="count-medium">0</div></div>
        <div class="stat-card info"><div>Low / Info</div><div class="stat-number" id="count-low">0</div></div>
    </div>
    <div class="controls">
        <input type="text" id="searchInput" placeholder="Search payloads, attack types, or reasons..." onkeyup="filterTable()">
        <button class="btn active" onclick="filterSeverity('ALL', this)">All</button>
        <button class="btn" onclick="filterSeverity('High', this)">High</button>
        <button class="btn" onclick="filterSeverity('Medium', this)">Medium</button>
        <button class="btn" onclick="filterSeverity('Low', this)">Low</button>
    </div>
    <table>
        <thead>
            <tr>
                <th style="width: 12%;">Time</th>
                <th style="width: 35%;">Input</th>
                <th style="width: 20%;">Attack Type</th>
                <th style="width: 20%;">Reason</th>
                <th style="width: 13%;">Severity</th>
            </tr>
        </thead>
        <tbody id="findingsBody"></tbody>
    </table>
    <script>
        let currentSeverityFilter = 'ALL';
        async function fetchFindings() {
            try {
                const res = await fetch('/api/findings');
                const data = await res.json();
                renderDashboard(data);
            } catch (err) { console.error("Error fetching findings:", err); }
        }
        function renderDashboard(rows) {
            const tbody = document.getElementById('findingsBody');
            tbody.innerHTML = '';
            let counts = { total: rows.length, high: 0, medium: 0, low: 0 };
            if (rows.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:#777;">No findings yet. Submit input via /scan to see live results here.</td></tr>';
                updateStats(counts);
                return;
            }
            [...rows].reverse().forEach(r => {
                const sev = r.severity || 'Info';
                if (['Critical', 'High'].includes(sev)) counts.high++;
                else if (sev === 'Medium') counts.medium++;
                else counts.low++;

                const bgClass = ['Critical', 'High'].includes(sev) ? 'bg-high' : (sev === 'Medium' ? 'bg-medium' : 'bg-low');
                const tr = document.createElement('tr');
                tr.setAttribute('data-severity', sev);
                tr.innerHTML = `
                    <td>${r.time || ''}</td>
                    <td><code>${escapeHtml(r.summary || r.input || '')}</code></td>
                    <td>${r.attack_type || 'XSS Attempt'}</td>
                    <td>${r.reason || 'rule_match'}</td>
                    <td><span class="badge ${bgClass}">${sev}</span></td>
                `;
                tbody.appendChild(tr);
            });
            updateStats(counts);
            filterTable();
        }
        function updateStats(counts) {
            document.getElementById('count-total').innerText = counts.total;
            document.getElementById('count-high').innerText = counts.high;
            document.getElementById('count-medium').innerText = counts.medium;
            document.getElementById('count-low').innerText = counts.low;
        }
        function filterTable() {
            const query = document.getElementById('searchInput').value.toLowerCase();
            const rows = document.querySelectorAll('#findingsBody tr');
            rows.forEach(tr => {
                const text = tr.innerText.toLowerCase();
                const sev = tr.getAttribute('data-severity') || '';
                const matchesSearch = text.includes(query);
                const matchesSev = (currentSeverityFilter === 'ALL') || 
                                   (currentSeverityFilter === 'High' && ['High', 'Critical'].includes(sev)) ||
                                   (currentSeverityFilter === sev);
                tr.style.display = (matchesSearch && matchesSev) ? '' : 'none';
            });
        }
        function filterSeverity(sev, btn) {
            currentSeverityFilter = sev;
            document.querySelectorAll('.controls .btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            filterTable();
        }
        function escapeHtml(str) { return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
        setInterval(() => { if (document.getElementById('autoRefresh').checked) fetchFindings(); }, 5000);
        fetchFindings();
    </script>
</body>
</html>
"""

@app.route("/")
def home():
    return "XSS Detector Flask app is running. POST JSON to /scan or view /dashboard."

@app.route("/dashboard")
def dashboard():
    return render_template_string(DASH_HTML)

@app.route("/api/findings")
def api_findings():
    return jsonify(get_findings())

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True) or {}
    text = data.get("text", "")
    
    verdict = "ALLOW"
    attack_type = "None"
    reason = "clean"
    severity = "Low"

    lower_text = text.lower()
    if "<script" in lower_text:
        verdict = "BLOCK"
        attack_type = "Script Tag Injection"
        reason = "rule:script_tag"
        severity = "High" if "cookie" in lower_text or "fetch" in lower_text else "Medium"
    elif "onload=" in lower_text or "onerror=" in lower_text:
        verdict = "BLOCK"
        attack_type = "Event Handler Injection"
        reason = "rule:event_handler"
        severity = "Medium"

    if verdict in ["BLOCK", "FLAG"]:
        save_finding(summary=text, attack_type=attack_type, reason=reason, severity=severity)

    return jsonify({
        "verdict": verdict,
        "attack_type": attack_type,
        "reason": reason,
        "severity": severity
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)