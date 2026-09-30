import os
import sys
import json
import datetime
from flask import Flask, render_template_string, jsonify, request, Response

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

def save_finding(summary, attack_type="XSS Attempt", reason="rule_match", severity="Medium", source_id="127.0.0.1"):
    findings = get_findings()
    new_entry = {
        "id": len(findings) + 1,
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": summary,
        "attack_type": attack_type,
        "reason": reason,
        "severity": severity,
        "source_id": source_id
    }
    findings.append(new_entry)
    
    os.makedirs(os.path.dirname(FINDINGS_FILE), exist_ok=True)
    with open(FINDINGS_FILE, "w") as f:
        json.dump(findings[-100:], f, indent=2)

DASH_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>XSS Security Command Center</title>
    <style>
        * { box-sizing: border-box; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        body { background-color: #0f172a; margin: 0; padding: 25px; color: #f8fafc; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        h2 { margin: 0; color: #38bdf8; font-size: 26px; }
        
        .sandbox-card { background: #1e293b; padding: 20px; border-radius: 10px; margin-bottom: 25px; border: 1px solid #334155; }
        .sandbox-card h3 { margin-top: 0; color: #e2e8f0; font-size: 16px; margin-bottom: 12px; }
        .sandbox-form { display: flex; gap: 10px; }
        .sandbox-input { flex: 1; padding: 10px; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: #fff; font-family: monospace; font-size: 14px; }
        .btn-primary { background: #0284c7; color: white; border: none; padding: 10px 18px; border-radius: 6px; cursor: pointer; font-weight: 600; }
        .btn-primary:hover { background: #0369a1; }
        .btn-danger { background: #dc2626; color: white; border: none; padding: 8px 14px; border-radius: 6px; cursor: pointer; font-weight: 600; }
        .btn-secondary { background: #334155; color: white; border: none; padding: 8px 14px; border-radius: 6px; cursor: pointer; font-weight: 600; }

        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 25px; }
        .stat-card { background: #1e293b; padding: 15px; border-radius: 10px; border-left: 5px solid #0284c7; border-top: 1px solid #334155; border-right: 1px solid #334155; border-bottom: 1px solid #334155; }
        .stat-card.danger { border-left-color: #ef4444; }
        .stat-card.warning { border-left-color: #f59e0b; }
        .stat-card.info { border-left-color: #64748b; }
        .stat-number { font-size: 26px; font-weight: bold; margin-top: 5px; color: #fff; }
        
        .controls { display: flex; gap: 12px; margin-bottom: 15px; align-items: center; background: #1e293b; padding: 12px 15px; border-radius: 10px; border: 1px solid #334155; }
        .controls input[type="text"] { flex: 1; padding: 8px 12px; border: 1px solid #475569; border-radius: 6px; background: #0f172a; color: #fff; font-size: 14px; }
        .filter-btn { padding: 8px 14px; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 13px; background: #334155; color: #94a3b8; }
        .filter-btn.active { background: #0284c7; color: #fff; }

        table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 10px; overflow: hidden; border: 1px solid #334155; }
        th { background: #0f172a; color: #38bdf8; padding: 12px; text-align: left; font-size: 14px; }
        td { padding: 12px; border-bottom: 1px solid #334155; font-size: 14px; word-break: break-all; color: #cbd5e1; }
        tr:hover { background-color: #334155; cursor: pointer; }

        .badge { padding: 4px 10px; border-radius: 12px; color: white; font-weight: bold; font-size: 12px; display: inline-block; }
        .bg-high { background-color: #ef4444; }
        .bg-medium { background-color: #f59e0b; }
        .bg-low { background-color: #64748b; }

        /* Modal Styles */
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); justify-content: center; align-items: center; }
        .modal-content { background: #1e293b; padding: 25px; border-radius: 12px; width: 600px; border: 1px solid #475569; color: #fff; }
        .modal-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 10px; }
        .close-btn { cursor: pointer; font-size: 20px; color: #94a3b8; }
    </style>
</head>
<body>

    <div class="header">
        <h2>🛡️ XSS Threat Detection Center</h2>
        <div>
            <button class="btn-secondary" onclick="exportCSV()">📥 Export CSV</button>
            <button class="btn-danger" onclick="clearFindings()">🗑️️ Clear Logs</button>
            <label style="font-size:14px; cursor:pointer; margin-left: 10px;">
                <input type="checkbox" id="autoRefresh" checked> Auto-refresh (5s)
            </label>
        </div>
    </div>

    <!-- Live Test Sandbox -->
    <div class="sandbox-card">
        <h3>⚡ Interactive Attack Payload Sandbox</h3>
        <div class="sandbox-form">
            <input type="text" id="sandboxInput" class="sandbox-input" placeholder="Enter XSS payload here e.g. <script>alert('XSS')</script>" value="<script>alert(document.cookie)</script>">
            <button class="btn-primary" onclick="testPayload()">Run Scan</button>
        </div>
    </div>

    <!-- Stat Cards -->
    <div class="stats-grid">
        <div class="stat-card"><div>Total Incidents</div><div class="stat-number" id="count-total">0</div></div>
        <div class="stat-card danger"><div>High / Critical</div><div class="stat-number" id="count-high">0</div></div>
        <div class="stat-card warning"><div>Medium Severity</div><div class="stat-number" id="count-medium">0</div></div>
        <div class="stat-card info"><div>Low / Info</div><div class="stat-number" id="count-low">0</div></div>
    </div>

    <!-- Search Controls -->
    <div class="controls">
        <input type="text" id="searchInput" placeholder="Search logs by payload, type, or vector..." onkeyup="filterTable()">
        <button class="filter-btn active" onclick="filterSeverity('ALL', this)">All</button>
        <button class="filter-btn" onclick="filterSeverity('High', this)">High</button>
        <button class="filter-btn" onclick="filterSeverity('Medium', this)">Medium</button>
        <button class="filter-btn" onclick="filterSeverity('Low', this)">Low</button>
    </div>

    <!-- Findings Table -->
    <table>
        <thead>
            <tr>
                <th style="width: 15%;">Time</th>
                <th style="width: 40%;">Detected Payload</th>
                <th style="width: 20%;">Attack Type</th>
                <th style="width: 15%;">Rule ID</th>
                <th style="width: 10%;">Severity</th>
            </tr>
        </thead>
        <tbody id="findingsBody"></tbody>
    </table>

    <!-- Incident Modal -->
    <div class="modal" id="incidentModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="modalTitle">Incident Details</h3>
                <span class="close-btn" onclick="closeModal()">&times;</span>
            </div>
            <div style="margin-top: 15px;">
                <p><strong>Timestamp:</strong> <span id="modalTime"></span></p>
                <p><strong>Severity:</strong> <span id="modalSeverity"></span></p>
                <p><strong>Attack Type:</strong> <span id="modalType"></span></p>
                <p><strong>Rule Triggered:</strong> <span id="modalReason"></span></p>
                <p><strong>Raw Payload:</strong></p>
                <pre id="modalPayload" style="background:#0f172a; padding:10px; border-radius:6px; color:#38bdf8; overflow-x:auto;"></pre>
            </div>
        </div>
    </div>

    <script>
        let currentSeverityFilter = 'ALL';
        let rawFindingsData = [];

        async function fetchFindings() {
            try {
                const res = await fetch('/api/findings');
                rawFindingsData = await res.json();
                renderDashboard(rawFindingsData);
            } catch (err) { console.error("Error fetching findings:", err); }
        }

        function renderDashboard(rows) {
            const tbody = document.getElementById('findingsBody');
            tbody.innerHTML = '';
            let counts = { total: rows.length, high: 0, medium: 0, low: 0 };

            if (rows.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:#64748b;">No security incidents recorded. Use the sandbox above or POST to /scan.</td></tr>';
                updateStats(counts);
                return;
            }

            [...rows].reverse().forEach((r, idx) => {
                const sev = r.severity || 'Info';
                if (['Critical', 'High'].includes(sev)) counts.high++;
                else if (sev === 'Medium') counts.medium++;
                else counts.low++;

                const bgClass = ['Critical', 'High'].includes(sev) ? 'bg-high' : (sev === 'Medium' ? 'bg-medium' : 'bg-low');
                const tr = document.createElement('tr');
                tr.setAttribute('data-severity', sev);
                tr.onclick = () => showModal(r);
                tr.innerHTML = `
                    <td>${r.time || ''}</td>
                    <td><code>${escapeHtml(r.summary || '')}</code></td>
                    <td>${r.attack_type || 'XSS Attempt'}</td>
                    <td>${r.reason || 'rule_match'}</td>
                    <td><span class="badge ${bgClass}">${sev}</span></td>
                `;
                tbody.appendChild(tr);
            });
            updateStats(counts);
            filterTable();
        }

        async function testPayload() {
            const payload = document.getElementById('sandboxInput').value;
            if(!payload) return;
            await fetch('/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text: payload, source_id: 'sandbox-ui' })
            });
            fetchFindings();
        }

        async function clearFindings() {
            if(confirm("Clear all logs?")) {
                await fetch('/api/clear', { method: 'POST' });
                fetchFindings();
            }
        }

        function exportCSV() {
            let csv = 'Time,Input,Attack Type,Reason,Severity\\n';
            rawFindingsData.forEach(r => {
                csv += `"${r.time}","${r.summary.replace(/"/g, '""')}","${r.attack_type}","${r.reason}","${r.severity}"\\n`;
            });
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.setAttribute('href', url);
            a.setAttribute('download', 'xss_findings_report.csv');
            a.click();
        }

        function showModal(data) {
            document.getElementById('modalTime').innerText = data.time;
            document.getElementById('modalSeverity').innerText = data.severity;
            document.getElementById('modalType').innerText = data.attack_type;
            document.getElementById('modalReason').innerText = data.reason;
            document.getElementById('modalPayload').innerText = data.summary;
            document.getElementById('incidentModal').style.display = 'flex';
        }

        function closeModal() { document.getElementById('incidentModal').style.display = 'none'; }

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
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
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
    return "XSS Command Center Running. Go to /dashboard"

@app.route("/dashboard")
def dashboard():
    return render_template_string(DASH_HTML)

@app.route("/api/findings")
def api_findings():
    return jsonify(get_findings())

@app.route("/api/clear", methods=["POST"])
def clear_findings():
    with open(FINDINGS_FILE, "w") as f:
        json.dump([], f)
    return jsonify({"status": "cleared"})

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True) or {}
    text = data.get("text", "")
    source_id = data.get("source_id", "API")
    
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
    elif "onload=" in lower_text or "onerror=" in lower_text or "onclick=" in lower_text:
        verdict = "BLOCK"
        attack_type = "Event Handler Injection"
        reason = "rule:event_handler"
        severity = "Medium"

    if verdict in ["BLOCK", "FLAG"]:
        save_finding(summary=text, attack_type=attack_type, reason=reason, severity=severity, source_id=source_id)

    return jsonify({
        "verdict": verdict,
        "attack_type": attack_type,
        "reason": reason,
        "severity": severity
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)