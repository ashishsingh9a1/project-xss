"""
evidence_log.py

Stores every BLOCK/FLAG as an incident record in SQLite -- not just "this
text was bad", but WHO/WHERE it came from, so the log reads the way a
real security log does: source, target, time, what happened, how sure
we are.

Each incident carries a source identifier (a stand-in for a client IP /
session ID, since this project doesn't sit behind a real web server) and
the field the input was submitted through (e.g. "comment", "search",
"username"). That's what turns "flagged text" into "an incident from
X targeting Y".
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "incidents.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    source_id       TEXT NOT NULL,   -- stand-in for client IP / session ID
    target_field    TEXT NOT NULL,   -- which input field this came through
    raw_input       TEXT NOT NULL,
    verdict         TEXT NOT NULL,   -- BLOCK / FLAG
    reason          TEXT NOT NULL,   -- matched_rule / anomaly / both
    attack_type     TEXT NOT NULL,
    severity        TEXT NOT NULL,   -- Low / Medium / High
    anomaly_score   REAL
);
"""


def init_db():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(SCHEMA)
    conn.commit()
    return conn


def log_incident(
    source_id: str,
    target_field: str,
    raw_input: str,
    verdict: str,
    reason: str,
    attack_type: str,
    severity: str,
    anomaly_score: float = None,
    conn=None,
):
    """Write one incident record. Only call this for BLOCK/FLAG verdicts --
    ALLOW is normal traffic and isn't an incident."""
    own_conn = conn is None
    if own_conn:
        conn = init_db()

    conn.execute(
        """
        INSERT INTO incidents
            (timestamp, source_id, target_field, raw_input, verdict,
             reason, attack_type, severity, anomaly_score)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now(timezone.utc).isoformat(),
            source_id,
            target_field,
            raw_input,
            verdict,
            reason,
            attack_type,
            severity,
            anomaly_score,
        ),
    )
    conn.commit()
    if own_conn:
        conn.close()


def list_incidents(limit: int = 50, conn=None):
    own_conn = conn is None
    if own_conn:
        conn = init_db()
    cur = conn.execute(
        """
        SELECT id, timestamp, source_id, target_field, verdict,
               attack_type, severity, anomaly_score, raw_input, reason
        FROM incidents
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cur.fetchall()
    if own_conn:
        conn.close()
    return rows


def _reason_label(reason: str) -> str:
    """Turn the stored reason code into a short human phrase for display.

    Reflects what actually determined the verdict -- a rule hit always
    decides BLOCK on its own, so it's labelled "rule match" even if the
    anomaly detector separately agreed (that score is still stored in
    anomaly_score, just not cited as the cause)."""
    if reason == "anomaly_only":
        return "anomaly detected"
    if reason.startswith("rule:"):
        return "rule match"
    return reason


_VERDICT_LABEL = {"BLOCK": "Blocked", "FLAG": "Flagged"}


def print_incident_blocks(limit: int = 50):
    """
    Print each incident as a labelled block:

        time:        04:40:17
        source_ip:   198.51.100.23
        input:       <img src=x onerror=alert(1)>
        attack_type: Event handler injection (XSS)
        severity:    Medium
        reason:      Blocked (rule match)

    This is the report-style view for a demo or write-up. Use
    print_incident_lines() for the compact comma-separated view, or
    print_incidents() for the full table with id/field/score.
    """
    rows = list_incidents(limit)
    if not rows:
        print("No incidents logged yet.")
        return
    for r in rows:
        id_, ts, source, field, verdict, atk, sev, score, raw, reason = r
        time_only = ts[11:19] if len(ts) >= 19 else ts
        verdict_label = _VERDICT_LABEL.get(verdict, verdict)
        print(f"time:        {time_only}")
        print(f"source_ip:   {source}")
        print(f"input:       {raw}")
        print(f"attack_type: {atk} (XSS)")
        print(f"severity:    {sev}")
        print(f"reason:      {verdict_label} ({_reason_label(reason)})")
        print()


def print_incident_lines(limit: int = 50):
    """
    Print each incident as one comma-separated line:
        time, source_ip, input, attack_type, severity, reason

    e.g.  14:02:11, 10.0.0.5, <script>alert(1)</script>, Script tag injection, Medium, rule match

    This is the compact, incident-report style view -- use print_incidents()
    below for the full table (includes id, field, anomaly score).
    """
    rows = list_incidents(limit)
    if not rows:
        print("No incidents logged yet.")
        return
    print("time, source_ip, input, attack_type, severity, reason")
    for r in rows:
        id_, ts, source, field, verdict, atk, sev, score, raw, reason = r
        time_only = ts[11:19] if len(ts) >= 19 else ts  # HH:MM:SS from the ISO timestamp
        print(f"{time_only}, {source}, {raw}, {atk}, {sev}, {_reason_label(reason)}")


def print_incidents(limit: int = 50):
    rows = list_incidents(limit)
    if not rows:
        print("No incidents logged yet.")
        return
    print(f"{'ID':<4} {'TIME':<20} {'SOURCE':<14} {'FIELD':<10} {'VERDICT':<7} "
          f"{'ATTACK TYPE':<22} {'SEV':<7} {'SCORE':<8} INPUT")
    for r in rows:
        id_, ts, source, field, verdict, atk, sev, score, raw, reason = r
        score_str = f"{score:+.3f}" if score is not None else "-"
        print(f"{id_:<4} {ts[:19]:<20} {source:<14} {field:<10} {verdict:<7} "
              f"{atk:<22} {sev:<7} {score_str:<8} {raw[:40]!r}")


if __name__ == "__main__":
    # Demo: log a couple of sample incidents and print the table.
    conn = init_db()
    log_incident(
        source_id="198.51.100.23",
        target_field="comment",
        raw_input="<img src=x onerror=alert(1)>",
        verdict="BLOCK",
        reason="rule:event_handler,svg_or_img_vector",
        attack_type="Event handler injection",
        severity="Medium",
        conn=conn,
    )
    log_incident(
        source_id="192.0.2.55",
        target_field="search",
        raw_input="';alert(String.fromCharCode(88,83,83))//",
        verdict="FLAG",
        reason="anomaly_only",
        attack_type="Unclassified (statistical anomaly)",
        severity="Medium",
        anomaly_score=-0.077,
        conn=conn,
    )
    conn.close()

    print("\nIncident log:\n")
    print_incident_blocks()
