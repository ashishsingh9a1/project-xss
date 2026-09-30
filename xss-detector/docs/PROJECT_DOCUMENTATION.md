# XSS Attack Detection: Project Documentation

**Project ID:** P_211 (Cyber sheet, HCL project list)
**Title:** Hybrid XSS Detection Using Rule-Based and Anomaly Detection Techniques
**Duration:** 5 weeks
**Author:** Lord (B.Tech CSE, 3rd year, ABES Engineering College, Ghaziabad; AKTU)

---

## 1. Overview

### 1.1 Problem statement
Implement a detection mechanism to analyze and detect the possibilities of malicious script injection risk in user input fields.

### 1.2 Objectives
- Detect XSS payloads in text submitted through input fields.
- Build a rule-based detector as a working baseline for known attack patterns.
- Add an anomaly detector, trained only on benign input, to catch input that matches no known rule but is statistically unusual — including attack styles the rule engine was never taught.
- Combine both into a hybrid verdict (BLOCK / FLAG / ALLOW), each carrying an attack type and a severity rating.
- Log every BLOCK/FLAG as an incident, with a source identifier and the input field it targeted, so the output reads as an incident record rather than a list of filtered strings.
- Report honest evaluation numbers for both detectors, including their tradeoffs.

### 1.3 Scope
In scope: detecting XSS in text input, evaluation, and a local demo.
Out of scope: fixing vulnerable applications, attacking any real system, production deployment, and any reverse-proxy/firewall component (out of scope per instructor guidance — this project is a detector, not a WAF).

### 1.4 No supervised classifier
This project deliberately does not use a supervised ML classifier trained on labelled attack examples. Attack type is derived from which regex rule fired (for rule-based hits), or labelled "Unclassified (statistical anomaly)" for anomaly-only hits, since those by definition matched no known category. This keeps the system's two detection paths conceptually distinct: rules encode *known* patterns, and the anomaly detector generalizes to *unknown* ones, without a black-box classifier blurring the two.

---

## 2. System Design

```
User input (with source_id + target_field)
   |
   v
[1] Rule engine (regex)  --------+
   |                             |
[2] Anomaly detector             |
   (IsolationForest,             |
    trained on benign            |
    input only)      ------------+
   |                             |
   v                             v
[3] Decision layer: rule hit -> BLOCK
                     anomaly-only hit -> FLAG
                     neither -> ALLOW
   |
   v
[4] Attack type + severity assigned
   |
   v
[5] Incident logged (SQLite): source_id, target_field,
    raw_input, verdict, attack_type, severity, anomaly_score
```

### Key design decisions
- **Rules give explainability.** A BLOCK from a rule hit names exactly which pattern fired.
- **Anomaly detection generalizes.** Trained only on benign text, it flags anything statistically unusual — including payloads with no matching rule — without needing labelled attack examples.
- **Incident, not just a filter hit.** Every logged record carries a source identifier (stand-in for a client IP or session ID) and the target field, so it reads like a security log entry: who, where, what, how severe.
- **Severity over a single label.** BLOCK/FLAG alone doesn't say how dangerous something is; the severity rubric (Section 6) does.

---

## 3. Operating Systems and Environment

| Item | Details |
|---|---|
| Development OS | Windows 10/11, macOS, or Linux (Ubuntu or similar); the project is not OS-specific |
| Development OS used by author | _fill in: e.g. Windows 11_ |
| Container OS (DVWA) | Debian-based Linux inside the `vulnerables/web-dvwa` Docker image, managed by Docker |
| Windows requirement | WSL2 enabled (needed by Docker Desktop) |

### Hardware
Any standard laptop, 4 to 8 GB RAM. No GPU is needed — IsolationForest and the regex engine are both lightweight.

---

## 4. Tools and Technologies

### 4.1 Language and standard library
| Tool | Purpose |
|---|---|
| Python 3 | All detection and pipeline logic |
| `re` | Regex rules |
| `csv`, `pathlib` | Dataset creation and file handling |
| `sqlite3` | Incident log storage |
| `math`, `collections.Counter` | Feature extraction (entropy, character stats) for the anomaly detector |

### 4.2 Machine learning (anomaly detection only)
| Tool | Purpose |
|---|---|
| scikit-learn | `IsolationForest`, trained only on benign samples |
| numpy | Feature vectors for the model |
| joblib | Saving and loading the trained anomaly model |

### 4.3 Web app and demo (planned, Week 4)
| Tool | Purpose |
|---|---|
| Flask | Demo page/API for submitting input and viewing the verdict |
| DVWA | Intentionally vulnerable web app used as the test target |
| Docker Desktop | Runs DVWA locally |

### 4.4 Development and delivery
| Tool | Purpose |
|---|---|
| VS Code | Code editor |
| Git and GitHub | Version control and a public repository |

---

## 5. Setup Instructions

### 5.1 Install dependencies
```bash
pip install -r requirements.txt
```

### 5.2 Run the pipeline so far
```bash
python src/build_dataset.py          # creates data/xss_dataset.csv
python src/rule_based_detector.py    # evaluates the regex detector
python src/anomaly_detector.py train # trains IsolationForest on benign samples only
python src/anomaly_detector.py       # evaluates the anomaly detector
python src/detector.py               # runs the full hybrid pipeline + logs incidents
python src/evidence_log.py           # standalone incident-log demo
```

### 5.3 Run DVWA (demo target, Week 4)
```bash
docker run --rm -it -p 8080:80 vulnerables/web-dvwa
```
Log in with `admin` / `password`, click **Create / Reset Database**, then set **DVWA Security** to **Low** before testing the XSS pages.

**Safety:** DVWA is intentionally vulnerable. Run it only locally and never expose it to the internet or a shared network.

---

## 6. Attack Type and Severity Rubric

**Attack type** comes from whichever detection path fired:

| Source | Attack type label |
|---|---|
| Rule: `script_tag` | Script tag injection |
| Rule: `event_handler` | Event handler injection |
| Rule: `javascript_uri` | javascript: URI injection |
| Rule: `iframe_or_object` | Embedded frame/object injection |
| Rule: `svg_or_img_vector` | SVG/IMG vector injection |
| Rule: `html_entity_encoded` / `url_encoded_script` | Encoded/obfuscated payload |
| Rule: `eval_or_document` | Script execution / data access (eval, cookie, fetch) |
| Anomaly only (no rule matched) | Unclassified (statistical anomaly) |

**Severity:**

| Severity | Condition |
|---|---|
| High | An exfiltration-capable pattern matched (`eval`, `document.cookie`, `fetch`), or anomaly score below -0.10 |
| Medium | An execution pattern matched with no confirmed exfiltration, or anomaly score between -0.10 and -0.03 |
| Low | Only an encoding-related pattern matched, or anomaly score above -0.03 |

These thresholds are a starting rubric from the small starter dataset and will be re-tuned once the dataset is expanded.

---

## 7. Project Structure

```
xss-detector/
├── data/            xss_dataset.csv, incidents.db
├── models/          anomaly_model.joblib
├── src/
│   ├── build_dataset.py          [done]
│   ├── rule_based_detector.py    [done]
│   ├── features.py               [done]
│   ├── anomaly_detector.py       [done]
│   ├── evidence_log.py           [done]
│   ├── detector.py               [done: hybrid pipeline]
│   └── app.py                    [planned: Flask]
├── docs/
│   └── PROJECT_DOCUMENTATION.md
├── requirements.txt
└── README.md
```

---

## 8. Implementation Status

| Phase | Deliverable | Status |
|---|---|---|
| Dataset (starter, 60 rows) | `build_dataset.py` | Done; needs expansion to 1,000+ |
| Rule-based detector | `rule_based_detector.py` | Done |
| Feature extraction | `features.py` | Done |
| Anomaly detector | `anomaly_detector.py` | Done |
| Incident log (source_id, target_field) | `evidence_log.py` | Done |
| Hybrid pipeline (verdict, attack type, severity) | `detector.py` | Done |
| Flask demo page | `app.py` | Planned (Week 4) |
| DVWA integration | — | Planned (Week 4) |
| Expanded dataset + held-out evaluation | — | Planned (Week 5) |
| Final write-up | — | Planned (Week 5) |

---

## 9. Results So Far

**Rule-based detector**, on the 60-row starter dataset:

| Metric | Value |
|---|---|
| Accuracy | 98.33% |
| Precision | 100.00% |
| Recall | 96.67% |
| TP / FP / TN / FN | 29 / 0 / 30 / 1 |

**Known miss:** `';alert(String.fromCharCode(88,83,83))//` — a JavaScript-context injection with no `<script>` tag or event handler.

**Anomaly detector** (IsolationForest, trained only on the 30 benign samples), evaluated against the full 60-row dataset:

| Metric | Value |
|---|---|
| Accuracy | 96.67% |
| Precision | 93.75% |
| Recall | 100.00% |
| TP / FP / TN / FN | 30 / 2 / 28 / 0 |

**Key finding:** the anomaly detector catches every malicious sample in the starter set, including the one the rule engine missed — without ever having seen a labelled attack example during training. The cost is 2 false positives on benign text. This precision/recall tradeoff between the two detectors is the central result of the hybrid design: rules are precise but blind to unknown patterns, and anomaly detection is broader but noisier.

**Caveat:** the dataset is small (60 rows), so these numbers are indicative only and will be re-measured on the expanded dataset with a held-out test set in Week 5.

---

## 10. Evaluation Plan

- Expand the dataset to 1,000+ labelled rows before final evaluation.
- Hold out a test set neither detector was tuned against.
- Report rules-only, anomaly-only, and hybrid results: accuracy, precision, recall, F1, and false-positive count.
- Perform error analysis on missed payloads and wrongly flagged benign inputs.
- Demonstrate the anomaly detector catching a payload style deliberately excluded from consideration by the rule engine, as the core "what makes this different" evidence for the demo.

---

## 11. Timeline (5 weeks)

| Week | Focus |
|---|---|
| 1 | Learn XSS, set up DVWA, build starter dataset |
| 2 | Rule-based detector |
| 3 | Feature extraction, anomaly detector, incident log, hybrid detector |
| 4 | Flask demo page, DVWA integration |
| 5 | Dataset expansion, held-out evaluation, final write-up, demo preparation |

**If time runs short:** cut the Flask page first and demo via the command-line script (`detector.py` already produces a clear incident log); protect the anomaly detector and hybrid pipeline.

---

## 12. Risks and Limitations

| Risk | Mitigation |
|---|---|
| Small dataset inflates scores | Expand data, evaluate on a held-out set, state dataset size openly |
| Anomaly detector's false positives on unusual-but-benign text | Include diverse benign text with special characters, code snippets, and symbols during training |
| DVWA setup takes too long | It is only the demo layer; the detector is evaluated without it |
| Payloads that evade both rules and anomaly detection | Document honestly in the final report; no detector is claimed to be complete |

Detection of this kind is one layer of defense. It does not replace output encoding, input validation, and Content Security Policy in a real application.

---

## 13. References

- OWASP: Cross Site Scripting (XSS) overview
- DVWA (Damn Vulnerable Web Application)
- scikit-learn documentation: `IsolationForest` and anomaly/outlier detection
- YouTube: *Web Hacking - XSS Basics with Python Automation* (Styx Show)
