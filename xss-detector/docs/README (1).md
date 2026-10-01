# XSS Attack Detection

A hybrid detection system for Cross-Site Scripting (XSS) payloads in user
input, combining:

- **Rule-based detection** (regex) for known attack patterns
- **Anomaly detection** (IsolationForest, trained on benign input only) to
  catch statistically unusual input that matches no known rule

No supervised classifier is used. Attack type is derived from which rule
fired (for rule-based hits) or labelled "Unclassified (statistical
anomaly)" (for anomaly-only hits, which by definition matched no known
pattern). Every BLOCK/FLAG is logged as an incident with a source
identifier and the target field, so the log reads as an incident report,
not just a list of filtered strings.

## Project structure

```
xss-detector/
├── data/            xss_dataset.csv (generated), incidents.db (evidence log), findings.json (dashboard)
├── src/
│   ├── build_dataset.py       labeled malicious/benign dataset
│   ├── rule_based_detector.py regex-based detector
│   ├── features.py            numeric features for the anomaly detector
│   ├── anomaly_detector.py    IsolationForest, trained on benign data only
│   ├── evidence_log.py        SQLite incident log (source_id, target_field, ...)
│   ├── detector.py            hybrid pipeline: rules + anomaly -> verdict
│   ├── payloads.py            Day 2 test inputs (normal / rule_match / no_rule)
│   ├── run_day2_demo.py       Day 2: logs the three inputs to a CSV
│   ├── day2_task.py           Day 2: attack-stage deliverables
│   ├── day3_task.py           Day 3: detection-stage deliverables
│   ├── app.py                 Flask dashboard + /scan API (calls detector.detect)
│   ├── build_dataset_v2.py    Day 4: 1,799 unique rows with train/val/test/stress splits
│   ├── evaluate.py            Day 4: held-out evaluation (rules vs anomaly vs hybrid)
│   └── dvwa_integration.py    Day 4: detector verdicts vs real DVWA reflection
├── models/          anomaly_model.joblib (after training)
├── evidence/        Day 2 and Day 3 proof files and screenshots
├── docs/            PROJECT_DOCUMENTATION.md, FINAL_REPORT.md, evaluation_results.md
└── README.md
```

## Setup

```bash
pip install -r requirements.txt
```

## Roadmap (4 days)

- [x] Day 1: tools installation (Python, dependencies, Docker Desktop and DVWA, VS Code, Git)
- [x] Day 2: attack part: DVWA at Low security, XSS payloads, three inputs logged with correct verdicts
- [x] Day 3: the detector and the Flask dashboard: dataset, rule-based detector (98.3% accuracy, 100% precision, 96.7% recall on starter set), features + IsolationForest anomaly detector (96.7% accuracy, 93.75% precision, 100% recall), incident log, hybrid `detector.py`, benign-only training, negative control, Flask dashboard wired to the real detector
- [x] Day 4: dataset expansion (1,799 unique rows), held-out evaluation, final report
- [ ] Day 4 (remaining): run `dvwa_integration.py` against your real DVWA and save the screenshot/CSV

## Usage so far

```bash
python src/build_dataset.py
```
Generates `data/xss_dataset.csv` — 60 labeled rows (30 malicious XSS
payloads, 30 benign everyday text samples). This is a starter set; expand
it before the Day 4 evaluation.

```bash
python src/rule_based_detector.py
```
Evaluates the regex-based detector. Current result: 98.3% accuracy, 100%
precision, 96.7% recall. One known miss: JS-context payloads with no
`<script>` tag or event handler (e.g.
`';alert(String.fromCharCode(88,83,83))//`).

```bash
python src/anomaly_detector.py train   # trains on benign samples only
python src/anomaly_detector.py         # evaluates against the full dataset
```
Current result: 96.7% accuracy, 93.75% precision, 100% recall — it catches
every malicious sample in the starter set, **including the one the regex
rules missed**, at the cost of 2 false positives on benign text. That
precision/recall tradeoff versus the rule engine is the key finding to
report: rules are precise but blind to unknown patterns; anomaly detection
is broader but noisier.

```bash
python src/detector.py
```
Runs the full hybrid pipeline on a few simulated submissions (each with a
source id and target field) and prints the incident log. A rule hit is
always BLOCK; an anomaly-only hit is FLAG; both get an attack type and a
Low/Medium/High severity, and are written to `data/incidents.db`.

```bash
python src/evidence_log.py
```
Standalone demo of the incident log format.

## Severity rubric

- **High** — matched an exfiltration-capable pattern (`eval`,
  `document.cookie`, `fetch`) or an anomaly score below -0.10
- **Medium** — matched an execution pattern (script tag, event handler,
  `javascript:` URI, iframe/object, SVG/IMG vector) with no confirmed
  exfiltration, or an anomaly score between -0.10 and -0.03
- **Low** — matched only an encoding-related pattern, or an anomaly score
  above -0.03

Thresholds are a starting rubric from the small starter dataset and will
be re-tuned once the dataset is expanded on Day 4.

## Development log (day by day)

| Day | Date | Work done | Proof |
|---|---|---|---|
| Day 1 | Mon 28 Sep 2026 *(inferred, please confirm)* | Tools installation only: Python 3 and `pip install -r requirements.txt` (flask, joblib, numpy, pandas, scikit-learn), Docker Desktop with WSL2, the DVWA image, VS Code, Git/GitHub | `requirements.txt` |
| Day 2 | Tue 29 Sep 2026 *(inferred)* | Attack part: DVWA running with security set to Low; XSS payloads tried (script and SVG); three inputs sent through the hybrid detector: normal -> ALLOW, `<script>alert(1)</script>` -> BLOCK (`script_tag`), `';alert(String.fromCharCode(88,83,83))//` -> FLAG (anomaly, score -0.077). The suggested `<svg onload=alert(1)>` was swapped out because this rule set already blocks it | `evidence/day2_*.png`, `day2_payloads.txt`, `day2_log.csv`, `day2_verdicts.txt` |
| Day 3 | Wed 30 Sep - Thu 1 Oct 2026 | **Detector:** starter dataset, 8 regex rules, 7 anomaly features, IsolationForest trained on normal input only (`random_state=42`), SQLite incident log, hybrid `detector.py` (BLOCK / FLAG / ALLOW with attack type and severity); all three verdicts re-checked; negative control: `Meeting at 5pm with the team` -> ALLOW (score +0.116). **Dashboard:** a generated `app.py` had reimplemented detection with two substring checks and bypassed the real pipeline (the no-rule payload would have been ALLOWed). Rewired `/scan` to `detector.detect()` with the model loaded once at startup, kept the UI, escaped all table fields, added `target_field`, fixed `/api/clear`, and verified end to end | `evidence/day3_*`, `models/anomaly_model.joblib`, `src/detector.py`, `src/app.py` |
| Day 4 | Fri 2 Oct 2026 *(planned)* | Dataset rebuilt as 1,799 unique rows (the old 1,100 rows came from 34 strings plus a counter); anomaly model fitted on benign train rows only, contamination chosen on a validation split; held-out evaluation of rules / anomaly / hybrid on a test split and a stress split (unseen benign categories and attack families); DVWA integration script; final report. Headline: hybrid recall 100% on test and 98.7% on stress, but 82 false positives on 180 unseen benign inputs | `docs/FINAL_REPORT.md`, `docs/evaluation_results.md`, `evidence/day4_dvwa_integration.csv` *(after you run it)* |

## Dashboard (Flask)

```bash
pip install -r requirements.txt
python src/app.py          # http://localhost:5000/dashboard
```

Features: payload sandbox, stat cards, search and severity filters, incident modal, CSV export,
clear logs, 5-second auto-refresh. `POST /scan` takes
`{"text": "...", "source_id": "...", "target_field": "..."}` and returns the full detector result
(`verdict`, `attack_type`, `severity`, `reason`, `matched_rules`, `anomaly_score`). BLOCK and FLAG results
are stored in `data/findings.json` (last 100) and in the pipeline's own incident log. If the detector
fails to load, `/scan` returns a 500 rather than falling back to weaker rules.

Checked on Day 4 through the real pipeline:

| Input | Verdict | Type / severity |
|---|---|---|
| `<img src=x onerror=alert(1)>` | BLOCK | Event handler injection / Medium |
| `<script>fetch(...document.cookie)</script>` | BLOCK | Script execution / data access / High |
| `';alert(String.fromCharCode(88,83,83))//` | FLAG | Unclassified (statistical anomaly) / Low |
| `Great article` | FLAG (false positive) | Unclassified / Medium |

## Known issues

- **False positives:** the old model FLAGged short benign text such as `Great article`; the Day 4 retrain (`python src/evaluate.py --save-model`) fixes that, but unseen benign types (URLs, math, HTML snippets) are still over-flagged (see `docs/FINAL_REPORT.md`).
- **Model version warning:** `anomaly_model.joblib` was saved with scikit-learn 1.9.1. Loading it with an older version prints a warning. Use the same version (or retrain) on every machine.
- Dashboard runs with Flask debug mode and binds to `0.0.0.0`; turn both off outside local use.

## Day 4 commands

```bash
python src/build_dataset_v2.py        # data/xss_dataset_v2.csv
python src/evaluate.py --save-model   # docs/evaluation_results.md + retrained model
python src/dvwa_integration.py        # with DVWA running on localhost:8080
```
