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
├── data/            xss_dataset.csv (generated), incidents.db (evidence log)
├── src/
│   ├── build_dataset.py       labeled malicious/benign dataset
│   ├── rule_based_detector.py regex-based detector
│   ├── features.py            numeric features for the anomaly detector
│   ├── anomaly_detector.py    IsolationForest, trained on benign data only
│   ├── evidence_log.py        SQLite incident log (source_id, target_field, ...)
│   └── detector.py            hybrid pipeline: rules + anomaly -> verdict
├── models/          anomaly_model.joblib (after training)
├── docs/            PROJECT_DOCUMENTATION.md
└── README.md
```

## Setup

```bash
pip install -r requirements.txt
```

## Roadmap (matches the 5-week plan)

- [x] Week 1: `src/build_dataset.py` — labeled dataset of malicious/benign samples
- [x] Week 2: `src/rule_based_detector.py` — regex-based detector — 98.3% accuracy, 100% precision, 96.7% recall on starter set
- [x] Week 3: `src/features.py` + `src/anomaly_detector.py` — IsolationForest trained on benign-only data — 96.7% accuracy, 93.75% precision, 100% recall on starter set
- [x] Week 3: `src/evidence_log.py` — SQLite incident log with source identifier + target field
- [x] Week 3: `src/detector.py` — hybrid pipeline combining rules + anomaly detection into one verdict, attack type and severity
- [ ] Week 4: Flask demo page, DVWA integration
- [ ] Week 5: expand dataset (1,000+ rows), held-out evaluation, adversarial-style test set, final write-up

## Usage so far

```bash
python src/build_dataset.py
```
Generates `data/xss_dataset.csv` — 60 labeled rows (30 malicious XSS
payloads, 30 benign everyday text samples). This is a starter set; expand
it before the Week 5 evaluation.

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
be re-tuned once the dataset is expanded in Week 5.
