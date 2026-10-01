# Hybrid XSS Detection Using Rule-Based and Anomaly Detection: Final Report

**Project ID:** P_211 | **Author:** Lord (B.Tech CSE, ABES Engineering College) | **Duration:** 4 days

## 1. Summary

The system detects XSS payloads in user input by combining a regex **rule engine** (known patterns) with an
**IsolationForest anomaly detector trained only on benign input**. A rule hit gives BLOCK, an anomaly-only hit gives
FLAG, otherwise ALLOW. Every BLOCK/FLAG carries an attack type and severity and is logged as an incident with a source
id and target field. A Flask dashboard shows the incidents live, and a DVWA script shows the detector in front of a
deliberately vulnerable app.

Main finding: the two detectors fail in different places. Rules are precise but blind to anything without a known
pattern; the anomaly detector catches those, but over-flags unusual-but-harmless text. The hybrid has the best recall
on both evaluation sets, and the cost is false positives on unfamiliar benign input (Section 4).

## 2. Method

| Component | Detail |
|---|---|
| Rules | 8 regex rules (script tag, event handler, `javascript:`, iframe/object/embed, SVG/IMG vector, HTML-entity and URL-encoded, eval/cookie/fetch) |
| Features | 7 statistical features (length, special-char ratio, tag count, entropy, digit ratio, uppercase ratio, longest word) |
| Anomaly model | IsolationForest, 200 trees, `random_state=42`, fitted on benign training rows only |
| Verdict | rule hit -> BLOCK; anomaly only -> FLAG; neither -> ALLOW |
| Severity | High: eval/cookie/fetch pattern or anomaly score < -0.10; Medium: execution pattern or score -0.10 to -0.03; Low: encoding only or score above -0.03 |

No supervised classifier is used. Attack type comes from which rule fired, or "Unclassified (statistical anomaly)".

## 3. Dataset and evaluation protocol

The original `build_dataset.py` made 1,100 rows from only 34 base strings with a counter appended, so splitting it
would leak near-duplicates. It was replaced by `build_dataset_v2.py`: **1,799 unique rows** (1,170 benign, 629
malicious), generated from templates with random fills and a fixed seed.

| Split | Rows | Purpose |
|---|---|---|
| train | 880 | Only the 594 benign rows are used, to fit the anomaly model |
| val | 294 | Choose the anomaly `contamination` (0.01 won) |
| test | 295 | In-distribution, untouched until the end |
| stress | 330 | Held out on purpose: 6 unseen benign categories (HTML formatting, code talk, math, URLs/paths, structured text, long paragraphs) and 5 unseen attack families (rare handlers, case/whitespace tricks, data: URIs, mutation XSS, long JS-context) |

Rules were not tuned on any of this data.

## 4. Results

**Test split (in-distribution)**

| Detector | Accuracy | Precision | Recall | F1 | FP | FN |
|---|---|---|---|---|---|---|
| Rules only | 94.6% | 100.0% | 83.5% | 91.0% | 0 | 16 |
| Anomaly only | 99.0% | 99.0% | 97.9% | 98.4% | 1 | 2 |
| **Hybrid** | 99.7% | 99.0% | 100.0% | 99.5% | 1 | 0 |

All 16 rule misses were the `js_context` family (payloads with no tag, like `';alert(1)//`): rules caught 0%, the
anomaly detector 100%.

**Stress split (unseen benign categories and attack families)**

| Detector | Accuracy | Precision | Recall | F1 | FP | FN |
|---|---|---|---|---|---|---|
| Rules only | 83.6% | 100.0% | 64.0% | 78.0% | 0 | 54 |
| Anomaly only | 73.3% | 63.7% | 96.0% | 76.6% | 82 | 6 |
| **Hybrid** | 74.5% | 64.3% | 98.7% | 77.9% | 82 | 2 |

Recall by unseen attack family (rules / anomaly / hybrid): rare handlers 10% / 93% / 93%; long JS-context 40% / 97% /
100%; mutation XSS 73% / 100% / 100%; case and whitespace tricks 100% / 90% / 100%; data: URIs 97% / 100% / 100%.

Full tables: `docs/evaluation_results.md` (regenerate with `python src/evaluate.py`).

## 5. Error analysis

- **Rule blind spots.** Rules miss attacks outside their 8 patterns: JS-context breakouts and handlers not on the
  list (`onclick`, `oncopy`, `onpageshow`, ...). The anomaly detector covers most of these.
- **Anomaly false positives.** On unseen benign categories it flagged 82 of 180 inputs: all 30 URL/path strings, 25 of
  30 math expressions, 16 of 30 HTML-formatting snippets and 11 of 30 structured strings. These look statistically
  "special-character heavy" like attacks, and the model never saw such benign text in training.
- **Remaining misses.** 2 attacks of 150 on the stress split (`<div oncopy=confirm(1)>click` and a near-identical one).
- **In-distribution accuracy is optimistic.** The data is generated from templates, so test accuracy of 99.7% mostly
  shows the model separates this synthetic data. The stress split is the more realistic estimate.

## 6. DVWA integration

`src/dvwa_integration.py` logs into a local DVWA (security Low), sends 9 inputs to the reflected-XSS page, and records
the detector verdict next to whether DVWA reflected the payload unescaped. Output: `evidence/day4_dvwa_integration.csv`.
The script was tested against a stand-in local server that mimics DVWA's login and reflection, and still needs to be
run against your real DVWA container to produce the final evidence.

## 7. Limitations

- Synthetic dataset; real traffic will differ. Numbers are indicative, not production estimates.
- Benign training text is narrow, so unusual harmless input (code, URLs, math) is over-flagged.
- Attack-type labels depend on the first matching rule; anomaly-only hits are "Unclassified" by design.
- Detection is one layer of defense and does not replace output encoding, input validation or CSP.

## 8. Future work

- Collect real benign input (comments, URLs, code snippets) and retrain; add those categories to the anomaly training data.
- Add rules for the missed handler families, or generalise the handler rule to `on\w+\s*=`.
- Re-tune severity thresholds on the larger data; evaluate on third-party XSS payload lists.

## 9. Reproduce

```bash
pip install -r requirements.txt
python src/build_dataset_v2.py          # data/xss_dataset_v2.csv
python src/evaluate.py --save-model     # results + retrained models/anomaly_model.joblib
python src/app.py                       # dashboard at http://localhost:5000/dashboard
python src/dvwa_integration.py          # needs DVWA running on localhost:8080
```
