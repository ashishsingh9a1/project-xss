# Held-out evaluation results

Dataset: `data/xss_dataset_v2.csv`, 1799 unique rows. Anomaly model trained on **594 benign train rows only**; contamination chosen on the validation split (**0.01**). Rules were not tuned on this data. "Detected" for the hybrid means BLOCK or FLAG.

Contamination tuning on validation split:

| contamination | hybrid F1 | false positives |
|---|---|---|
| 0.01 | 100.0% | 0 |
| 0.02 | 99.5% | 1 |
| 0.03 | 99.0% | 2 |
| 0.05 | 97.5% | 5 |
| 0.08 | 93.2% | 14 |
| 0.1 | 91.9% | 17 |

## Test split (in-distribution, never used for tuning)

295 rows: 198 benign, 97 malicious.

| Detector | Accuracy | Precision | Recall | F1 | False pos. | False neg. | TP/FP/TN/FN |
|---|---|---|---|---|---|---|---|
| Rules only | 94.6% | 100.0% | 83.5% | 91.0% | 0 | 16 | 81/0/198/16 |
| Anomaly only | 99.0% | 99.0% | 97.9% | 98.4% | 1 | 2 | 95/1/197/2 |
| **Hybrid (rules + anomaly)** | 99.7% | 99.0% | 100.0% | 99.5% | 1 | 0 | 97/1/197/0 |

Recall by attack family (% detected):

| Family | n | Rules | Anomaly | Hybrid |
|---|---|---|---|---|
| encoded | 7 | 100.0% | 100.0% | 100.0% |
| event_common | 16 | 100.0% | 93.8% | 100.0% |
| exfil_dom | 15 | 100.0% | 100.0% | 100.0% |
| frame_object | 6 | 100.0% | 100.0% | 100.0% |
| js_context | 16 | 0.0% | 100.0% | 100.0% |
| js_uri | 8 | 100.0% | 87.5% | 100.0% |
| mixed_obfuscated | 16 | 100.0% | 100.0% | 100.0% |
| script_tag | 13 | 100.0% | 100.0% | 100.0% |

False positives by benign category (hybrid):

| Category | False positives | Rows |
|---|---|---|
| product | 1 | 22 |

Examples of wrongly flagged benign input:

- `SKU-7776-DY`

Hybrid verdict mix on this split: 81 BLOCK (rule hit), 17 FLAG (anomaly only).

Attacks missed by the hybrid (0 total), examples:

None.

## Stress split (unseen benign categories and unseen attack families)

330 rows: 180 benign, 150 malicious.

| Detector | Accuracy | Precision | Recall | F1 | False pos. | False neg. | TP/FP/TN/FN |
|---|---|---|---|---|---|---|---|
| Rules only | 83.6% | 100.0% | 64.0% | 78.0% | 0 | 54 | 96/0/180/54 |
| Anomaly only | 73.3% | 63.7% | 96.0% | 76.6% | 82 | 6 | 144/82/98/6 |
| **Hybrid (rules + anomaly)** | 74.5% | 64.3% | 98.7% | 77.9% | 82 | 2 | 148/82/98/2 |

Recall by attack family (% detected):

| Family | n | Rules | Anomaly | Hybrid |
|---|---|---|---|---|
| case_whitespace | 30 | 100.0% | 90.0% | 100.0% |
| data_uri | 30 | 96.7% | 100.0% | 100.0% |
| js_context_long | 30 | 40.0% | 96.7% | 100.0% |
| mutation_xss | 30 | 73.3% | 100.0% | 100.0% |
| rare_handler | 30 | 10.0% | 93.3% | 93.3% |

False positives by benign category (hybrid):

| Category | False positives | Rows |
|---|---|---|
| url_path | 30 | 30 |
| math | 25 | 30 |
| html_formatting | 16 | 30 |
| structured | 11 | 30 |

Examples of wrongly flagged benign input:

- `/var/www/python/index.html`
- `/var/www/machine_learning/index.html`
- `f(x) = x^2 + 4x - 7; f(1) = ?`
- `C:\Users\Amit\Documents\running_shoes.txt`
- `SELECT name FROM users WHERE id = 91;`
- `if x < 8 and y > 5 then z = x + y`

Hybrid verdict mix on this split: 96 BLOCK (rule hit), 134 FLAG (anomaly only).

Attacks missed by the hybrid (2 total), examples:

- `<div oncopy=confirm(1)>click`
- `<span oncopy=prompt(1)>x`
