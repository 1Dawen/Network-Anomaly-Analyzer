# Technical review and limitations

This note documents findings from the original source code, presentation, report and notebook, and describes which issues the reorganized version addresses. It is not an independent security efficacy evaluation.

## What was present in the original implementation

- Data conversion, date extraction and hand-crafted activity heuristics.
- Isolation Forest with `n_estimators=100`, `contamination=0.05` and `random_state=0`.
- Per-record weighted risk scores and mean-risk grouping by source IP.
- Low/medium/high risk thresholds and a CSV export.
- A Streamlit app accepting firewall CSV logs.
- Exploratory KMeans clustering, PCA plots, anomaly-by-hour visualizations and manually named roles in the notebook.

The original training dataset was large but has since been lost. The accompanying presentation shows plots, but the underlying records, ground-truth attack labels, validation design, confusion matrix, and reproducible measurements are unavailable.

## Problems and how the maintained version differs

| Original concern | Change / interpretation |
| --- | --- |
| `train.py` fitted `RobustScaler`, but inference fitted a **new scaler** on uploaded data before predicting with the saved forest. | Wrap fitted imputation, scaling and Isolation Forest in a single scikit-learn `Pipeline`, then save the whole object. |
| `MinMaxScaler` was refitted for the byte ratio and for risk scores on each uploaded batch. | Use a fixed clipped byte-ratio scale and the fixed weighted-sum range. This avoids scores changing merely because the batch composition changes. |
| The notebook used `Unsual` where it earlier produced `Unusual`. | Fix the typo so the weekend rule works as intended. |
| The original notebook defined rule features that the standalone training script expected to already exist in the input CSV. | Generate all required features from raw CSV input in one preprocessing function. |
| Model path and data path assumed a local `DATA/` folder and provided model file. | Add CLI training with an explicit input path, documented schema and a reproducible synthetic sample. |
| Some notebook KMeans clusters were assigned job labels such as Sales/Developer without verified role labels. | Do not include those labels in the maintained app. KMeans clusters cannot establish a person's job role without independent evidence. |
| No tests provided. | Add tests for preprocessing, time rules, batch-independent risk scores, consistent inference, aggregation and scoring thresholds. |

These changes affect numeric results compared with the original notebook. The generated demo values **are not a reproduction of the historical results**.

## Main analytical limitations

1. **Unsupervised is not supervised detection.** Isolation Forest measures departures from the learned data distribution. `contamination=0.05` specifies an assumed outlier fraction for training. It is not a hypothesis-test p-value, statistical significance level, or measured detection accuracy.
2. **Risk weights are subjective.** The 0.2/0.1/0.4 weights and the 0.4/0.7 tier thresholds were not calibrated against observed security outcomes.
3. **Rules assume a work schedule.** Night and weekend activity can be normal. Expected behavior can differ across teams, shifts, time zones and services.
4. **Features are weak security proxies.** Received byte thresholds and a port >=1024 indicator may identify ordinary traffic. The thresholds appear to be exploratory and should not be used as a security policy.
5. **Input assumptions matter.** This demo expects consistently named columns, local naive timestamps and consistent duration units. It rejects malformed timestamps and does not infer time zones.
6. **Mean IP scores can hide isolated incidents.** A large number of normal events will dilute a small set of suspicious events; the app also shows anomaly rates.
7. **Synthetic training is not real-world validation.** The demo dataset includes deliberately injected unusual records to demonstrate the interface. A model trained on this synthetic data should not be deployed to production logs.
8. **No reproducible held-out evaluation.** The original dataset is lost, and the available materials do not establish precision, recall, F1, false-positive rate or generalization performance. These would require representative labeled incidents, analyst review and time-based testing.
9. **New data sources require review.** Real datasets may encode firewall actions differently and may have missing fields, unstable source identities, CGNAT or device-generated logs. Retraining should be conducted under a controlled evaluation process.
10. **Serialization safety.** Only use trusted `joblib` models. Do not load third-party `.pkl`/`.joblib` files without verifying provenance.

## Reproduction scope

`python train.py --data data/sample_firewall_logs.csv` trains an Isolation Forest on the synthetic example and creates a fresh model artifact. `python -m pytest -q` checks defined invariants. This verifies *software behavior*, not the scientific accuracy of the original results.

## Original dataset and public release

The original dataset is no longer available, so the historical analysis cannot be rerun here. This repository includes only generated synthetic example records.

This public version omits the original report and presentation because they contain identifiers and network-related figures.
