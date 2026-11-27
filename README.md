# Sentinel ML — Network Flow Anomaly Detection

A final-year project demo showing how **unsupervised learning** and **robust statistics** can flag unusual network flow summaries without needing attack labels. The demo is offline and uses synthetic data; it does not capture, scan, or send network traffic.

## What it demonstrates

- **Isolation Forest** learns patterns in baseline flow summaries and scores observations that sit apart from that baseline.
- **Modified z-scores** use the baseline median and median absolute deviation (MAD) to identify unusually large or small feature values.
- An alert is raised when either method flags a flow. The alert includes a score, severity, and unusual feature names to help an analyst review it.
- The demo includes ordinary synthetic traffic plus several deliberately unusual flows. It does not attach attack labels to the model input.

## Run the synthetic demo

Requires Python 3.10+.

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
python detector.py --demo
```

The script creates `demo_flows.csv` and `alerts.json` in the current folder and prints the alerts. No packet capture or administrator permissions are needed.

## Score your own flow-summary CSV

Use one CSV of known ordinary flows as the baseline and a second CSV as the new observations. Required columns:

```text
flow_id,timestamp,duration_ms,bytes_sent,bytes_received,packets,destination_port,protocol
```

Then run:

```bash
python detector.py --baseline baseline.csv --input new_flows.csv --output alerts.json
```

Use only traffic summaries you are allowed to analyze, and remove personal or identifying information before sharing a dataset. This project intentionally works with flow summaries, not raw packet payloads.

## Method in presentation terms

1. **Collect flow summaries:** duration, byte counts, packet count, destination port, and protocol.
2. **Learn normal behavior:** fit a scaler and Isolation Forest using a baseline that represents ordinary activity.
3. **Check statistical outliers:** compare each observation to the baseline using median/MAD modified z-scores.
4. **Alert for review:** if either method detects an outlier, show its severity, score, and the features that looked unusual.
5. **Tune with evidence:** review false alarms and missed events, adjust the threshold, and test on a separate labeled benchmark when available.

### Why it can help with previously unseen attacks

Because the model is not trained only on named attack signatures, it can flag activity that differs from the learned baseline even when the exact attack label is unknown. This is a useful detection signal, not proof that an attack occurred. Subtle attacks that resemble ordinary activity may be missed, and normal changes in traffic can produce false alerts.

## Evaluation plan

For a stronger research presentation, evaluate with a publicly documented, permission-compatible labeled flow dataset. Keep training and test periods separate. Report:

- precision, recall, F1 score, and false-positive rate;
- detection delay and alert volume per hour;
- results by attack family and by traffic type;
- the effect of contamination and MAD thresholds;
- limitations caused by class imbalance, data drift, and baseline quality.

Do not report demo metrics as real-world detection performance. Synthetic examples prove that the code path works, not that it can detect real attacks.

## Suggested presentation outline

1. Problem: signature-based systems may not recognize new behavior.
2. Aim: surface unusual flow patterns for analyst review.
3. Data and features: summarize what each CSV field means.
4. Method: explain Isolation Forest and median/MAD in plain language.
5. Demonstration: run the offline demo and inspect generated alerts.
6. Evaluation: describe a labeled benchmark and metrics you would use.
7. Limits and next steps: false positives, drift, threshold tuning, privacy, and analyst review.

## Project structure\n\n- `detector.py` — feature preparation, Isolation Forest, statistical scoring, and command-line demo.\n- `requirements.txt` — Python dependencies.\n- `index.html`, `styles.css`, and `app.js` — responsive dashboard demo.\n- `PRESENTATION.md` — speaker notes and likely questions.\n\nThe dashboard uses illustrative sample metrics. It is not connected to live traffic or to the Python detector. The detector works with synthetic data in demo mode or authorized flow-summary CSV files.\n