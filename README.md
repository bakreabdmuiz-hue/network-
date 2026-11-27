# Sentinel ML — Network Flow Anomaly Detection

A student project demo that combines **unsupervised machine learning** and **robust statistics** to flag unusual network-flow summaries without needing attack labels. The demo runs offline with synthetic data. It does not capture, scan, or send network traffic.

## Run the demo on Windows

Install Python 3.10 or newer, then open PowerShell:

```powershell
git clone https://github.com/bakreabdmuiz-hue/network-.git
cd network-
py -m venv .venv
.\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt
.\\.venv\\Scripts\\python.exe detector.py --demo
```

The demo creates `demo_flows.csv` and `alerts.json`, then prints any alerts it found. The dependencies, including NumPy and scikit-learn, are installed from `requirements.txt`.

## How detection works

- **Isolation Forest** learns a baseline from ordinary flow summaries and scores observations that differ from it.
- **Median/MAD modified z-scores** flag unusually large or small feature values using robust statistics.
- An alert is raised if either method flags a flow. Each alert includes an anomaly score, severity, and unusual feature names for review.

The demo generates synthetic baseline and observation flows. For your own data, provide two CSVs: one containing known ordinary baseline flows, and one containing new flows to score.

Required CSV columns:

```text
flow_id,timestamp,duration_ms,bytes_sent,bytes_received,packets,destination_port,protocol
```

Run the detector with:

```powershell
python detector.py --baseline baseline.csv --input new_flows.csv --output alerts.json
```

Only analyze flow summaries you are allowed to use, and remove identifying details before sharing data. The project does not inspect packet payloads.

## Presentation outline

1. Explain why signature-only detection can miss new behavior.
2. Describe the flow features and how an ordinary baseline is prepared.
3. Explain Isolation Forest and median/MAD in plain language.
4. Run the offline demo and inspect the alerts.
5. Discuss evaluation metrics: precision, recall, F1, false-positive rate, and alert volume.
6. Cover limitations and next steps: false alarms, traffic drift, baseline quality, privacy, and analyst review.

## Important limits

An anomaly alert is a signal to investigate, not proof of an attack. An unsupervised approach may flag previously unseen behavior, but it cannot guarantee detection of every zero-day. Subtle attacks may look normal, and normal traffic changes can create false positives. Synthetic demo results are not real-world performance claims.

The dashboard uses illustrative sample metrics. It is not connected to live traffic or to the Python detector.
