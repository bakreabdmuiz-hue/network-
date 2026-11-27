# Presentation Notes: Sentinel ML

## Project title
**Unsupervised Network Flow Anomaly Detection with Statistical Alerting**

## Short opening
“Many security tools look for patterns they already know. Our project explores a complementary approach: learn what ordinary network flows look like, then alert when new flows differ strongly from that baseline.”

## Key explanation
- **Isolation Forest:** isolates unusual examples with fewer random splits than typical examples; it can score new combinations without attack labels.
- **Median/MAD:** a robust statistical comparison. Median absolute deviation is less affected by a few extreme training values than standard deviation.
- **Alert policy:** combine the model score and statistical checks, then show why the flow was flagged. An alert asks for investigation; it does not confirm an attack.

## Live demo steps
1. Install the two dependencies from `requirements.txt`.
2. Run `python detector.py --demo`.
3. Point out that `demo_flows.csv` contains flow summaries only.
4. Review `alerts.json` and the console alert lines.
5. Relate a flagged feature (for example, packet count or destination port) to the baseline.

## Questions to prepare for
**Can it catch every zero-day?** No. It may surface behavior unlike the baseline, but stealthy attacks can resemble ordinary use, and benign changes can look unusual.

**How do you know it works?** The synthetic demo shows the pipeline. Real performance needs a separate, labeled test dataset and metrics such as precision, recall, F1, and false-positive rate.

**How do you reduce false alarms?** Improve baseline coverage, tune thresholds on validation data, monitor drift, and include analyst feedback.

**Why not inspect packet contents?** Flow summaries are a safer, simpler starting point and can reduce exposure to sensitive payload data. They also limit what the model can see.

