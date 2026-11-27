"""Offline network-flow anomaly detector for a student project demo.

This project reads flow summaries from CSV. It does not capture, scan, or send
network traffic. The built-in demo creates synthetic flow data only.
"""
from __future__ import annotations
import argparse
import csv
import json
import math
import random
from pathlib import Path
from typing import Iterable

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURES = ("duration_ms", "bytes_sent", "bytes_received", "packets", "destination_port")
PROTOCOLS = ("tcp", "udp", "icmp")


def make_features(rows: list[dict[str, str | int | float]]) -> np.ndarray:
    """Log-transform skewed flow counters, scale units, and encode protocol."""
    values = []
    for row in rows:
        protocol = str(row.get("protocol", "tcp")).lower()
        values.append([
            math.log1p(max(0, float(row["duration_ms"]))),
            math.log1p(max(0, float(row["bytes_sent"]))),
            math.log1p(max(0, float(row["bytes_received"]))),
            math.log1p(max(0, float(row["packets"]))),
            math.log1p(max(0, float(row["destination_port"]))),
            *[1.0 if protocol == p else 0.0 for p in PROTOCOLS],
        ])
    return np.asarray(values, dtype=float)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        missing = set((*FEATURES, "protocol")) - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV is missing required columns: {', '.join(sorted(missing))}")
        return list(reader)


def write_csv(path: Path, rows: Iterable[dict[str, object]]) -> None:
    rows = list(rows)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["flow_id", "timestamp", *FEATURES, "protocol"])
        writer.writeheader()
        writer.writerows(rows)


def synthetic_data(seed: int = 19) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Create normal baseline flows and a held-out stream with a few outliers."""
    rng = random.Random(seed)
    ports = [(443, "tcp"), (80, "tcp"), (53, "udp")]

    def normal_flow(index: int, monitored: bool = False) -> dict[str, object]:
        port, protocol = rng.choice(ports)
        return {
            "flow_id": f"{'M' if monitored else 'B'}{index:03d}",
            "timestamp": f"2026-11-27T09:{index % 60:02d}:00Z",
            "duration_ms": max(30, round(rng.gauss(900, 260))),
            "bytes_sent": max(120, round(rng.lognormvariate(7.9, .48))),
            "bytes_received": max(300, round(rng.lognormvariate(8.9, .52))),
            "packets": max(3, round(rng.gauss(38, 12))),
            "destination_port": port,
            "protocol": protocol,
        }

    baseline = [normal_flow(i) for i in range(240)]
    monitored: list[dict[str, object]] = [normal_flow(i, True) for i in range(14)]
    monitored.extend([
        {"flow_id":"M014","timestamp":"2026-11-27T10:14:00Z","duration_ms":260,"bytes_sent":850000,"bytes_received":900,"packets":7200,"destination_port":4444,"protocol":"tcp"},
        {"flow_id":"M015","timestamp":"2026-11-27T10:15:00Z","duration_ms":140,"bytes_sent":640000,"bytes_received":2100,"packets":4100,"destination_port":31337,"protocol":"tcp"},
        {"flow_id":"M016","timestamp":"2026-11-27T10:16:00Z","duration_ms":90,"bytes_sent":300000,"bytes_received":1800,"packets":2600,"destination_port":53,"protocol":"udp"},
        {"flow_id":"M017","timestamp":"2026-11-27T10:17:00Z","duration_ms":420,"bytes_sent":2200,"bytes_received":12000,"packets":31,"destination_port":443,"protocol":"tcp"},
    ])
    return baseline, monitored


def robust_z_scores(train_scaled: np.ndarray, sample_scaled: np.ndarray) -> np.ndarray:
    """Absolute modified z-scores using training median and MAD per feature."""
    median = np.median(train_scaled, axis=0)
    mad = np.median(np.abs(train_scaled - median), axis=0)
    safe_mad = np.where(mad < 1e-9, 1e-9, mad)
    return 0.6745 * np.abs(sample_scaled - median) / safe_mad


def detect(baseline: list[dict[str, str | int | float]],
           observations: list[dict[str, str | int | float]],
           contamination: float = 0.03,
           z_threshold: float = 4.5) -> list[dict[str, object]]:
    """Fit only on baseline flows and score unseen flows without labels."""
    if len(baseline) < 30:
        raise ValueError("Provide at least 30 baseline flows for a stable demo.")
    if not observations:
        return []
    scaler = StandardScaler().fit(make_features(baseline))
    train_x = scaler.transform(make_features(baseline))
    sample_x = scaler.transform(make_features(observations))

    model = IsolationForest(n_estimators=250, contamination=contamination,
                            random_state=42, n_jobs=1)
    model.fit(train_x)
    # decision_function: lower values indicate more unusual observations.
    model_score = model.decision_function(sample_x)
    train_score = model.decision_function(train_x)
    cutoff = float(np.quantile(train_score, contamination))
    z = robust_z_scores(train_x, sample_x)
    results = []
    for row, score, feature_z in zip(observations, model_score, z):
        abnormal_features = [FEATURES[i] for i in range(len(FEATURES)) if feature_z[i] >= z_threshold]
        forest_flag = float(score) < cutoff
        stats_flag = len(abnormal_features) >= 2
        results.append({
            **row,
            "is_alert": bool(forest_flag or stats_flag),
            "isolation_score": round(float(score), 4),
            "statistical_flag": bool(stats_flag),
            "unusual_features": abnormal_features,
            "severity": "high" if len(abnormal_features) >= 2 else ("medium" if forest_flag or stats_flag else "normal"),
        })
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline ML + statistical network-flow anomaly detector")
    parser.add_argument("--demo", action="store_true", help="run the deterministic synthetic demo")
    parser.add_argument("--baseline", type=Path, help="CSV of known normal flow summaries")
    parser.add_argument("--input", type=Path, help="CSV of flows to score")
    parser.add_argument("--output", type=Path, default=Path("alerts.json"), help="JSON result path")
    args = parser.parse_args()

    if args.demo:
        baseline, observations = synthetic_data()
        write_csv(Path("demo_flows.csv"), observations)
    elif args.baseline and args.input:
        baseline, observations = read_csv(args.baseline), read_csv(args.input)
    else:
        parser.error("Use --demo or provide both --baseline and --input.")

    results = detect(baseline, observations)
    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    alerts = [item for item in results if item["is_alert"]]
    print(f"Scored {len(results)} flows · {len(alerts)} alert(s) · saved {args.output}")
    for item in alerts:
        features = ", ".join(item["unusual_features"]) or "combined flow pattern"
        print(f"ALERT {item['flow_id']} | {item['severity'].upper()} | {item['protocol'].upper()} port {item['destination_port']} | {features}")


if __name__ == "__main__":
    main()

