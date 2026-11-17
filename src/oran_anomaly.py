"""Baseline prototype: attack detection for synthetic O-RAN-style telemetry.

Secure O-RAN telemetry project, part 1 (detection). This is a deliberately
small, standard-library-only starting point. It generates synthetic cell
telemetry with a daily load pattern, injects labeled security events
(jamming, signaling storm, rogue cell, slice SLA attack), and evaluates a
simple per-cell z-score detector. Part 2 (`secure_telemetry.py`) covers
the integrity/provenance layer. The point is a reproducible scaffold
Lemuel can extend with public traces or a real O-RAN testbed later --
not a claim of real-world performance.
"""

from __future__ import annotations

import csv
import json
import math
import random
import statistics
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
RESULTS_DIR = ROOT / "results"

FEATURES = [
    "throughput_mbps",
    "latency_ms",
    "prb_utilization",
    "sinr_db",
    "handover_failures",
    "active_users",
    "packet_loss_pct",
]

STEP_MINUTES = 5
DAYS = 7
STEPS_PER_DAY = 24 * 60 // STEP_MINUTES
CELLS = ["cell_a", "cell_b", "cell_c"]


def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    k = (len(ordered) - 1) * pct / 100.0
    lo = math.floor(k)
    hi = math.ceil(k)
    if lo == hi:
        return ordered[int(k)]
    return ordered[lo] * (hi - k) + ordered[hi] * (k - lo)


def event_schedule(total_steps: int) -> list[dict]:
    """Deterministic injected events, kept out of the first 36 hours."""
    day = STEPS_PER_DAY
    return [
        {"cell": "cell_a", "start": day + 120, "duration": 18, "type": "jamming"},
        {"cell": "cell_b", "start": 2 * day + 150, "duration": 24, "type": "signaling_storm"},
        {"cell": "cell_c", "start": 3 * day + 90, "duration": 30, "type": "rogue_cell"},
        {"cell": "cell_a", "start": 4 * day + 170, "duration": 16, "type": "slice_sla_attack"},
        {"cell": "cell_b", "start": 5 * day + 60, "duration": 20, "type": "jamming"},
        {"cell": "cell_c", "start": 6 * day + 130, "duration": 22, "type": "signaling_storm"},
    ]


def generate_rows(seed: int = 42) -> tuple[list[dict], list[dict]]:
    rng = random.Random(seed)
    total_steps = DAYS * STEPS_PER_DAY
    events = event_schedule(total_steps)
    event_by_cell_step: dict[tuple[str, int], str] = {}
    for ev in events:
        for s in range(ev["start"], min(total_steps, ev["start"] + ev["duration"])):
            event_by_cell_step[(ev["cell"], s)] = ev["type"]

    start_time = datetime(2026, 11, 16, 0, 0)
    base_users = {"cell_a": 95.0, "cell_b": 75.0, "cell_c": 60.0}
    rows: list[dict] = []

    for cell in CELLS:
        for step in range(total_steps):
            ts = start_time + timedelta(minutes=STEP_MINUTES * step)
            minute_of_day = (step * STEP_MINUTES) % (24 * 60)
            # Daily load: quiet overnight, peaks late morning and evening.
            phase = 2 * math.pi * (minute_of_day - 9 * 60) / (24 * 60)
            load = 0.52 + 0.30 * math.sin(phase) + 0.10 * math.sin(2 * phase + 1.1)
            load = clamp(load + rng.gauss(0, 0.03), 0.05, 0.98)

            active_users = max(1.0, base_users[cell] * load + rng.gauss(0, 3.0))
            prb = clamp(0.18 + 0.68 * load + rng.gauss(0, 0.025), 0.02, 0.99)
            per_user = 1.15 - 0.45 * max(0.0, prb - 0.62)
            throughput = max(1.0, active_users * per_user + rng.gauss(0, 2.0))
            latency = max(2.0, 7.0 + 22.0 * prb + rng.gauss(0, 1.1))
            sinr = clamp(17.0 - 4.5 * load + rng.gauss(0, 0.8), -5.0, 30.0)
            packet_loss = clamp(max(0.0, (prb - 0.78) * 3.0) + rng.gauss(0, 0.05), 0.0, 25.0)
            ho_rate = 0.25 + 0.7 * load
            handover_failures = 1 if rng.random() < ho_rate / 6 else 0
            if rng.random() < ho_rate / 18:
                handover_failures += 1

            label = event_by_cell_step.get((cell, step), "normal")
            if label == "jamming":
                # Deliberate interference: SINR collapses, latency and loss spike.
                sinr -= 7.5
                latency += 14.0
                throughput *= 0.62
                packet_loss += 3.2
            elif label == "signaling_storm":
                # Abusive signaling load: user count and PRB use surge, service degrades.
                active_users *= 1.45
                prb = clamp(prb + 0.22, 0.02, 0.995)
                latency += 16.0
                throughput *= 0.78
                packet_loss += 1.6
            elif label == "rogue_cell":
                # Rogue/false base station indicators: abnormally strong signal,
                # elevated handover failures, unstable throughput.
                sinr += 6.0
                handover_failures += 2
                throughput *= 0.80
                latency += 5.0
                packet_loss += 0.8
            elif label == "slice_sla_attack":
                # Targeted degradation of a slice's service level.
                latency += 24.0
                packet_loss += 2.4
                throughput *= 0.84

            rows.append(
                {
                    "timestamp": ts.isoformat(timespec="minutes"),
                    "cell": cell,
                    "step": step,
                    "throughput_mbps": round(throughput, 3),
                    "latency_ms": round(latency, 3),
                    "prb_utilization": round(prb, 4),
                    "sinr_db": round(sinr, 3),
                    "handover_failures": int(handover_failures),
                    "active_users": round(active_users, 2),
                    "packet_loss_pct": round(packet_loss, 3),
                    "label": label,
                }
            )

    rows.sort(key=lambda r: (r["step"], r["cell"]))
    return rows, events


def fit_detector(train_rows: list[dict]) -> dict:
    stats: dict[str, dict[str, tuple[float, float]]] = {}
    for cell in CELLS:
        cell_rows = [r for r in train_rows if r["cell"] == cell]
        stats[cell] = {}
        for feature in FEATURES:
            values = [float(r[feature]) for r in cell_rows]
            mean = statistics.fmean(values)
            stdev = statistics.pstdev(values) or 1.0
            stats[cell][feature] = (mean, stdev)
    return stats


def score_row(row: dict, stats: dict) -> float:
    total = 0.0
    for feature in FEATURES:
        mean, stdev = stats[row["cell"]][feature]
        z = (float(row[feature]) - mean) / stdev
        total += z * z
    return math.sqrt(total / len(FEATURES))


def evaluate(rows: list[dict], events: list[dict]) -> dict:
    train_cutoff = int(1.5 * STEPS_PER_DAY)  # first 36 hours: normal by construction
    train_rows = [r for r in rows if r["step"] < train_cutoff]
    stats = fit_detector(train_rows)
    train_scores = [score_row(r, stats) for r in train_rows]
    threshold = percentile(train_scores, 99.5)

    for row in rows:
        row["anomaly_score"] = round(score_row(row, stats), 4)
        row["flagged"] = row["anomaly_score"] > threshold

    test_rows = [r for r in rows if r["step"] >= train_cutoff]
    tp = sum(1 for r in test_rows if r["flagged"] and r["label"] != "normal")
    fp = sum(1 for r in test_rows if r["flagged"] and r["label"] == "normal")
    fn = sum(1 for r in test_rows if not r["flagged"] and r["label"] != "normal")
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    event_results = []
    for ev in events:
        window = [
            r
            for r in test_rows
            if r["cell"] == ev["cell"] and ev["start"] <= r["step"] < ev["start"] + ev["duration"]
        ]
        flagged_steps = [r["step"] for r in window if r["flagged"]]
        detected = len(flagged_steps) >= 3
        latency_steps = (min(flagged_steps) - ev["start"]) if detected else None
        event_results.append(
            {
                "cell": ev["cell"],
                "type": ev["type"],
                "start_step": ev["start"],
                "duration_steps": ev["duration"],
                "detected": detected,
                "detection_latency_minutes": latency_steps * STEP_MINUTES if latency_steps is not None else None,
            }
        )

    detected_latencies = [
        e["detection_latency_minutes"] for e in event_results if e["detection_latency_minutes"] is not None
    ]
    return {
        "threshold": round(threshold, 4),
        "rows_total": len(rows),
        "rows_evaluated": len(test_rows),
        "anomalous_points_evaluated": sum(1 for r in test_rows if r["label"] != "normal"),
        "point_precision": round(precision, 4),
        "point_recall": round(recall, 4),
        "point_f1": round(f1, 4),
        "events_detected": sum(1 for e in event_results if e["detected"]),
        "events_total": len(event_results),
        "median_detection_latency_minutes": statistics.median(detected_latencies) if detected_latencies else None,
        "event_results": event_results,
    }


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def write_summary(metrics: dict) -> None:
    lines = [
        "# Baseline results (synthetic telemetry)",
        "",
        "These numbers come from the synthetic generator in `src/oran_anomaly.py`.",
        "They validate the pipeline end to end; they are **not** evidence of",
        "performance on real RAN data.",
        "",
        f"- Rows generated: {metrics['rows_total']}",
        f"- Rows evaluated after the 36-hour normal training window: {metrics['rows_evaluated']}",
        f"- Detector: per-cell z-score over {len(FEATURES)} telemetry features; threshold = 99.5th percentile of training scores ({metrics['threshold']})",
        f"- Point precision: {metrics['point_precision']}",
        f"- Point recall: {metrics['point_recall']}",
        f"- Point F1: {metrics['point_f1']}",
        f"- Events detected: {metrics['events_detected']} / {metrics['events_total']}",
        f"- Median detection latency: {metrics['median_detection_latency_minutes']} minutes",
        "",
        "| Cell | Event type | Detected | Detection latency (min) |",
        "|---|---|---:|---:|",
    ]
    for e in metrics["event_results"]:
        latency = "" if e["detection_latency_minutes"] is None else str(e["detection_latency_minutes"])
        lines.append(f"| {e['cell']} | {e['type']} | {'yes' if e['detected'] else 'no'} | {latency} |")
    lines.append("")
    (RESULTS_DIR / "summary.md").write_text("\n".join(lines))


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    rows, events = generate_rows()
    metrics = evaluate(rows, events)

    write_csv(
        DATA_DIR / "telemetry.csv",
        rows,
        ["timestamp", "cell", "step", *FEATURES, "label"],
    )
    write_csv(
        RESULTS_DIR / "detections.csv",
        rows,
        ["timestamp", "cell", "step", *FEATURES, "label", "anomaly_score", "flagged"],
    )
    (RESULTS_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2))
    write_summary(metrics)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
