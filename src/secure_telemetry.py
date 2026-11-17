"""Secure O-RAN telemetry project, part 2: integrity and provenance layer.

Telemetry only helps a detector if the monitoring system can trust it.
This prototype batches the synthetic telemetry from `oran_anomaly.py`
(one batch = one cell, one hour = 12 five-minute samples), authenticates
each batch with HMAC-SHA256 under a per-cell key, and binds each batch to
a monotonically increasing counter. Verification then demonstrates three
attack outcomes:

- tampering with a telemetry value        -> MAC check fails
- replaying an old, validly signed batch  -> counter check fails
- forging a batch without the cell's key  -> MAC check fails

HMAC is the right prototype choice here (symmetric, standard library).
A production design would use per-node certificates with Ed25519/ECDSA
signatures so any authorized consumer can verify without sharing a
secret; that design step is documented in the research brief.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import json
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
RESULTS_DIR = ROOT / "results"

BATCH_STEPS = 12  # 12 x 5-minute samples = 1 hour
FIELDS = [
    "timestamp",
    "cell",
    "step",
    "throughput_mbps",
    "latency_ms",
    "prb_utilization",
    "sinr_db",
    "handover_failures",
    "active_users",
    "packet_loss_pct",
]

# Demo keys only -- a real deployment provisions per-node keys via PKI.
KEYS = {cell: hashlib.sha256(f"demo-key-for-{cell}".encode()).digest() for cell in ("cell_a", "cell_b", "cell_c")}


def canonical_batch(cell: str, counter: int, rows: list[dict]) -> bytes:
    lines = [f"{cell}|{counter}|{rows[0]['step']}|{rows[-1]['step']}"]
    for r in rows:
        lines.append("|".join(str(r[f]) for f in FIELDS))
    return "\n".join(lines).encode()


def sign_batch(cell: str, counter: int, rows: list[dict]) -> dict:
    mac = hmac.new(KEYS[cell], canonical_batch(cell, counter, rows), hashlib.sha256).hexdigest()
    return {"cell": cell, "counter": counter, "rows": rows, "mac": mac}


def verify_batch(batch: dict, expected_counter: int) -> tuple[bool, str]:
    if batch["counter"] != expected_counter:
        return False, "counter mismatch (replay or out-of-order batch)"
    expected_mac = hmac.new(
        KEYS[batch["cell"]],
        canonical_batch(batch["cell"], batch["counter"], batch["rows"]),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_mac, batch["mac"]):
        return False, "MAC mismatch (tampered or forged batch)"
    return True, "ok"


def load_batches() -> list[dict]:
    with (DATA_DIR / "telemetry.csv").open() as f:
        rows = list(csv.DictReader(f))
    batches: list[dict] = []
    counters: dict[str, int] = {}
    for cell in KEYS:
        cell_rows = sorted((r for r in rows if r["cell"] == cell), key=lambda r: int(r["step"]))
        counters[cell] = 0
        for i in range(0, len(cell_rows), BATCH_STEPS):
            chunk = cell_rows[i : i + BATCH_STEPS]
            batches.append(sign_batch(cell, counters[cell], chunk))
            counters[cell] += 1
    return batches


def main() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    batches = load_batches()
    total_rows = sum(len(b["rows"]) for b in batches)

    # Honest-path verification, timed.
    expected: dict[str, int] = {cell: 0 for cell in KEYS}
    start = time.perf_counter()
    honest_ok = 0
    for batch in sorted(batches, key=lambda b: (b["cell"], b["counter"])):
        ok, _ = verify_batch(batch, expected[batch["cell"]])
        if ok:
            honest_ok += 1
            expected[batch["cell"]] += 1
    elapsed = time.perf_counter() - start

    sample = next(b for b in batches if b["cell"] == "cell_a" and b["counter"] == 10)

    # Attack 1: tamper with one telemetry value after signing.
    tampered = {"cell": sample["cell"], "counter": sample["counter"], "mac": sample["mac"],
                "rows": [dict(r) for r in sample["rows"]]}
    tampered["rows"][0]["latency_ms"] = str(float(tampered["rows"][0]["latency_ms"]) + 40.0)
    tamper_ok, tamper_reason = verify_batch(tampered, sample["counter"])

    # Attack 2: replay an old valid batch after the stream has advanced.
    replay_ok, replay_reason = verify_batch(sample, sample["counter"] + 5)

    # Attack 3: forge a batch with an attacker's key.
    forged_rows = [dict(r) for r in sample["rows"]]
    forged_mac = hmac.new(hashlib.sha256(b"attacker-key").digest(),
                          canonical_batch(sample["cell"], sample["counter"], forged_rows),
                          hashlib.sha256).hexdigest()
    forged = {"cell": sample["cell"], "counter": sample["counter"], "rows": forged_rows, "mac": forged_mac}
    forged_ok, forged_reason = verify_batch(forged, sample["counter"])

    mac_bytes = len(bytes.fromhex(sample["mac"]))
    metrics = {
        "batches_total": len(batches),
        "telemetry_rows_total": total_rows,
        "batch_size_rows": BATCH_STEPS,
        "honest_batches_verified": honest_ok,
        "verify_seconds_all_batches": round(elapsed, 4),
        "avg_verify_ms_per_batch": round(elapsed / len(batches) * 1000, 3),
        "mac_bytes_per_batch": mac_bytes,
        "overhead_bytes_per_row": round(mac_bytes / BATCH_STEPS, 2),
        "tamper_detected": not tamper_ok,
        "tamper_reason": tamper_reason,
        "replay_detected": not replay_ok,
        "replay_reason": replay_reason,
        "forgery_detected": not forged_ok,
        "forgery_reason": forged_reason,
    }
    (RESULTS_DIR / "security_metrics.json").write_text(json.dumps(metrics, indent=2))

    lines = [
        "# Integrity-layer results (synthetic telemetry)",
        "",
        "Batches of 12 five-minute samples (one cell-hour) are authenticated",
        "with HMAC-SHA256 under a per-cell key and bound to a monotonic counter.",
        "",
        f"- Batches signed and verified: {honest_ok} / {len(batches)} ({total_rows} telemetry rows)",
        f"- Average verification time: {metrics['avg_verify_ms_per_batch']} ms per batch (prototype, this machine)",
        f"- Overhead: {mac_bytes} MAC bytes per batch = {metrics['overhead_bytes_per_row']} bytes per telemetry row",
        f"- Tampered telemetry value: {'detected' if metrics['tamper_detected'] else 'NOT detected'} ({tamper_reason})",
        f"- Replayed old batch: {'detected' if metrics['replay_detected'] else 'NOT detected'} ({replay_reason})",
        f"- Forged batch (wrong key): {'detected' if metrics['forgery_detected'] else 'NOT detected'} ({forged_reason})",
        "",
    ]
    (RESULTS_DIR / "security_summary.md").write_text("\n".join(lines))
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
