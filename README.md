# Secure O-RAN Telemetry: Attack Detection with Authenticated Monitoring Data

An independent research project by Lemuel Agur Mensah on securing the
telemetry pipeline that Open RAN (O-RAN) monitoring and intelligence
systems depend on.

## The problem

O-RAN disaggregates the radio access network and leans heavily on
telemetry — throughput, latency, physical-resource-block utilization,
signal quality, handover failures — streamed from cells to monitoring
and ML components (xApps/rApps) that detect faults and attacks and steer
the network. That creates two linked security problems:

1. **Attacks show up in telemetry.** Jamming, signaling storms,
   rogue/false base stations, and targeted slice degradation all distort
   the KPI stream — if the monitoring system can recognize the pattern.
2. **Telemetry itself can be attacked.** If an adversary can tamper with,
   replay, or forge the KPI stream, the detector is reasoning over lies:
   real attacks can be hidden and false alarms manufactured.

Most student projects address only the first problem. This project treats
both: detect attacks in the telemetry, and cryptographically protect the
telemetry so the detector's input can be trusted.

## Threat model

- The attacker can degrade the radio environment (jamming), generate
  abusive signaling load, operate a rogue cell, or target a network
  slice's service level.
- The attacker can intercept telemetry in transit and tamper with,
  replay, or forge batches, but does not know the sending node's key.
- The defender operates the monitoring pipeline and must detect attacks
  quickly, with few false alarms, and reject untrustworthy telemetry.

## What is built (v0.1, synthetic prototype)

- `src/oran_anomaly.py` — generates 7 days of synthetic telemetry for
  3 cells (6,048 five-minute samples, 7 KPI features), injects six
  labeled attacks (2× jamming, 2× signaling storm, 1× rogue cell,
  1× slice SLA attack), and evaluates a per-cell z-score detector
  trained on the first 36 (normal) hours.
- `src/secure_telemetry.py` — batches telemetry into cell-hours,
  authenticates each batch with HMAC-SHA256 under a per-cell key, and
  binds batches to a monotonic counter. Verification is tested against
  tampering, replay, and forgery.

## Preliminary results (synthetic data — pipeline validation only)

Detection:

- Point precision 1.00, recall 0.86, F1 0.92 on held-out synthetic data
- 4 of 6 injected attack events detected; the missed events (one shorter
  jamming burst, the slice SLA attack) motivate the sequence-aware
  detector on the roadmap below

Integrity layer:

- 504 / 504 honest batches verified; tampered, replayed, and forged
  batches all rejected
- Overhead: 32 MAC bytes per 12-sample batch ≈ 2.7 bytes per sample

These numbers validate that the pipeline works end to end. They are not
evidence of performance on real RAN data, and the project materials say
so wherever the numbers appear.

## Roadmap

1. **Better detection:** sequence-aware models (forecasting residuals,
   isolation forest, lightweight autoencoder) with per-attack-type
   analysis; tune for the subtle events the baseline misses.
2. **Real data:** move from the synthetic generator to public RAN/wireless
   traces or an open O-RAN testbed (e.g., Colosseum / OpenRAN Gym style
   environments) as access allows.
3. **Production-grade provenance:** replace shared HMAC keys with
   per-node certificates and Ed25519/ECDSA signatures so any authorized
   consumer can verify telemetry without holding a secret; study key
   rotation and revocation.
4. **Privacy angle:** operators may not want to share raw telemetry —
   explore privacy-preserving sharing (aggregation, differential
   privacy, federated detection) as a later extension.
5. **Write-up:** research brief → poster/workshop submission once the
   detector improves and a less synthetic evaluation exists.

## How to run

```bash
python3 src/oran_anomaly.py      # writes data/telemetry.csv, results/metrics.json, results/summary.md
python3 src/secure_telemetry.py  # writes results/security_metrics.json, results/security_summary.md
```

Standard library only; no dependencies.

## Why this project

It sits exactly on Lemuel's intended research direction — wireless and
mobile networking (5G/O-RAN), IoT, and AI/network security — and on a
problem of clear national importance: the trustworthiness of the
monitoring data that next-generation wireless infrastructure uses to
defend itself.
