# Research Brief — Secure O-RAN Telemetry

**Lemuel Agur Mensah** · Independent research project · November 2026
Status: working prototype (synthetic data); brief version for graduate
application packets and recommender briefing.

## Motivation

Open RAN architectures make the radio access network programmable and
observable: cells stream key performance indicators (KPIs) to monitoring
and machine-learning components that detect anomalies and control the
network in near-real time. This observability is a security asset and a
security liability. Attacks such as jamming, signaling storms, rogue
base stations, and targeted slice degradation manifest in the KPI
stream — but only if the stream is both analyzed and trustworthy. An
adversary who can tamper with, replay, or forge telemetry can blind the
very systems meant to detect them. As 5G and future 6G networks become
critical infrastructure, the integrity of RAN telemetry is a problem of
practical and national importance.

## Research questions

1. Which KPI signatures distinguish common RAN attacks (jamming,
   signaling storms, rogue cells, slice-level degradation) from normal
   load variation, and how quickly can they be detected?
2. What does it cost — in bandwidth, latency, and complexity — to
   authenticate telemetry at the source so that monitoring systems can
   reject tampered, replayed, or forged data?
3. Where is the practical trade-off between detection sensitivity and
   trust overhead for a monitoring pipeline that must run continuously?

## Approach

**Detection layer.** A synthetic generator produces 7 days of telemetry
for 3 cells at 5-minute intervals (6,048 samples; throughput, latency,
PRB utilization, SINR, handover failures, active users, packet loss),
with a realistic daily load pattern. Six labeled attacks are injected.
A per-cell z-score detector is calibrated on the first 36 hours of
normal operation and evaluated on the remaining stream, reporting point
precision/recall/F1, per-event detection, and detection latency.

**Integrity layer.** Telemetry is batched per cell-hour and authenticated
with HMAC-SHA256 under a per-cell key, with a monotonic batch counter.
Verification is evaluated against three attacks on the telemetry itself:
value tampering, replay of a previously valid batch, and forgery under
an attacker-controlled key. The brief documents the production design
this prototypes: per-node certificates with Ed25519/ECDSA signatures,
key rotation, and revocation.

## Preliminary results (synthetic data)

- Detection: precision 1.00, recall 0.86, F1 0.92; 4 of 6 attack events
  detected. The two missed events — a shorter jamming burst and the
  slice SLA attack — are the explicit motivation for sequence-aware
  detection in the next phase.
- Integrity: all 504 honest batches verified; tampered, replayed, and
  forged batches all rejected. Authentication overhead is 32 bytes per
  12-sample batch (≈2.7 bytes/sample); verification is ~0.02 ms/batch in
  this Python prototype.

These results validate the pipeline end to end. They are not claimed as
performance on real network data.

## Limitations

- Synthetic telemetry cannot capture real radio-environment complexity;
  results will change — likely downward — on real traces.
- The z-score baseline assumes roughly stationary per-cell behavior and
  is intentionally simple; it is a floor, not the contribution.
- HMAC requires a shared secret; the signature-based production design
  is specified but not yet implemented.

## Next steps

1. Sequence-aware detection (forecasting residuals, isolation forest,
   lightweight autoencoder) with per-attack-type error analysis.
2. Evaluation on public wireless/RAN traces or an open O-RAN testbed.
3. Signature-based provenance prototype (Ed25519) with key-rotation
   experiments.
4. Poster/workshop write-up once a less synthetic evaluation exists.

## Fit with my graduate research direction

This project is the seed of the research I intend to pursue in a thesis
master's and later a PhD in networked systems security: trustworthy
monitoring and defense for next-generation wireless infrastructure. It
connects directly to faculty work in network security monitoring, 5G RAN
profiling, wireless and IoT security, and IoT attack detection at the
programs I am applying to.
