# Baseline results (synthetic telemetry)

These numbers come from the synthetic generator in `src/oran_anomaly.py`.
They validate the pipeline end to end; they are **not** evidence of
performance on real RAN data.

- Rows generated: 6048
- Rows evaluated after the 36-hour normal training window: 4752
- Detector: per-cell z-score over 7 telemetry features; threshold = 99.5th percentile of training scores (2.7338)
- Point precision: 1.0
- Point recall: 0.8571
- Point F1: 0.9231
- Events detected: 4 / 6
- Median detection latency: 0.0 minutes

| Cell | Event type | Detected | Detection latency (min) |
|---|---|---:|---:|
| cell_a | jamming | no |  |
| cell_b | signaling_storm | yes | 0 |
| cell_c | rogue_cell | yes | 0 |
| cell_a | slice_sla_attack | no |  |
| cell_b | jamming | yes | 0 |
| cell_c | signaling_storm | yes | 0 |
