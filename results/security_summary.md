# Integrity-layer results (synthetic telemetry)

Batches of 12 five-minute samples (one cell-hour) are authenticated
with HMAC-SHA256 under a per-cell key and bound to a monotonic counter.

- Batches signed and verified: 504 / 504 (6048 telemetry rows)
- Average verification time: 0.021 ms per batch (prototype, this machine)
- Overhead: 32 MAC bytes per batch = 2.67 bytes per telemetry row
- Tampered telemetry value: detected (MAC mismatch (tampered or forged batch))
- Replayed old batch: detected (counter mismatch (replay or out-of-order batch))
- Forged batch (wrong key): detected (MAC mismatch (tampered or forged batch))
