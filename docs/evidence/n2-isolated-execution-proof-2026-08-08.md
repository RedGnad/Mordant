# N=2 isolated execution evidence

The retained machine-readable proof is [n2-isolated-execution-proof-2026-08-08.json](./n2-isolated-execution-proof-2026-08-08.json). Its validator is `scripts/validate-n2-isolation-evidence.mjs`.

The harness builds all seven native executables from its clean, commit-pinned checkout and launches two authentic instances of the existing managed combined-intake worker. The workers use separate ephemeral ports and temporary durable roots, retain one active case each, execute opposite real BGV cases, and are required to show simultaneous native evaluator children. The retained artifact includes build hashes, measured timestamps, operation overlap, governed results, terminal receipts, and bidirectional state-isolation checks.

`evaluationOperationOverlapMs` measures overlap between the durable `evaluatePrivateConflict` operation-journal intervals. It is broader than native evaluator process lifetime and is not presented as exact native process-runtime overlap; the separate simultaneous-process observation establishes that both native evaluator children were alive in one process snapshot.

The supported claim is exactly: **“Multiple isolated execution slots can run concurrently.”**

This test does not implement or establish production routing/pooling, N>2 behavior, linear scaling, throughput, autoscaling, load balancing, high availability, settlement scalability, or production readiness. The public deployment still intentionally exposes one worker slot.
