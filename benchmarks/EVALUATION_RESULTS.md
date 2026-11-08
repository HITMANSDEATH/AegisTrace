# Evaluation Results: AegisTrace

> Status: September 2026 baseline (schema v1); later versions add per-session sequence counters and external anchoring.

## Benchmark Methodology & Environment

- **Date of Execution**: September 16, 2026
- **Hardware Environment**: Intel Core i5-13420H (8 physical cores, 12 logical threads, base 2.1 GHz, boost up to 4.6 GHz), 16.0 GB DDR5 RAM
- **Operating System & Runtime**: Windows 11 Pro, Docker Desktop with WSL2 Linux kernel (Debian 12 base, Python 3.12 within container network)
- **Workload**: All benchmarks executed using deterministic synthetic test events and deterministic mock LLM provider returns (zero live Groq API inference calls) to ensure reproducible, zero-cost measurements.

---

## 1. Tamper Detection

Evaluated across 100 clean synthetic sessions (~20 events each) and 100 tampered synthetic sessions (~20 events each), where each tampered session underwent an out-of-band payload mutation at a uniformly randomized position (1 to 20). Cryptographic integrity was assessed via `/api/session/{session_id}/verify`.

| Metric | Sample Size | Observed Result | Rate / Accuracy |
|---|---|---|---|
| **Detection Rate** (Tampered Sessions Flagged) | 100 sessions | 100 correctly flagged (`chain_intact: false`) | **100.0%** (100/100) |
| **False Positive Rate** (Clean Sessions Flagged) | 100 sessions | 0 incorrectly flagged (`chain_intact: true`) | **0.0%** (0/100) |
| **Localization Accuracy** (Broken Entry ID & Position Matched) | 100 sessions | 100 correctly localized to exact mutated ID and sequence position | **100.0%** (100/100) |

The cryptographic hash chain achieved a 100% detection rate across all mutated sessions with zero false positives on clean histories. In all 100 tampered cases, the verification engine accurately identified the exact database primary key and 1-indexed sequence position of the modified record.

---

## 2. Isolation / Oracle-Resistance

Evaluated directly from within the `agent_service` container network namespace to determine whether an adversarial or compromised agent process can access the SQLite database, inspect reconstruction state, or extract sensitive audit metadata.

| Attempt Type | Observed Result | Isolation Claim |
|---|---|---|
| **Direct connection to SQLite audit database file or host** | **Blocked**: Volume is not mounted in agent container (`/data/audit.db` does not exist); direct network connections to internal storage and gateway ports failed | **Pass** |
| **Direct HTTP request to reconstruction_service endpoints** | **Blocked**: Direct requests to `reconstruction_service:8002` failed via DNS non-resolution and TCP connection timeouts; reverse-proxy gateway blocked access with HTTP 403 Forbidden | **Pass** |
| **Reading data back from audit_service `/ingest` response** | **No data returned**: Ingest endpoint returned strictly `{"status":"recorded"}`; response contained no hashes, IDs, sequence markers, or echoed payloads; all GET/read endpoints returned 404/405 | **Pass** |

The network architecture and write-only API contract successfully isolate the agent, preventing it from reading stored evidence, inspecting verification status, or using the audit service as an oracle. All direct database connections, reconstruction queries, and data extraction attempts were blocked.

---

## 3. Audit Layer Overhead

Measured over 1,000 synthetic tool-call turns through the agent graph under two conditions: audit capture middleware DISABLED and audit capture middleware ENABLED (normal production operation posting to `audit_service`). A 100-event warm-up preceded each condition (warm-up measurements discarded), and the full 1,000-event workload was repeated across 5 independent trials per condition (5,000 total measured events each).

### Overall Latency Summary (5,000 Events per Condition)

| Condition | Median Latency (ms) | p95 Latency (ms) | Mean Latency (ms) |
|---|---|---|---|
| **Audit Capture DISABLED** | 1.756 | 2.386 | 1.822 |
| **Audit Capture ENABLED** (Normal Operation) | 2.301 | 3.657 | 2.414 |
| **Difference (Audit Layer Cost)** | **+0.545** | **+1.271** | **+0.592** |

### Per-Run Breakdown (1,000 Events per Trial)

| Trial | Disabled Median (ms) | Disabled p95 (ms) | Enabled Median (ms) | Enabled p95 (ms) |
|---|---|---|---|---|
| **Run 1** | 1.725 | 2.233 | 2.305 | 3.779 |
| **Run 2** | 1.700 | 2.342 | 2.308 | 3.664 |
| **Run 3** | 1.856 | 2.486 | 2.320 | 3.564 |
| **Run 4** | 1.762 | 2.441 | 2.298 | 3.644 |
| **Run 5** | 1.746 | 2.374 | 2.267 | 3.626 |

The asynchronous bounded FIFO capture worker imposes a sub-millisecond median overhead of +0.545 ms (+1.271 ms at p95) on the agent's turn execution. Because audit event ingestion is decoupled from the agent request lifecycle, tamper-evident logging adds virtually no perceptible latency to model reasoning and tool invocation.

---

## 4. Verification Scaling

Evaluated on sessions containing 10, 100, 1,000, and 10,000 synthetic entries to analyze computational scaling of the `/api/session/{session_id}/verify` endpoint (performing canonical JSON re-serialization, SHA-256 hash chaining, error localization, and DAG reconstruction).

| Entry Count | Server Verification Time (`durationMs`) | Total HTTP Round-Trip Time (ms) |
|---|---|---|
| **10** | 0.14 ms | 2.59 ms |
| **100** | 0.91 ms | 4.41 ms |
| **1,000** | 7.62 ms | 20.42 ms |
| **10,000** | 108.10 ms | 248.36 ms |

Verification runtime scales linearly (\(O(N)\)) with session size, taking under 1 millisecond for typical sessions (100 events) and approximately 108 milliseconds for an extensive 10,000-event trajectory. Even without caching, complete cryptographic verification and graph reconstruction remain fast enough for real-time validation.

---

## 5. Naive-Logging Baseline Comparison

Evaluated using the identical 1,000-event synthetic tool-call workload across 5 independent trials (5,000 measured events, following a discarded 100-event warm-up) to benchmark AegisTrace against a naive in-process synchronous SQLite logging implementation lacking container isolation, network segregation, and cryptographic hash chaining.

| Condition | Median (ms) | p95 (ms) |
|---|---|---|
| A — No audit layer | 1.756 | 2.386 |
| B — Naive synchronous logging | 2.258 | 3.172 |
| C — AegisTrace (isolated, async, hash-chained) | 2.301 | 3.657 |

AegisTrace's median overhead over the unlogged baseline (Condition A) is +0.545 ms, which is directly comparable to naive synchronous logging's +0.502 ms overhead (a difference of only 0.043 ms between Conditions B and C). At the 95th percentile, AegisTrace incurs a modest 0.485 ms higher latency than naive logging (3.657 ms vs. 3.172 ms), confirming that strong isolation and tamper-evident hash chaining introduce negligible latency penalty compared to an unhardened in-process write.

