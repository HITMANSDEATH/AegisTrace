# AegisTrace: Architecture, Methodologies, Working Mechanisms, and Empirical Evaluation

> Historical document: describes the September 2026 baseline (schema v1). Later versions add external anchoring and per-session sequence counters; see the README for the current design.

---

## 1. Executive Summary & Core Security Philosophy

**AegisTrace** is a zero-trust, server-backed evidence room and provenance verification engine designed for autonomous AI agent systems. As language model assistants transition from advisory chatbots to agentic executors endowed with tool-calling capabilities, database interfaces, and state-transition autonomy, conventional application logging paradigms break down. Standard logging approaches exhibit three fundamental structural vulnerabilities:

1. **Co-location / Privilege Conflation**: Log writers and agent code typically share an execution environment (the same container, filesystem, or OS process). A prompt injection attack, model jailbreak, or compromised tool can overwrite, alter, or truncate audit records to conceal illicit activity.
2. **Oracle Vulnerability**: When an agent has read access to audit logs or verification endpoints during execution, it can treat the audit subsystem as an "oracle" — querying internal state to probe defensive thresholds, test evasion vectors, or verify whether sensitive actions were detected.
3. **Malleability**: Plaintext log streams and unauthenticated relational tables can be modified out-of-band without detection. Insiders, compromised hosts, or storage layer modifications can alter events, reorder sequences, or drop records without leaving cryptographic traces.

AegisTrace addresses these challenges through **strict microservice isolation**, **asynchronous non-blocking provenance capture**, **canonical cryptographic hash chaining**, and **deterministic DAG reconstruction**.

```
                       +-------------------------------------------------------------+
                       |                     CLIENT / INVESTIGATOR                   |
                       |                     Browser UI (Port 3000)                  |
                       +------------------------------+------------------------------+
                                                      |
                                                      v
                                        +----------------------------+
                                        |      FRONTEND GATEWAY      |
                                        |    Nginx Reverse Proxy     |
                                        |   (Source IP ACL Enforced) |
                                        +--------------+-------------+
                                                       |
                             +-------------------------+-------------------------+
                             |                                                   |
                     (Agent Chat API)                                     (Evidence API)
                             |                                                   |
                             v                                                   v
               +---------------------------+                       +---------------------------+
               |       AGENT SERVICE       |                       |  RECONSTRUCTION SERVICE   |
               |  LangGraph State Machine  |                       |  Cryptographic Validator  |
               |   Bounded FIFO Capture    |                       |  NetworkX DAG Generator   |
               |  (Read-Only Container)    |                       |  (Read-Only SQLite URI)   |
               +-------------+-------------+                       +-------------+-------------+
                             |                                                   |
        +--------------------+--------------------+                              |
        |                                         |                              |
        v                                         v                              v
+---------------+                         +---------------+              +---------------+
|  GROQ PROXY   |                         | AUDIT SERVICE |              |  AUDIT VOLUME |
| Squid CONNECT |                         | Write-Only    |  (Writes)    |               |
| Egress Tunnel |                         | Authenticated |============> |  /data/       |
| (api.groq.com)|                         | Hash Chaining |              |  audit.db     |
+---------------+                         +---------------+              +---------------+
```

---

## 2. System Components & Runtime Topology

AegisTrace decouples agent execution from audit storage and verification across four primary containerized services, an egress proxy sidecar, and an isolated persistent storage volume:

### 2.1. `agent_service` (Execution Layer)
The agent service hosts the cognitive execution graph of the assistant, built using **LangGraph** and **FastAPI**:
- **Cyclic Execution Graph**: Implements a structured turn workflow:
  - `classify_node`: Evaluates user instructions using heuristic classification to detect questions, operational requests, and sensitive actions directed against audit logs or ledgers.
  - `tool_node`: Executes sandboxed simulated actions (`retrieve_context`, `execute_action`). Tool payloads explicitly differentiate simulation metadata (`simulated: true`, `action_executed: true`, `real_world_action_executed: false`) from live infrastructure alterations.
  - `respond_node`: Formulates the final model response via an isolated provider factory (remote Groq API or offline local Ollama), strictly preventing user text from being elevated to system instructions.
- **Session Registry & Lock Serialization**: Manages active sessions using an in-memory `SessionRegistry` with per-session `asyncio.Lock` serialization, preventing race conditions while bounding conversation memory to the latest 20 turns.
- **Asynchronous Capture Dispatcher (`AuditCapture`)**: As turns progress, state transitions and tool records are enqueued into a bounded, thread-safe in-memory FIFO queue (`queue.Queue(maxsize=512)`). A dedicated daemon thread drains this queue and POSTs events to the audit service.
- **Container Sandboxing**: Operates on a read-only root filesystem (`read_only: true`), with all Linux capabilities dropped (`cap_drop: [ALL]`), privilege escalation disabled (`no-new-privileges:true`), and execution under an unprivileged user (UID 10001). It has no volume mount to the audit database and shares no network route with the reconstruction service.

### 2.2. `audit_service` (Ingestion & Cryptographic Sealing Layer)
The audit service acts as an immutable, write-only cryptographic ledger:
- **Strictly Minimal Attack Surface**: Exposes exactly **one** route: `POST /ingest`. It serves no GET routes, documentation paths (`/docs`, `/openapi.json`), health endpoints, or query APIs.
- **Constant-Time Authentication**: Authenticates every write request using an HTTP Bearer token verified with constant-time byte comparison (`hmac.compare_digest`), preventing timing-attack side channels.
- **Oracle-Resistant Zero-Knowledge Response**: Always replies with a bare acknowledgment: `{"status": "recorded"}` (HTTP 200). It never returns record IDs, sequence numbers, calculated hashes, preceding digests, or echoed payload contents.
- **Serialized Storage Engine**: Manages the SQLite database (`/data/audit.db`) using `PRAGMA journal_mode=DELETE` and `BEGIN IMMEDIATE` transactions to enforce strictly ordered, atomic row insertions across concurrent writes.
- **Cryptographic Envelope Injection**: Automatically injects a protected metadata envelope (`_aegis`) into the payload, sealing the session identifier, event type, and sensitivity flag directly into the hashed string.

### 2.3. `reconstruction_service` (Forensic Verification & DAG Analysis Layer)
The reconstruction service performs forensic verification and graph synthesis over stored audit logs:
- **Hardware-Enforced Read-Only Mounting**: Mounts the audit storage volume in read-only mode (`volumes: [audit_data:/data:ro]`). All database connections are opened using the SQLite URI `file:/data/audit.db?mode=ro` and execute `PRAGMA query_only=ON` within snapshot-consistent transactions (`BEGIN`).
- **Cryptographic Verification Engine**: Traverses stored session records sequentially, verifying:
  1. That each entry's `prev_hash` matches the recomputed hash of the preceding entry.
  2. That stored payloads parse into valid canonical JSON matching the sealed `_aegis` envelope.
  3. That recalculated SHA-256 digests over `timestamp_repr + payload_str + prev_hash` match the stored hash column.
- **DAG Reconstruction & Taint Propagation**: Uses **NetworkX** to generate a directed acyclic graph (DAG) representing the complete event sequence, categorized into three distinct visual tiers: `retrieval`, `state`, and `tool`. When an entry fails verification, the direct corrupt record is identified in `broken_entry_ids`, and downstream nodes are flagged with `tampered: true`.
- **Forensic Export Facility**: Exports forensic packages formatted under the `aegistrace-audit/v1` specification, documenting exact hash inputs, canonicalization rules, and explicit trust boundaries.

### 2.4. `frontend` (Gateway & Investigator Dashboard)
- **Nginx Reverse-Proxy Gateway**: Serves as the single entrypoint (`http://localhost:3000`).
- **Network-Level Access Control (ACL)**: Evaluates the real client IP address. Any request originating from the internal agent network (`172.29.11.0/24` or `172.29.12.0/24`) attempting to access evidence endpoints (`/api/*`) is blocked immediately with `HTTP 403 Forbidden`. Forwarded headers (`X-Forwarded-For`) are ignored to prevent header spoofing.
- **Investigation UI**: Provides an interactive browser workspace featuring live Cytoscape DAG visualization, timeline replay controls, hash ledger inspection, and manual tamper injection testing.

### 2.5. `groq_proxy` (Egress Restriction Sidecar)
- **Squid Proxy Service**: Mediates external network traffic from `agent_service`.
- **Strict Destination Allowlisting**: Rejects direct IP literals and non-whitelisted domain names. Enforces an exact CONNECT rule allowing only `api.groq.com:443`.
- **Zero Direct Internet Routing**: The `agent_service` is attached only to internal Docker bridge networks; it possesses no direct internet gateway.

---

## 3. Network Architecture & Isolation Matrix

AegisTrace partitions services across five isolated Docker bridge subnets:

| Network Name | Subnet | Internal? | Connected Containers | Purpose |
|---|---|---|---|---|
| `agent_net` | `172.29.11.0/24` | **Yes** | `agent_service`, `audit_service` | Authenticated write-only event ingestion |
| `chat_net` | `172.29.12.0/24` | **Yes** | `agent_service`, `frontend` | User chat interaction and response streaming |
| `audit_net` | `172.29.13.0/24` | **Yes** | `audit_service`, `reconstruction_service` | Internal storage tier (no shared network DB port) |
| `dashboard_net` | `172.29.14.0/24` | **No** | `reconstruction_service`, `frontend` | Investigator dashboard and read APIs |
| `groq_egress` | `172.29.15.0/24` | **Yes** | `agent_service`, `groq_proxy` | Restricted LLM provider egress |
| `internet` | Default Bridge | **No** | `groq_proxy` | Public internet route to `api.groq.com:443` |

### Service Interconnection Matrix

| Source Service | Target: `agent_service` | Target: `audit_service` | Target: `reconstruction_service` | Target: `frontend` | Target: `groq_proxy` | Target: Public Internet |
|---|---|---|---|---|---|---|
| **`agent_service`** | — | **Allowed** (`POST /ingest`) | **BLOCKED** (No shared net) | **Allowed** (Chat reply) | **Allowed** (Port 3128) | **BLOCKED** (Internal only) |
| **`audit_service`** | **BLOCKED** | — | **BLOCKED** (No network port) | **BLOCKED** | **BLOCKED** | **BLOCKED** |
| **`reconstruction_service`** | **BLOCKED** | **BLOCKED** | — | **Allowed** (HTTP 8002) | **BLOCKED** | **BLOCKED** |
| **`frontend` (Gateway)** | **Allowed** (`/chat`) | **BLOCKED** | **Allowed** (`/api/*`) | — | **BLOCKED** | Loopback Host Port |
| **`groq_proxy`** | **BLOCKED** | **BLOCKED** | **BLOCKED** | **BLOCKED** | — | **Allowed** (`api.groq.com:443`) |

---

## 4. Cryptographic Methodology & Hash Chain Design

AegisTrace implements an append-only, chained cryptographic data structure inspired by Merkle-Damgård constructions:

### 4.1. Genesis Block
For any session, the initial audit record ($seq = 1$) links to a fixed genesis hash consisting of 64 zero characters:
$$\text{prev\_hash}_1 = \mathtt{0000000000000000000000000000000000000000000000000000000000000000}$$

### 4.2. Canonical Payload Serialization
To guarantee deterministic hashing across varying operating systems, runtimes, and database libraries, JSON serialization follows RFC-compliant canonical rules:
```python
def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False
    )
```
- Lexicographical key sorting (`sort_keys=True`).
- Complete elimination of whitespace padding (`separators=(",", ":")`).
- Native UTF-8 preservation for non-ASCII unicode characters (`ensure_ascii=False`).
- Strict rejection of IEEE 754 non-finite float constants (`NaN`, `Infinity`).

### 4.3. Sealed Metadata Envelope (`_aegis`)
To prevent an attacker with direct SQL access from modifying table columns (e.g., changing `session_id`, renaming `event_type`, or unflagging `sensitive_action_flag`), the audit service automatically embeds an immutable envelope inside the payload before serialization:
```json
{
  "_aegis": {
    "schema_version": 1,
    "session_id": "SOC-248b6b9a",
    "event_type": "tool_start",
    "sensitive_action_flag": true
  }
}
```
During verification, the recomputed envelope is cross-checked against stored SQL columns. Any discrepancy causes immediate verification failure.

### 4.4. Hash Recurrence Formulation
For entry $i$, the cryptographic digest is computed as:
$$\text{hash}_i = \text{SHA-256}\Big(\text{UTF-8}\big(\text{repr}(\text{timestamp}_i) + \text{payload\_str}_i + \text{prev\_hash}_i\big)\Big)$$

```python
def entry_hash(timestamp: float, payload_str: str, prev_hash: str) -> str:
    timestamp_repr = str(float(timestamp))
    concatenated = (timestamp_repr + payload_str + prev_hash).encode("utf-8")
    return hashlib.sha256(concatenated).hexdigest()
```
*Normalization*: SQLite normalizes negative zero (`-0.0`) to `0.0`. AegisTrace normalizes `timestamp = 0.0 if body.timestamp == 0 else body.timestamp` to prevent sign discrepancies.

---

## 5. Working Mechanisms

### 5.1. Non-Blocking Capture Lifecycle
1. **Turn Receipt**: User submits prompt to `POST http://localhost:3000/chat`.
2. **Gateway Evaluation**: Nginx verifies the client origin is external to internal agent subnets and routes to `agent_service:8000/chat`.
3. **Session Concurrency Lock**: The agent acquires an asynchronous session lock (`session.lock`).
4. **Graph Execution & Asynchronous Ingestion**:
   - `classify_node` categorizes input.
   - `emit()` enqueues events non-blockingly via `AuditCapture.capture()`.
   - The detached daemon worker pops events and POSTs them to `http://audit_service:8001/ingest`.
   - `audit_service` opens `BEGIN IMMEDIATE`, fetches the latest hash for that session, computes the SHA-256 digest, inserts the record, and commits.
5. **Tool Execution**: `tool_node` executes simulated tools, emitting `tool_start` and `tool_end` events.
6. **Model Inference**: `respond_node` queries Groq via `groq_proxy:3128`.
7. **Client Reply**: The agent returns the response to the user without waiting for audit disk commits.

### 5.2. Verification & DAG Reconstruction Lifecycle
1. The investigator opens the dashboard or queries `GET /api/session/{session_id}/verify`.
2. `reconstruction_service` begins a consistent snapshot read (`BEGIN` with `PRAGMA query_only=ON`).
3. Verification initializes `previous = "0" * 64`.
4. The verification algorithm processes records in ascending order:
   - Verifies `row.prev_hash == previous` (detects deletions, insertions, reordering).
   - Verifies `row.payload._aegis` matches the database row columns (detects column tampering).
   - Computes `computed = entry_hash(row.timestamp, row.payload, row.prev_hash)`.
   - Compares `computed == row.hash` (detects payload or timestamp alterations).
   - Updates `previous = row.hash`.
5. Events are grouped into topological tiers (`retrieval`, `state`, `tool`).
6. Nodes downstream of the first broken entry are marked with `tampered: true`.

---

## 6. Comprehensive Empirical Evaluation & Benchmark Results

A complete, honest evaluation of AegisTrace was performed on **September 16, 2026**, executing five distinct empirical evaluations under deterministic synthetic workloads.

### Evaluation Environment & Hardware

- **Date of Execution**: September 16, 2026
- **Hardware Platform**: Intel Core i5-13420H (8 physical cores, 12 logical threads, base 2.1 GHz, boost up to 4.6 GHz), 16.0 GB DDR5 RAM
- **Operating System & Runtime**: Windows 11 Pro, Docker Desktop with WSL2 Linux kernel (Debian 12 base, Python 3.12 within container network)
- **Workload**: Deterministic synthetic test events and deterministic mock LLM provider returns (zero live Groq API inference calls) to ensure reproducible, zero-cost measurements.

---

### 6.1. Metric 1: Tamper Detection Reliability

Evaluated across 100 clean synthetic sessions (~20 events each) and 100 tampered synthetic sessions (~20 events each), where each tampered session underwent an out-of-band payload mutation at a uniformly randomized position ($1 \le pos \le 20$). Cryptographic integrity was assessed via `/api/session/{session_id}/verify`.

| Metric | Sample Size | Observed Result | Rate / Accuracy |
|---|---|---|---|
| **Detection Rate** (Tampered Sessions Flagged) | 100 sessions | 100 correctly flagged (`chain_intact: false`) | **100.0%** (100/100) |
| **False Positive Rate** (Clean Sessions Flagged) | 100 sessions | 0 incorrectly flagged (`chain_intact: true`) | **0.0%** (0/100) |
| **Localization Accuracy** (Broken Entry ID & Position Matched) | 100 sessions | 100 correctly localized to exact mutated ID and sequence position | **100.0%** (100/100) |

The cryptographic hash chain achieved a 100% detection rate across all mutated sessions with zero false positives on clean histories. In all 100 tampered cases, the verification engine accurately identified the exact database primary key and 1-indexed sequence position of the modified record.

---

### 6.2. Metric 2: Isolation & Oracle-Resistance Verification

Evaluated directly from within the `agent_service` container network namespace to determine whether an adversarial or compromised agent process can access the SQLite database, inspect reconstruction state, or extract sensitive audit metadata.

| Attempt Type | Observed Result | Isolation Claim |
|---|---|---|
| **Direct connection to SQLite audit database file or host** | **Blocked**: Volume is not mounted in agent container (`/data/audit.db` does not exist); direct network connections to internal storage and gateway ports failed | **Pass** |
| **Direct HTTP request to reconstruction_service endpoints** | **Blocked**: Direct requests to `reconstruction_service:8002` failed via DNS non-resolution and TCP connection timeouts; reverse-proxy gateway blocked access with HTTP 403 Forbidden | **Pass** |
| **Reading data back from audit_service `/ingest` response** | **No data returned**: Ingest endpoint returned strictly `{"status":"recorded"}`; response contained no hashes, IDs, sequence markers, or echoed payloads; all GET/read endpoints returned 404/405 | **Pass** |

The network architecture and write-only API contract successfully isolate the agent, preventing it from reading stored evidence, inspecting verification status, or using the audit service as an oracle. All direct database connections, reconstruction queries, and data extraction attempts were blocked.

---

### 6.3. Metric 3: Audit Layer Overhead

Measured over 1,000 synthetic tool-call turns through the agent graph under two conditions: audit capture middleware DISABLED and audit capture middleware ENABLED (normal production operation posting to `audit_service`). A 100-event warm-up preceded each condition (warm-up measurements discarded), and the full 1,000-event workload was repeated across 5 independent trials per condition (5,000 total measured events each).

#### Overall Latency Summary (5,000 Events per Condition)

| Condition | Median Latency (ms) | p95 Latency (ms) | Mean Latency (ms) |
|---|---|---|---|
| **Audit Capture DISABLED** | 1.756 | 2.386 | 1.822 |
| **Audit Capture ENABLED** (Normal Operation) | 2.301 | 3.657 | 2.414 |
| **Difference (Audit Layer Cost)** | **+0.545** | **+1.271** | **+0.592** |

#### Per-Run Breakdown (1,000 Events per Trial)

| Trial | Disabled Median (ms) | Disabled p95 (ms) | Enabled Median (ms) | Enabled p95 (ms) |
|---|---|---|---|---|
| **Run 1** | 1.725 | 2.233 | 2.305 | 3.779 |
| **Run 2** | 1.700 | 2.342 | 2.308 | 3.664 |
| **Run 3** | 1.856 | 2.486 | 2.320 | 3.564 |
| **Run 4** | 1.762 | 2.441 | 2.298 | 3.644 |
| **Run 5** | 1.746 | 2.374 | 2.267 | 3.626 |

The asynchronous bounded FIFO capture worker imposes a sub-millisecond median overhead of +0.545 ms (+1.271 ms at p95) on the agent's turn execution. Because audit event ingestion is decoupled from the agent request lifecycle, tamper-evident logging adds virtually no perceptible latency to model reasoning and tool invocation.

---

### 6.4. Metric 4: Verification Scaling

Evaluated on sessions containing 10, 100, 1,000, and 10,000 synthetic entries to analyze computational scaling of the `/api/session/{session_id}/verify` endpoint (performing canonical JSON re-serialization, SHA-256 hash chaining, error localization, and DAG reconstruction).

| Entry Count | Server Verification Time (`durationMs`) | Total HTTP Round-Trip Time (ms) |
|---|---|---|
| **10** | 0.14 ms | 2.59 ms |
| **100** | 0.91 ms | 4.41 ms |
| **1,000** | 7.62 ms | 20.42 ms |
| **10,000** | 108.10 ms | 248.36 ms |

Verification runtime scales linearly (\(O(N)\)) with session size, taking under 1 millisecond for typical sessions (100 events) and approximately 108 milliseconds for an extensive 10,000-event trajectory. Even without caching, complete cryptographic verification and graph reconstruction remain fast enough for real-time validation.

---

### 6.5. Metric 5: Naive-Logging Baseline Comparison

Evaluated using the identical 1,000-event synthetic tool-call workload across 5 independent trials (5,000 measured events, following a discarded 100-event warm-up) to benchmark AegisTrace against a naive in-process synchronous SQLite logging implementation lacking container isolation, network segregation, and cryptographic hash chaining.

| Condition | Median (ms) | p95 (ms) |
|---|---|---|
| **A — No audit layer** | 1.756 | 2.386 |
| **B — Naive synchronous logging** | 2.258 | 3.172 |
| **C — AegisTrace (isolated, async, hash-chained)** | 2.301 | 3.657 |

AegisTrace's median overhead over the unlogged baseline (Condition A) is +0.545 ms, which is directly comparable to naive synchronous logging's +0.502 ms overhead (a difference of only 0.043 ms between Conditions B and C). At the 95th percentile, AegisTrace incurs a modest 0.485 ms higher latency than naive logging (3.657 ms vs. 3.172 ms), confirming that strong isolation and tamper-evident hash chaining introduce negligible latency penalty compared to an unhardened in-process write.

---

## 7. Security Boundaries & Threat Model Disclosures

AegisTrace explicitly defines its trust boundaries to prevent overstated security guarantees:

### 7.1. Guaranteed Protections
- **Agent Self-Tampering**: An adversarial prompt injection cannot alter existing audit entries or delete prior tool steps.
- **Oracle-Based Evasion**: The agent cannot check whether its actions triggered security alarms or inspect audit ledger contents.
- **Out-of-Band Modifiers**: Any third party or process altering stored rows without knowing the write token will invalidate the SHA-256 chain.
- **Middle-Row Deletions & Insertions**: Removing or inserting an event in the middle of a history causes an immediate link mismatch (`prev_hash != calculated_previous`).

### 7.2. Inherent Boundaries & Production Hardening
1. **Suffix Truncation Limitation**: Hash chaining guarantees internal consistency from genesis forward. However, if an adversary deletes the most recent $K$ entries from the tail of a session, the remaining prefix remains internally valid. To detect suffix deletion, the system must be paired with an **external head anchor** (e.g., periodic signed checkpoints published to a transparency log or witness service).
2. **Storage Administrator Privilege**: A root administrator on the Docker host with access to `/data/audit.db` can recalculate hashes for an entire rewritten session. Evidentiary permanence against storage admins requires WORM (Write Once, Read Many) physical storage or cryptographic threshold signing.
3. **Single-Process Capture Model**: The current bounded FIFO queue lives in-memory in the agent container. An abrupt power cut or `kill -9` could drop un-flushed in-flight events. For mission-critical environments, a local write-ahead log (WAL) spool should precede network dispatch.

---

## 8. Summary Table of Technical Specifications

| Parameter | Specification |
|---|---|
| **Core Architecture** | Microservice-isolated write-only sink and read-only validator |
| **Agent Framework** | LangGraph, FastAPI, Python 3.12 |
| **Hash Algorithm** | SHA-256 (256-bit cryptographic digest) |
| **Serialization Standard** | Canonical JSON (sorted keys, compact separators, UTF-8) |
| **Database Engine** | SQLite 3 (WAL/DELETE journal mode, `BEGIN IMMEDIATE` transactions) |
| **Container Sandbox** | Read-only roots, UID 10001, `cap_drop: [ALL]`, `no-new-privileges` |
| **Network Isolation** | 5 internal Docker bridge networks; Squid CONNECT egress proxy |
| **Verification Complexity** | $O(N)$ linear time complexity |
| **Capture Latency Overhead** | +0.545 ms (median) per turn |
| **Tamper Detection Accuracy** | 100.0% detection rate; 0.0% false positive rate |
| **Export Specification** | `aegistrace-audit/v1` JSON forensic package |
