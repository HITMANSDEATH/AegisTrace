# AegisTrace — server-backed evidence room

Application-level guide for the layout described in the [project README](../../README.md). Four Python services provide agent execution, write-only audit ingestion, read-only reconstruction and separate anchoring; Nginx supplies a same-origin gateway and a narrow Groq egress proxy controls model access.

**Validation scope:** [the original test report](docs/test-report.md) is historical evidence, not a certification of the current release. Current CI checks run without real provider keys; Docker network enforcement must still be verified separately against the release's clean clone.

## 1. Configure

Requires Docker Engine 28+ with Compose v2, available subnet range `172.29.11.0/24`–`172.29.16.0/24`, and a Groq key for live inference.

Run commands in this guide from `aegistrace-complete/aegistrace/`. This directory's `.env.example` is the canonical public template; Compose reads this directory's private `.env` (not a root template).

```sh
# New checkout only; preserve an existing .env.
cp .env.example .env
```

Set independently generated random values for `AUDIT_WRITE_TOKEN` and `ANCHOR_WRITE_TOKEN` in `.env`. Set `GROQ_API_KEY` there for live inference. Default model: `llama-3.3-70b-versatile`. Credentials never enter the browser. `.env` is excluded from Git and Docker build contexts. An empty/misconfigured Groq key produces a sanitized, recorded `503 live_agent_unavailable`, not a silent mock response. An absent Groq key does not prevent startup or browser-only simulation.

## 2. Start

**Normal, read-only reconstruction:**

```sh
docker compose up --build -d
```

**Presenter/demo deployment, including scripted modes and tamper injection:**

```sh
docker compose -f compose.yaml -f compose.demo.yaml up --build -d
```

Open **http://localhost:3000**. Read API/direct static frontend: http://localhost:8002. Use port **3000 for interactive chat**; it provides the same-origin agent gateway. Agent and audit ports are not published.

Try It Yourself and the landing-page chain lab are browser-local simulations and work without a backend. Live Agent calls the real `/chat` backend. The verified/tampered scripted modes require the demo override and do not call a model; they exercise server ingestion, persistence, reconstruction and tampering.

Same-origin routing is the default: leave `AEGIS_API_BASE` empty. For a separate static frontend, set `window.AEGIS_API_BASE` in that deployment's `frontend/config.js` to the backend gateway URL and set backend `ALLOWED_ORIGINS` to the frontend's exact origin. Reconstruction serves `/config.js` from `AEGIS_API_BASE` when it hosts the frontend. See [CORS troubleshooting and separate hosting](../../README.md#separately-hosted-frontend); no agent/audit port publication is needed.

### Exercise the thesis

1. In Try It Yourself, submit **“make changes to the log.”** The same mock action runs normally; amber flags are recorded. The chain still verifies.
2. Open an artifact to inspect payload and hashes. Move the timeline or replay it.
3. In demo deployment, click **Inject demo tamper**. The payload in SQLite changes without updating its hash. The first bad artifact turns red; affected downstream artifacts dim.
4. **Export case** downloads server JSON containing the full entries, exact hash inputs, verification, and graph.
5. Stored live evidence remains accessible through the session API. **Reset case** opens a new ID; it does not erase stored backend records. Browser-local Try It Yourself data is not durable backend evidence.

Capture is asynchronous. The UI waits for a terminal recorded event and explicitly reports pending/unavailable evidence rather than inventing a sealed response.

## 3. Architecture

```text
Browser -> frontend gateway -> reconstruction_service -> SQLite (read-only)
                          \-> agent_service
                                  |            \-> Groq-only CONNECT proxy -> api.groq.com:443
                                  \-> audit_service /ingest -> SQLite (read/write)
```

- `agent_service`: LangGraph classify → mock tools → provider response. Bounded per-session history and turn serialization; bounded FIFO background capture. No audit volume, no audit/reconstruction network, no direct internet network.
- `audit_service`: exactly one route, `POST /ingest`. Bearer token required; unauthorized calls return 403. Replies only `{"status":"recorded"}`. No docs, health, read, or debugging endpoints. Docker health checks inspect SQLite locally, not over HTTP.
- `reconstruction_service`: SQLite URI `mode=ro`, `query_only=ON`, consistent read snapshots, hash/link/metadata verification, NetworkX recorded-order DAG, entries, sessions, export, and static frontend hosting.
- `anchor_service`: separate authenticated append-only checkpoint service on `anchor_net`, with its own named volume; reconstruction reads the volume read-only, while the agent has no access. Anchor delivery is asynchronous and may fail, so the unanchored tail is not guaranteed to stay below a fixed number of events.
- `frontend`: Nginx same-origin gateway. Agent-source addresses are denied before proxying, preventing the gateway from becoming an indirect evidence-reading route. Forwarded headers cannot override source-address checks.
- `groq_proxy`: only exact-host `CONNECT api.groq.com:443` from the agent's egress address; other hosts/ports and private destinations denied. Only the proxy attaches to the internet network.

The demo override deliberately grants reconstruction a writable volume and registers the presenter-only tamper handler. Normal handlers still use read-only connections. **Do not enable demo mode with real evidence.**

The supplied landing-page chain lab remains explicitly browser-local and educational. Its hash format is separate from backend evidence. Workspace rendering preserves the original event/verification aliases and three-tier positions; details are in [frontend contract](docs/frontend-contract.md).

## 4. API

| Method | Route | Purpose |
|---|---|---|
| POST | `/chat` | `{session_id,message}` → `{response,event_type,sensitive_action_flag,turn_id}` |
| POST | `/ingest` | Audit-network-only authenticated write; no evidence echoed |
| GET | `/api/config` | Demo capability flag |
| GET | `/api/sessions` | IDs, verified/tampered status, counts |
| GET | `/api/session/{id}/entries` | Ordered numeric-ID entries, parsed payload and exact `payload_str` |
| GET | `/api/session/{id}/verify` | Chain verdict, direct broken entry IDs, renderer aliases |
| GET | `/api/session/{id}/graph` | Snapshot-consistent nodes, edges, events, verification |
| GET | `/api/session/{id}/export` | Downloadable full JSON evidence case |
| POST | `/api/session/{id}/tamper` | Demo only; `{entry_id,payload}`; selected row must belong to session |
| POST | `/demo/session` | Demo only, on agent; `{session_id,mode}` queues authored server fixtures |

Missing sessions return 404; invalid input 422; unavailable database/provider 503. Read API errors and provider errors are sanitized. The graph uses **recorded-order dependencies**, not a claim to recover private chain-of-thought or unobserved causality.

### Hash protocol

The schema is the requested `audit_log` table. Inserts are serialized with `BEGIN IMMEDIATE`. Each session begins with 64 zero characters:

```python
payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False)
hash = hashlib.sha256((str(float(timestamp)) + payload_str + prev_hash).encode("utf-8")).hexdigest()
```

The sink injects a schema-v2 `_aegis` envelope into the hashed payload, mirroring session, type, sensitive flag and the supplied client sequence, so column-only edits and some sequence gaps are detectable. Exports include `timestamp_repr` and `payload_str`; use those exact strings, not another language's reserialized JSON. Negative-zero timestamps normalize to `0.0` before storage.

Hash chaining shows internal consistency, not completeness of capture or immutability against the trusted host administrator. The separate anchor service can expose changes to checkpointed history, but asynchronous delivery failures and unanchored tails remain limitations. [SECURITY.md](SECURITY.md) describes the current trust boundaries and reporting process.

## 5. Ollama / offline provider

Ollama is an explicit alternative, not a silent fallback after Groq errors; the same `get_llm()` factory selects it through `LLM_PROVIDER`. **No Compose override for Ollama is shipped yet**, so this tree does not currently provide a containerized offline-inference deployment. Do not merge networks or relax the isolation described above to work around that.

For a native process, install Ollama on the host, pull a model (several GB; adequate RAM/disk required), and set `LLM_PROVIDER=ollama`, `OLLAMA_MODEL`, and `OLLAMA_BASE_URL` (for example `http://127.0.0.1:11434`) for the agent process. Air-gapped hosts can use a locally provisioned model directory.

## 6. Tests and deployment checks

```sh
# Start in the application directory, create/use the repository-root environment.
cd ../..
python -m venv .venv
. .venv/bin/activate
python -m pip install -r aegistrace-complete/aegistrace/requirements-dev.txt
cd aegistrace-complete/aegistrace
python -m pytest -q tests ../../benchmarks/tests
node --test tests/frontend_api.test.mjs
# Against the actual started Docker deployment:
python tests/docker_isolation.py
# If using demo overrides:
COMPOSE_FILES=compose.yaml:compose.demo.yaml python tests/docker_isolation.py
```

The isolation test checks direct reconstruction reachability, gateway read denial even with forged forwarding headers, ingest auth, lack of read routes, proxy denials, direct TCP egress, no agent DB mount, and read-only reconstruction.

`tests/e2e_browser.py` runs the real UI through local HTTP services with a fake LLM. It additionally requires Nginx, Playwright/Chromium, and a local Cytoscape 3.26.0 JS file (path supplied with `CYTOSCAPE_JS`). No provider key is required. `docs/e2e-tamper.jpg` is the resulting tested UI.

The public tree contains the already integrated `frontend/` and standalone `agent/demo_fixtures.json`. The agent loads that JSON directly; no legacy frontend or transformation script is needed at build/runtime or by the active tests. Node is only needed for optional frontend syntax/unit checks, not application runtime.

## Native development (without Docker)

Activate the repository-root virtual environment and run from this application directory. Set `DB_PATH` to a local writable path such as `data/audit.db` and `ANCHOR_DATA_DIR` to `data/anchors`. Provide fresh, matching `AUDIT_WRITE_TOKEN` values to agent/audit and matching `ANCHOR_WRITE_TOKEN` values to audit/anchor. Set `AUDIT_SINK_URL=http://127.0.0.1:8001/ingest`, `ANCHOR_SINK_URL=http://127.0.0.1:8003/anchor`, and `FRONTEND_DIR=frontend`. Configure provider variables only in the agent process; no `.env` is automatically loaded by these commands.

Start each command in a separate terminal with the appropriate environment:

```sh
python -m uvicorn anchor.main:app --host 127.0.0.1 --port 8003
python -m uvicorn audit.main:app --host 127.0.0.1 --port 8001
python -m uvicorn agent.main:app --host 127.0.0.1 --port 8000
python -m uvicorn reconstruction.main:app --host 127.0.0.1 --port 8002
```

Audit creates its schema and parent directory at startup. Reconstruction's `/health` returns 200 only when its configured database is readable; agent's `/health` does not call a provider. Native processes do not enforce Docker network/volume isolation. For full interactive routing, use a separate local Nginx configuration with the upstream service names replaced by loopback addresses; do not change the checked-in isolated Docker configuration or point a single frontend base at only the agent service. The `tests/e2e_browser.py` harness demonstrates this local proxy arrangement.

Historical reports and selected result files live at the repository root. Excluded raw output/log directories are listed in the [project README](../../README.md#raw-data-and-reproduction); experiment instructions are in the [benchmark guide](../../benchmarks/README.md).

## Operational boundaries

This is a loopback-only, single-operator implementation, not an authenticated multi-tenant service. Before public deployment add TLS, identity, per-session authorization, quotas, retention policy, backups/checkpoints, and host firewall/DNS controls. Keep one agent worker for ordered capture and in-memory session locking; SQLite uses a local Docker volume, not network storage. A host/Docker administrator is trusted.

Stop without deleting evidence: `docker compose down`. **`docker compose down -v` deletes evidence volumes**; use only when you deliberately intend to destroy demo data.
