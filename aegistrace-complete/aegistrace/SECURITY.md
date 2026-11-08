# Security boundaries and deployment notes

## Reporting a vulnerability

Use GitHub's private vulnerability reporting (Security tab, "Report a vulnerability"). Do not open a public issue for a security report.

## What AegisTrace detects — and what it does not

AegisTrace is a research prototype provided without warranty. It is not "tamper-proof" or "unhackable", and it does not make a compromised host trustworthy.

It can expose specified forms of tampering with recorded evidence: editing a payload or covered metadata without recomputing its hash, breaking a stored hash link, deleting a middle row, reordering entries, and some per-session sequence gaps or duplicates through `client_seq`. The separate anchor service stores periodic checkpoints, so changes to checkpointed history can also be detected.

It does **not** prove that every event was captured, prevent deletion of a suffix or a whole session when that history was never anchored, detect a storage administrator who rewrites and rehashes the entire chain before it is anchored, authenticate end users, authorize per-session access, provide multi-tenancy, or attest to agent-supplied timestamps. Capture is best effort; anchoring does not repair events that were never delivered.

## What is isolated

The agent has no SQLite volume and shares no Docker network with reconstruction or anchoring. `agent_net`, `chat_net`, `audit_net`, `anchor_net`, and `groq_egress` are internal Docker networks. The agent can reach the sink's write-only HTTP interface and the frontend gateway; its only internet path is through the Groq proxy. The sink has no HTTP read functionality, even with a valid write token. Reconstruction mounts the audit and anchor volumes read-only; the agent has no volume containing either.

The host-facing `dashboard_net` bridge is not marked internal, so it is not a complete egress boundary. Published ports bind to loopback only, and the host firewall/DNS policy described below must restrict outbound traffic from that bridge. Do not treat Docker networking alone as a sandbox.

The sink accepts writes only with `AUDIT_WRITE_TOKEN`, and the anchor service accepts checkpoints only with `ANCHOR_WRITE_TOKEN`. These are independent secrets: compromise of the audit write token does not authorize anchor writes. Audit and reconstruction share a directory volume—not a network database port.

The gateway is a necessary cross-boundary component: it can call both agent and reconstruction. Therefore it rejects every request whose actual peer address is any of the agent's fixed addresses, before dispatching to a route. It does not trust `X-Forwarded-For` for this decision. Without this rule, network separation alone would leave an indirect read oracle. Capabilities are dropped and IP addresses are fixed; update the ACL and tests if you change subnets.

The Groq egress proxy is the only service attached to the explicit `internet` network. Squid permits the agent to establish a CONNECT tunnel to the exact destination `api.groq.com:443`; other names, ports, literal/private destinations, and proxy methods are denied. TLS verification is performed by the provider SDK. This is a domain/port policy, not request-path inspection or TLS interception.

**Docker runtime verification is still required on your host.** Run `tests/docker_isolation.py`. A build machine without a Docker daemon cannot certify host firewall behavior. Use a current Docker Engine; older Docker releases have had loopback-publishing and inter-network isolation caveats.

### Host hardening for a stronger threat model

Docker internal bridges are not an exhaustive information-flow sandbox. Docker's embedded DNS may resolve outside names even when direct TCP egress is blocked. A compromised process could attempt DNS-based leakage. Constrain upstream DNS to an approved resolver/policy, restrict outbound DNS at the host, disable or explicitly filter IPv6, and enforce a DOCKER-USER/nftables policy appropriate to your Docker backend.

Recommended agent-origin policy: permit established replies, the sink on port 8001, the proxy on port 3128, and approved name resolution; deny all other newly initiated flows, including host/gateway administration ports. Permit frontend-initiated chat connections to the agent on 8000. Do not run arbitrary commands from copied firewall snippets without reconciling your existing host rules.

The Docker host, root, Docker socket, sink, gateway, reconstruction, anchor service, and provider configuration are trusted components. No Docker socket is mounted. Services run without added Linux capabilities; application containers use nonroot UID 10001 and read-only root filesystems. The writable audit and anchor volumes are owned by UID 10001; do not share them with the agent or unrelated services.

## Integrity and verification

The sink stores the `audit_log` schema and hashes the exact string `timestamp + payload_str + prev_hash` using SHA-256. A sink-owned schema-v2 `_aegis` envelope covers session, type, sensitive flag, and `client_seq`, and is checked against columns during verification. Labels and tool data are inside the payload. Database row IDs, display sequence numbers, and graph positions are not authenticated identities. Event timestamps are agent-supplied observations, not trusted wall-clock attestations.

Verification independently checks each row's hash, preceding stored-hash link, and the injected envelope and sequence metadata. `broken_entry_ids` contains direct failures. Graph `tampered` flags propagate downstream, but downstream taint does **not** assert that those payloads were edited. The graph is a conservative chain-shaped NetworkX DAG of recorded dependencies; it does not infer internal model reasoning.

Detectable examples: modifying a payload without rehashing, editing covered metadata, breaking a link, deleting a middle row, reordering entries, and some `client_seq` gaps or duplicates. The anchor service stores append-only checkpoints of the chain head; because delivery is asynchronous and may fail, the unanchored tail is not bounded by a fixed number of events. A database owner who rewrites and rehashes history that has not yet been anchored can create another internally consistent chain. Deleting an unanchored suffix—or an entire session—cannot be detected without an independent trusted checkpoint. Store independent signed head checkpoints and protected backups when evidentiary permanence against storage administrators is required.

## Capture is intentionally best effort

The agent enqueues capture events without waiting for the sink. One bounded FIFO worker preserves delivery order; the agent never branches on ingestion success. Queue overflow, abrupt process termination, serialization rejection, a slow/unavailable sink, or a request timeout can lose events. There is no durable local spool, sink acknowledgement exposed to the agent, replay retry, deduplication token, or exactly-once guarantee.

Only evidence accepted by the sink is durable. The UI independently polls reconstruction for the matching terminal turn ID and warns when capture is unconfirmed. It never manufactures an audit event to cover missing evidence. Anchoring is also asynchronous and best effort: a failed checkpoint does not restore missing events. For reliable completeness, design a trusted capture supervisor/durable buffer and externally anchored receipts; do not silently make the agent wait for sink acknowledgement because that changes the non-blocking behavior.

Per-session turn serialization and bounded history live in one agent process. Run one worker/replica with this implementation. Restarting the agent clears conversational memory, not stored audit evidence. FIFO ordering is local to that process; the sink serializes all accepted writes across sessions with SQLite transactions.

## Sensitive actions

Classification uses action verbs plus evidence-target nouns, including the "make changes to the log" example. The flag does not gate tools. The same simulated action completes for sensitive and ordinary requests, producing start/end events. `action_executed=true` means the **mock tool** ran; `real_world_action_executed=false` and `simulated=true` explicitly distinguish it from real evidence modification. There is no ledger-editing tool available to the model. Amber is review metadata, not failed cryptography.

## Same-origin gateway, CORS, and the demo mode

The default browser entry point is the Nginx gateway on `http://localhost:3000`, which serves the frontend and routes chat and reconstruction calls behind one origin. CORS middleware exists only on the agent and reconstruction services; the audit and anchor services expose no CORS and no browser-facing routes. `ALLOWED_ORIGINS` is an explicit comma-separated list. `ALLOWED_ORIGINS=*` is an insecure-for-private-data opt-in, emits a startup warning, and browser credentials remain disabled.

In the default deployment, reconstruction mounts `/data` read-only, opens every read connection using `mode=ro` and `query_only=ON`, and has no tamper route registered. A `DEMO_MODE` entry in `.env` alone does not change that configuration.

`compose.demo.yaml` explicitly enables presenter-only demo endpoints and replaces reconstruction's volume mount with read/write access. Only the tamper handler opens a separate `mode=rw` connection; it changes the selected row's payload without altering hashes. This is an intentional weakening of investigator privilege for a presenter, not a production capability. The gateway includes a basic chat rate limit, but that is not full abuse protection and does not make demo evidence trustworthy. Use only fictional data on loopback. Disable by recreating services without the override. Already altered demo records remain altered.

## Deploying publicly

Before exposing a deployment beyond loopback:

- Set `ALLOWED_ORIGINS` to the exact HTTPS origin(s) of the frontend; leave `AEGIS_API_BASE` consistent with the chosen gateway.
- Rotate both `AUDIT_WRITE_TOKEN` and `ANCHOR_WRITE_TOKEN` to independent random values, and replace environment credentials with managed secrets where possible.
- Never expose the audit or anchor services to the browser, LAN, or internet; keep their ports unpublished and their networks internal.
- Keep provider credentials such as `GROQ_API_KEY` on the backend only; never place them in frontend files or browser-visible configuration.
- Add TLS, end-user authentication, per-session authorization, quotas, retention/backup controls, and host firewall/DNS policy. This tree is a single-operator research prototype, not an authenticated multi-tenant service.

## Exposure and data handling

Host ports bind to `127.0.0.1`. The read/chat APIs intentionally have no end-user authentication or per-session authorization: all local operators can read all cases. Session IDs are identifiers, not access tokens. Do not publish these ports to a LAN or internet without adding TLS, authentication, per-session access checks, quotas, and export/tamper controls.

Chat sends the message, recent in-memory conversation, and fictional tool result to the configured provider. Audit payloads store user messages and responses. Do not enter secrets or regulated evidence without an appropriate provider/privacy/retention agreement. The landing page uses CDN resources; it retains a transcript fallback when Cytoscape is unavailable. To eliminate browser-side third-party requests, vendor Cytoscape and optional fonts locally.

Application access logs are disabled to avoid recording prompt bodies or session URLs. Errors returned to the UI are generic. `.env` and databases are excluded from the source bundle and image build context. For higher-assurance deployments replace environment credentials with managed secrets, rotate write tokens, and apply independent storage/retention controls.
