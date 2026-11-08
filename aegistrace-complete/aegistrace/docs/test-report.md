# Validation report

## Passed in the build environment

**32 automated tests**, final run: all passed. Coverage includes:

- Requested `audit_log` schema, bearer-only authorization, 403 rejection, no read/docs/health routes on the sink, and constant write-only success responses.
- Canonical hash reproduction from exported exact strings, 64-zero genesis, sink-owned metadata, session isolation, and 32 concurrent ingests across two sessions.
- Payload, metadata, timestamp, malformed JSON, and previous-link tampering; middle deletion detection; explicit suffix-deletion limitation.
- Direct-vs-downstream failure distinction, graph tiers, JSON case export, unknown/invalid sessions, cross-session tamper rejection, read-only connections, and absence of production demo routes.
- LangGraph chat for questions, ordinary requests, sensitive actions, and casual messages; session history separation; provider errors; FIFO/queue bounds; nonblocking behavior with a stalled/failing sink; Groq/Ollama factory selection; server-owned fixture dispatch.
- Static Compose-policy assertions: no agent DB mount, no shared reconstruction network, internal agent networks, read-only default reconstruction, exact-host proxy policy, gateway denial addresses, explicit demo override.

**Full browser integration passed** with the supplied UI and three live local HTTP services behind Nginx. The LLM alone was injected with a deterministic test provider; HTTP dispatch, SQLite writes, SHA-256 verification, reconstruction, export, and browser code were real.

The browser test exercised:

1. Try It Yourself submission of “make changes to the log.”
2. Background HTTP ingestion and stored sensitive flag; mock action executed normally.
3. Amber graph/transcript styling with an intact chain.
4. Artifact inspector and stored hashes.
5. Actual SQLite payload mutation through the demo endpoint.
6. Red mismatch and dimmed downstream graph/transcript nodes.
7. Server-generated JSON download with failed verification and unchanged original hash.
8. Timeline/replay controls and persisted evidence after reload.
9. Verified and tampered scripted modes using server ingestion.
10. Sanitized provider failure displayed in Live Agent with the failed turn recorded.
11. Zero browser JavaScript errors.
12. Nginx source-denial behavior on a loopback-emulated agent peer, including forged `X-Forwarded-For`.

A screenshot is included as `docs/e2e-tamper.jpg`. The browser test intercepts the Cytoscape CDN request using a locally installed copy; other external browser resources are blocked, so no internet or provider dependency is needed for the test.

Nginx configuration syntax passed using locally substituted upstream addresses. Squid configuration parsing passed. JavaScript syntax checks passed. Dependency installation succeeded for the pinned Python requirements.

## Not validated here

- **Docker images, Compose startup, volume permissions, runtime inter-network filtering, and host firewall behavior:** no Docker daemon was available. Static configuration tests are not a substitute for these checks. Run `tests/docker_isolation.py` on the target Docker host.
- **Real Groq inference / key validity / successful outbound Groq TLS:** no Groq key was supplied.
- **Real Ollama inference:** no model/server was provisioned. The factory, local-provider selection, and failure behavior were tested with injected constructors, not a model download.
- Load/soak performance, disaster recovery, cross-host storage, multi-replica agent ordering, penetration testing, public multi-user authentication, and independent external hash anchoring.

Two library-level deprecation warnings were present; no test failure or application error resulted. No real provider credentials, runtime `.env`, or evidence database are included in the deliverable.
