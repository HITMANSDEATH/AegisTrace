# Step 0 — frontend inspection (before backend implementation)

Inspected all five JavaScript files (`session.js`, `graph.js`, `audit-chain.js`, `fixtures.js`, `landing.js`) and both HTML pages in the supplied archive.

## Existing HTTP checklist
- **No fetch, XMLHttpRequest, WebSocket, or backend API calls exist.** No API base URL exists.
- `session.js` uses local `sealEvents`, `appendEvent`, `verifyChain`, fixture generation, in-memory payload mutation, and Blob JSON export.
- Live mode is an unavailable placeholder; Try mode is rule-based. Existing simulated sensitive actions are blocked, contrary to the requested backend behavior; this is replaced.
- External resources: Cytoscape CDN and CSS fonts only.

## Exact renderer contract to preserve
- Event: `{id: 'evt-001', seq: 1, session_id, timestamp: ISO string, type, label, payload: object, parent_ids: string[], flagged: boolean, prev_hash, hash}`.
- Verification: `{ok, checked, firstBroken: sequence|null, errors:[{seq,reason}], recalculated:{[eventId]:hash}, durationMs}`.
- Graph renderer consumes ordered events + position + verification + selected ID. Tiers: retrieval/context y=90, state y=240, `tool_*` y=360. Flags are amber; first mismatch red; later events affected.
- Inspector reads all event fields, including recalculated hash. Replay slices ordered events. Export expects a downloadable **JSON**, not PDF.

## New HTTP checklist (no preexisting API shapes to override)
All paths are same-origin through the frontend gateway; no key or ingest token in the browser.
- `POST /chat` `{session_id,message}` -> `{response,event_type,sensitive_action_flag,turn_id}`; failure 503 `{error:'live_agent_unavailable',message,turn_id}`. Both Try and Live call this.
- `GET /api/config` -> `{demo_mode}`.
- `GET /api/sessions` -> `[{session_id,status:'verified'|'tampered',entry_count}]`.
- `GET /api/session/{id}/entries` -> raw ordered entry array with numeric database IDs and timestamps, parsed payload and `payload_str` for exact independent hash reproduction.
- `GET /api/session/{id}/verify` -> spec fields plus `ok,checked,firstBroken,errors,recalculated,durationMs` renderer aliases.
- `GET /api/session/{id}/graph` -> `{session_id,nodes,edges,events,verification}`. `events` and renderer aliases preserve existing display logic; all components derive from one SQLite read snapshot. Node fields include spec fields plus positions. This is the UI's consistent refresh endpoint.
- `GET /api/session/{id}/export` -> downloadable JSON `{format,session_id,entries,verification,...}`.
- `POST /api/session/{id}/tamper` `{entry_id:number,payload:object}` -> `{status:'tampered',entry_id}`. Registered only in explicit demo mode; demo Compose override permits the intentionally separate write connection.
- `POST /demo/session` `{session_id,mode:'verified'|'tampered'}` -> 202 `{session_id,event_count:7}`. Only demo mode. Agent queues server-owned fictional walkthrough events through the same sink. UI polls reconstruction then calls tamper for the altered walkthrough. No browser-supplied raw ingest route.

The standalone landing-page chain lab remains explicitly browser-local educational material, not a backend session or evidence export. Workspace modes all use durable server records. Backend hashing differs from the old browser-lab format and its scope must be accurately labeled.
