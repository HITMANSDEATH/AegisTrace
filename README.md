# AegisTrace

AegisTrace is a research prototype for recording and inspecting the execution of an LLM-backed agent. Its central design separates the agent from readable audit storage: the agent can submit events to an authenticated write-only sink, but cannot query the audit database. A reconstruction service verifies hash-linked records and builds a recorded-order event graph, while a separate anchor service stores periodic chain checkpoints. These mechanisms expose specified forms of tampering; they do not prove that every event was captured or make a compromised host trustworthy.

## Architecture

```text
Browser -> Nginx gateway :3000 -> agent_service :8000 -> Groq-only egress proxy
                         |              |
                         |              +-- POST /ingest --> audit_service :8001
                         |                                        |       |
                         +-> reconstruction_service :8002         |       +-- POST /anchor
                                  |             |                 |              |
                                  |             +-- read-only ----+-- anchor_service :8003
                                  |                              anchor volume
                                  +-- read-only audit volume <-- audit_service
```

The agent has no audit or anchor volume and no network shared with reconstruction or anchoring. The gateway rejects agent-source addresses before proxying any route, so it must not become an indirect audit-read path. Audit and anchor endpoints remain internal; the host/Docker administrator is trusted. See the [application guide](aegistrace-complete/aegistrace/README.md) and [security model](aegistrace-complete/aegistrace/SECURITY.md).

## Quick start

Requires Docker Engine with Compose v2. Keep the isolated Docker subnets available. Run these commands from the repository root, then stay in the application directory:

```sh
cd aegistrace-complete/aegistrace
# For a new checkout only; do not overwrite an existing .env.
cp .env.example .env
```

The **only public environment template** is `aegistrace-complete/aegistrace/.env.example`. Compose reads the application directory's `.env`, not `.env.example` and not a root template. Set independently generated random values for `AUDIT_WRITE_TOKEN` and `ANCHOR_WRITE_TOKEN` in that private file. Set `GROQ_API_KEY` for live Groq inference; it is not needed for startup or browser-only exploration. Never put these credentials in frontend files, experiment outputs, or Git.

```sh
docker compose up --build -d
```

Open **http://localhost:3000**. The default is **same-origin mode**: Nginx routes chat and reconstruction requests behind the frontend origin; leave `AEGIS_API_BASE` empty. Reconstruction is currently also loopback-bound on port 8002 for local diagnostics; it is not a complete chat gateway and must not be published separately to make the agent work.

Try It Yourself and the landing-page chain lab are browser-local simulations. Live Agent uses the backend and configured provider. The verified/tampered scripted cases use the backend and require the explicit local-only demo override:

```sh
docker compose -f compose.yaml -f compose.demo.yaml up --build -d
```

That override permits deliberate changes to stored demo evidence. Use fictional data only. Stop without deleting evidence with `docker compose down`; adding `-v` deletes evidence volumes.

## Separately hosted frontend

Deploy the contents of `aegistrace-complete/aegistrace/frontend/` as static files without changing relative asset paths. In its `config.js`, set `window.AEGIS_API_BASE` to your HTTPS **backend gateway** URL (for example `https://api.example.com`), not the internal agent or audit endpoint. All API calls, including export, use that one base.

For frontend files served by reconstruction/Nginx, `/config.js` is generated from backend `AEGIS_API_BASE`; blank retains same-origin mode. A separately hosted static frontend uses its own `config.js`; a backend environment variable cannot change files on another host. Set `ALLOWED_ORIGINS` on the backend to the separate frontend's exact origin. CORS is implemented only on agent and reconstruction; it does not grant the agent read access or authenticate a browser.

CORS troubleshooting:

- A missing `Access-Control-Allow-Origin` or “blocked by CORS policy” usually means a scheme, hostname, or port mismatch. Use comma-separated origins without paths; surrounding whitespace and trailing slashes are removed.
- A preflight 404/405/403 can mean the frontend points to the wrong service or the reverse proxy blocks `OPTIONS`. The included gateway passes preflights for `/chat`, `/demo/session`, and reconstruction routes.
- An HTTPS frontend cannot call an HTTP backend because of mixed-content rules. Use HTTPS on both hosts; changing CORS alone does not fix mixed content.

Explicit origins are the default. `ALLOWED_ORIGINS=*` is an intentional insecure-for-private-data opt-in and emits a startup warning; browser credentials are disabled in either mode.

## Repository map

| Location | Purpose |
|---|---|
| `aegistrace-complete/aegistrace/` | Application, canonical env template, Compose files, service Dockerfiles and app guide |
| `aegistrace-complete/aegistrace/frontend/` | Standalone static UI and its API configuration |
| `aegistrace-complete/aegistrace/tests/` | Unit, browser-configuration, deployment-policy and manual isolation checks |
| `benchmarks/` | Experiment harnesses, guard tests and [safe-running instructions](benchmarks/README.md) |
| `evaluation_results/` | Retained September additional-experiment summaries and selected CSV records; see its [README](evaluation_results/README.md) |
| `.github/workflows/ci.yml` | No-key unit checks, local health smoke and frontend checks; no deployment |

The research reports are distinct historical snapshots, not interchangeable descriptions of the current code:

- `benchmarks/EVALUATION_RESULTS.md` contains the September baseline. The two root architecture/system documents reuse that baseline and describe the pre-v2 design; all three carry a historical-baseline banner.
- `evaluation_results/` covers the additional six September experiments; see its [README](evaluation_results/README.md).
- The October extended and v2 evaluation reports are not included in the public tree.

Historical reports are retained without rewriting their scientific evidence; their claims and links need to be interpreted in that context. Paper/LaTeX sources and editorial follow-up files are not included in the public tree.

## Raw data and reproduction

Large raw experiment outputs and execution logs are **not distributed in this repository**. Their original local paths were `results/raw/`, `results/raw_v2/` (including `rq1_30seed/`), `results/logs/`, `results/logs_v2/`, and `evaluation_results/raw_logs/`. The October extended/v2 evaluation reports are also excluded. References to these paths in retained documents do not mean they are included in a clone.

Harnesses recreate their output directories when run. Retained summaries and selected files in `evaluation_results/` are not renamed. Whether to distribute the omitted artifacts through a GitHub Release or Zenodo is undecided; no external dataset download is currently promised. Experiments may destroy local demo evidence and must pass the safeguards described in the [benchmark guide](benchmarks/README.md).

## Development and checks

Create a root virtual environment and install the declared application test dependencies:

```sh
python -m venv .venv
. .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r aegistrace-complete/aegistrace/requirements-dev.txt
# Only for running research harnesses:
python -m pip install -r benchmarks/requirements.txt
cd aegistrace-complete/aegistrace
python -m pytest -q tests ../../benchmarks/tests
node --test tests/frontend_api.test.mjs
```

Tests use fake providers and temporary storage rather than private `.env` files. See the app guide for native-process operation and the explicit Docker isolation test. The CI health smoke does not prove Docker network isolation; that requires the separate real-stack check. Release preparation and clean-clone verification must be completed before treating this as deployment-ready.

## Security and license

This is a research prototype, not an authenticated multi-tenant product. Do not expose real prompts or evidence to untrusted users: browser session authorization, durable capture/replay, secure retention, TLS, and operator controls require separate consideration. Periodic asynchronous anchoring does not guarantee a fixed maximum unanchored tail when delivery fails.

The project is distributed under the [MIT License](LICENSE). Review the [security document](aegistrace-complete/aegistrace/SECURITY.md) for detailed trust boundaries; a private reporting contact has not yet been selected.
