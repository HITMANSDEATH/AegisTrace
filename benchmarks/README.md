# Research benchmarks

AegisTrace is a research prototype, not a production audit system. These are real
experiment harnesses, not ordinary unit tests. Many delete or rewrite audit rows,
truncate anchors, restart/stop containers, or submit forged events and heavy load.
Use only disposable local services and data. Back up anything you need first.

## Safety requirements

- Set `AEGIS_ALLOW_DESTRUCTIVE=1` explicitly. No other value enables mutations.
- Actual HTTP target hosts must be `localhost`, `127.0.0.1`, `audit_service`,
  `agent_service`, `reconstruction_service`, or `anchor_service`. Malformed URLs,
  userinfo, and remote hosts are refused without displaying the URL.
- Docker must be local. The selected context and `DOCKER_HOST` must use a local
  Unix socket or local Windows named pipe. SSH/TCP daemons (including loopback
  TCP, which could be forwarded) and uninspectable contexts are refused.
- Live ingest requires `AUDIT_WRITE_TOKEN` in the agent container. The two
  live-ingest tamper entrypoints also require it in the host environment **before
  reset or output creation**. Missing/empty tokens fail clearly; embedded ingest
  code checks its own token too. Provision tokens securely; do not put them in
  commands, source code, or reports.
- `AUDIT_SINK_URL`, where supported, defaults to
  `http://audit_service:8001/ingest`. The effective override is checked in the
  process/container that uses it. Host orchestrators preflight the agent's
  environment before resets. They do not copy or display the container's token.
- When anchoring is enabled, host orchestrators also preflight the audit
  container's effective `ANCHOR_SINK_URL` and require `ANCHOR_WRITE_TOKEN`.
  `ANCHOR_EVERY=0` disables anchoring and waives that token requirement.

Use a locally provisioned Compose stack with disposable volumes, the existing
`aegistrace-*-1` container names, and its existing internal networks. The audit,
agent, reconstruction, and anchor services must be running as required by the
experiment. Reconstruction is reached from the host at `127.0.0.1:8002`; internal
services use their existing ports 8000–8003. Configure the stack's normal required
secrets independently. Live tamper experiments expect `ANCHOR_EVERY=10`.

## Run one existing experiment

From the repository root, install the app's declared development dependencies and
the benchmark-only dependency file (`benchmarks/requirements.txt`, currently
`psutil`) in the root `.venv`, provision local services, and securely set the
token in both environments. This PowerShell command runs the existing live-ingest
suite (340 sessions, 8,500 events):

```powershell
$env:AEGIS_ALLOW_DESTRUCTIVE = '1'
.\.venv\Scripts\python.exe benchmarks/run_live_ingest_tamper_v2.py
Remove-Item Env:AEGIS_ALLOW_DESTRUCTIVE
```

This is destructive and can overwrite prior outputs with the same names. Do not
run it simply to check installation. For offline guard tests instead:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s benchmarks/tests -v
```

The focused tests also work with pytest when installed. Do not collect the whole
`benchmarks/` directory as a normal test suite: historical `test_exp_*.py` files
and isolation probes are experiment entrypoints.

## Container launch modes

Native file/module execution and existing host orchestrators are supported. Each
orchestrator transports the stdlib safety helper with embedded/loaded Python
code, and uses `docker exec -e AEGIS_ALLOW_DESTRUCTIVE` to forward the caller's
explicit choice, never to enable it automatically. No helper mount is needed for
these launches. Embedded code checks its own opt-in and effective target.

For manually streaming a standalone benchmark into a container without mounting
`benchmarks/`, use `benchmarks.benchmark_safety.guarded_python(script_text)` on the
host to build the stdin payload, and pass `-e AEGIS_ALLOW_DESTRUCTIVE` to
`docker exec -i ... python -`. Do not stream an unbundled file that imports the
helper into an image without that helper. Direct launches inside a provisioned
container require the helper on its Python import path and explicit opt-in in
that container; the host remains responsible for selecting local Docker.

## Outputs and limitations

Writers create the raw/log directories they need before opening their outputs.
Raw outputs are not shipped:

- `results/raw/`
- `results/raw_v2/`
- `results/logs/`
- `results/logs_v2/`
- `evaluation_results/raw_logs/`

Existing research summaries are retained. Missing raw inputs cannot be recreated
by report generators alone. The release/Zenodo archival decision is pending.

The isolation harness retains historical numeric network probes and a frontend
target that are outside the allowlist; those probes now fail closed rather than
silently broadening access.
Scratch-only variant benchmarks use temporary databases and do not mutate live
services, but still require explicit opt-in. Report generators also require opt-in
because they overwrite outputs; they do not recreate missing raw evidence. These
local-only operations have no network target to validate. Guards are accident
prevention, not a sandbox against a hostile local operator, altered DNS, or a
locally forwarded Unix socket. No scientific calculations, experiment classes, or
output names are changed by the guards.
