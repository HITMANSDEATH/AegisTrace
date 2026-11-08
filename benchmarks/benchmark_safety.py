"""Explicit safety checks for destructive research benchmarks (stdlib only)."""
import json
import os
from pathlib import Path
import subprocess
from urllib.parse import urlsplit


ALLOWED_HOSTS = frozenset({
    "localhost", "127.0.0.1", "audit_service", "agent_service",
    "reconstruction_service", "anchor_service",
})
DEFAULT_AUDIT_URL = "http://audit_service:8001/ingest"


def require_token():
    token = os.environ.get("AUDIT_WRITE_TOKEN")
    if not token or not token.strip():
        raise SystemExit("Benchmark refused: AUDIT_WRITE_TOKEN is required before reset or output.")
    return token


def validate_target(url):
    """Reject ambiguous URLs without including possibly credential-bearing input."""
    try:
        if not isinstance(url, str) or not url or any(c.isspace() or ord(c) < 32 for c in url):
            raise ValueError
        if "\\" in url:
            raise ValueError
        parts = urlsplit(url)
        if (parts.scheme not in {"http", "https"} or not parts.netloc
                or parts.hostname not in ALLOWED_HOSTS
                or parts.username is not None or parts.password is not None
                or parts.fragment or "%" in parts.netloc
                or parts.netloc.endswith(":")):
            raise ValueError
        port = parts.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
    except (ValueError, TypeError):
        raise SystemExit("Benchmark refused: malformed or non-local target URL (credentials are not permitted).") from None


def _local_docker_endpoint(endpoint):
    # TCP (even loopback) and SSH may forward to a remote daemon. Only local IPC.
    if not isinstance(endpoint, str) or any(c.isspace() for c in endpoint):
        return False
    if endpoint.startswith("unix:///"):
        parts = urlsplit(endpoint)
        return not parts.netloc and bool(parts.path) and not parts.query and not parts.fragment
    return endpoint.startswith("npipe:////./pipe/") and len(endpoint) > len("npipe:////./pipe/") and not any(c in endpoint for c in "?#@")


def require_local_docker():
    override = os.environ.get("DOCKER_HOST")
    if override and not _local_docker_endpoint(override):
        raise SystemExit("Benchmark refused: DOCKER_HOST must use a local Unix socket or named pipe.")
    # DOCKER_CONTEXT overrides DOCKER_HOST; inspect the actual selected context.
    context = os.environ.get("DOCKER_CONTEXT")
    if override and not context:
        return
    command = ["docker", "context", "inspect"]
    if context:
        command.append(context)
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        records = json.loads(result.stdout)
        endpoint = records[0]["Endpoints"]["docker"]["Host"]
        if len(records) != 1 or not _local_docker_endpoint(endpoint):
            raise ValueError
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, IndexError, TypeError):
        raise SystemExit("Benchmark refused: cannot establish a local Docker context (remote daemons are not allowed).") from None


def require_destructive(*target_urls, docker=False, agent=False):
    if os.environ.get("AEGIS_ALLOW_DESTRUCTIVE") != "1":
        raise SystemExit("Benchmark refused: set AEGIS_ALLOW_DESTRUCTIVE=1 explicitly for disposable local data only.")
    for url in target_urls:
        validate_target(url)
    if docker:
        require_local_docker()
    if agent:
        # Check the container's effective environment before a host-side reset.
        # No environment values or token values are returned to the host.
        code = "import os\nrequire_token()\nrequire_destructive(os.environ.get('AUDIT_SINK_URL', 'http://audit_service:8001/ingest'))\n"
        try:
            result = subprocess.run(
                ["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i",
                 "aegistrace-agent_service-1", "python", "-"],
                input=guarded_python(code), text=True, capture_output=True,
            )
            if result.returncode:
                raise ValueError
        except (OSError, subprocess.SubprocessError, ValueError):
            raise SystemExit("Benchmark refused: agent preflight failed; require AUDIT_WRITE_TOKEN and a valid local AUDIT_SINK_URL in the container.") from None
        # The audit service may asynchronously forward anchors; validate its
        # effective destination before any host-side reset or ingest.
        anchor_code = (
            "import os\n"
            "require_destructive()\n"
            "validate_target(os.environ.get('ANCHOR_SINK_URL', 'http://anchor_service:8003/anchor'))\n"
            "if int(os.environ.get('ANCHOR_EVERY', '10')) > 0 and not os.environ.get('ANCHOR_WRITE_TOKEN', '').strip():\n"
            "    raise SystemExit('Benchmark refused: ANCHOR_WRITE_TOKEN is required when anchoring is enabled.')\n"
        )
        try:
            result = subprocess.run(
                ["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i",
                 "aegistrace-audit_service-1", "python", "-"],
                input=guarded_python(anchor_code), text=True, capture_output=True,
            )
            if result.returncode:
                raise ValueError
        except (OSError, subprocess.SubprocessError, ValueError):
            raise SystemExit("Benchmark refused: audit anchor preflight failed; require a valid local ANCHOR_SINK_URL and ANCHOR_WRITE_TOKEN when anchoring is enabled.") from None


def guarded_python(code):
    """Transport the helper with stdin/-c code, without requiring a container mount.

    The caller must pass Docker's '-e AEGIS_ALLOW_DESTRUCTIVE' (no value):
    this forwards the explicit host opt-in, never manufactures consent.
    """
    require_destructive(docker=True)
    source = Path(__file__).read_text(encoding="utf-8")
    return (
        "import sys, types\n"
        "_safety = types.ModuleType('benchmark_safety')\n"
        "sys.modules['benchmark_safety'] = _safety\n"
        f"exec(compile({source!r}, '<benchmark_safety>', 'exec'), _safety.__dict__)\n"
        "from benchmark_safety import require_destructive, require_token, validate_target\n"
        "require_destructive()\n"
        + code
    )
