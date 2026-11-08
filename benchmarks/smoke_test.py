"""Pre-flight smoke test verifying container operations, ledger reset, and verifier queries."""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import os
import sys

sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import subprocess
import time
import urllib.request

from benchmarks.eval_common import reset_ledger_and_restart_services

def smoke_test():
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    print("=== Running Pre-flight Smoke Test ===")
    print("1. Testing Ledger Reset & Restart...")
    reset_ledger_and_restart_services()
    print("   Reset & restart successful.")

    print("2. Testing Container Connectivity...")
    req = urllib.request.Request("http://127.0.0.1:8002/health")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
    print("   Reconstruction service healthy.")

    print("3. Testing Agent Chat Ingestion via container...")
    agent_code = """
import json
from types import SimpleNamespace
from fastapi.testclient import TestClient
from agent.capture import AuditCapture
from agent.main import create_app

class FakeLLM:
    async def ainvoke(self, m): return SimpleNamespace(content="Smoke test response")

import os
require_destructive(os.environ.get("AUDIT_SINK_URL", "http://audit_service:8001/ingest"))
require_token()
cap = AuditCapture(autostart=True)
app = create_app(llm=FakeLLM(), capture=cap)
with TestClient(app) as client:
    r = client.post("/chat", json={"session_id": "smoke-session", "message": "Smoke test message"})
    assert r.status_code == 200
cap.close(drain=True)
print("AGENT_OK")
"""
    proc = subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-agent_service-1", "python", "-"], input=guarded_python(agent_code), capture_output=True, text=True, check=True)
    assert "AGENT_OK" in proc.stdout
    print("   Agent chat turn succeeded inside container.")

    print("4. Testing SQLite Ledger Ingestion...")
    proc = subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-c", guarded_python("import sqlite3; conn = sqlite3.connect('/data/audit.db'); print('Rows:', conn.execute('SELECT count(id) FROM audit_log').fetchone()[0])")], capture_output=True, text=True, check=True)
    rows_count = int(proc.stdout.strip().split()[-1])
    assert rows_count > 0
    print(f"   Audit log count: {rows_count}")

    print("5. Testing /verify Endpoint...")
    url = "http://127.0.0.1:8002/api/session/smoke-session/verify"
    with urllib.request.urlopen(url) as resp:
        vdata = json.loads(resp.read().decode())
        assert vdata.get("chain_intact") is True
    print(f"   Smoke session verified: chain_intact={vdata.get('chain_intact')}, entries={vdata.get('entry_count')}")

    print("=== All Smoke Tests Passed Successfully! ===")

if __name__ == "__main__":
    smoke_test()
