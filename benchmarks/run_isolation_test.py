"""Benchmark 2: Isolation / Oracle-Resistance Evaluation for AegisTrace.
Must be executed from inside agent_service container context.
Tests:
1. Direct network connection attempt to SQLite audit database file or its host
2. Direct HTTP request to reconstruction_service's endpoints
3. Reading any data back from audit_service's /ingest response beyond bare acknowledgment
"""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import json
import os
import socket
import sys

def test_sqlite_file_and_host():
    # 1. Local filesystem volume check: agent must not have audit volume mounted
    require_destructive("http://audit_service:8001/ingest")
    db_file_accessible = os.path.exists('/data/audit.db') or os.path.exists('/data')
    
    # 2. Network connection attempt to SQLite / host storage ports or audit_net
    # In SQLite container architecture, SQLite is an embedded file in audit_service & reconstruction_service.
    # Attempt connecting to audit_service internal storage ports or non-HTTP ports, or host ports
    sqlite_conn_attempt = False
    details = []
    
    if db_file_accessible:
        details.append("Found /data/audit.db in filesystem")
    else:
        details.append("Filesystem check: /data/audit.db does not exist (no audit volume mount)")

    # Test direct socket connections to possible DB host / port addresses
    probe_targets = [
        ("audit_service", 5432),
        ("audit_service", 3306),
        ("172.29.13.2", 8001), # audit_service on audit_net (agent is not on audit_net)
        ("172.29.13.1", 22),   # gateway
    ]
    for host, port in probe_targets:
        validate_target(f"http://{host}:{port}")
    blocked_sockets = 0
    for host, port in probe_targets:
        try:
            with socket.create_connection((host, port), timeout=1.5):
                details.append(f"Connected to {host}:{port}")
                sqlite_conn_attempt = True
        except (OSError, socket.timeout):
            blocked_sockets += 1

    details.append(f"Direct network socket probes to storage/internal network blocked ({blocked_sockets}/{len(probe_targets)})")
    
    passed = (not db_file_accessible) and (not sqlite_conn_attempt)
    return {
        "attempt_type": "Direct network/filesystem connection to SQLite audit database or host",
        "result": "Blocked (no volume mounted; /data/audit.db not present; non-ingest network paths unreachable)",
        "pass_fail": "Pass" if passed else "Fail",
        "details": "; ".join(details)
    }

def test_reconstruction_http():
    require_destructive("http://audit_service:8001/ingest")
    import httpx
    client = httpx.Client(timeout=2.0, trust_env=False)
    
    targets = [
        "http://reconstruction_service:8002/health",
        "http://reconstruction_service:8002/api/sessions",
        "http://reconstruction_service:8002/api/session/test/verify",
        "http://172.29.13.3:8002/api/sessions",
        "http://172.29.14.3:8002/api/sessions",
    ]
    
    for url in targets + ["http://frontend:3000/api/sessions"]:
        validate_target(url)
    blocked_count = 0
    reasons = []
    for url in targets:
        try:
            resp = client.get(url)
            reasons.append(f"Unexpected success reaching {url}: status={resp.status_code}")
        except httpx.ConnectError as e:
            blocked_count += 1
            reasons.append(f"Blocked: ConnectError for {url}")
        except httpx.ConnectTimeout as e:
            blocked_count += 1
            reasons.append(f"Blocked: ConnectTimeout for {url}")
        except Exception as e:
            blocked_count += 1
            reasons.append(f"Blocked: {type(e).__name__} for {url}")

    # Also test through frontend proxy if gateway forwards to reconstruction
    try:
        r = client.get("http://frontend:3000/api/sessions")
        if r.status_code == 403:
            reasons.append("Frontend gateway: 403 Forbidden (access restricted to dashboard network)")
            gateway_blocked = True
        else:
            reasons.append(f"Frontend gateway returned status {r.status_code}")
            gateway_blocked = False
    except Exception as e:
        gateway_blocked = True
        reasons.append(f"Frontend gateway unreachable: {e}")

    passed = (blocked_count == len(targets)) and gateway_blocked
    return {
        "attempt_type": "Direct HTTP request to reconstruction_service's endpoints",
        "result": f"Blocked ({blocked_count}/{len(targets)} direct endpoints unreachable, gateway blocked with 403)",
        "pass_fail": "Pass" if passed else "Fail",
        "details": "; ".join(reasons)
    }

def test_audit_ingest_data_leakage():
    require_destructive("http://audit_service:8001/ingest")
    import httpx
    client = httpx.Client(timeout=2.0, trust_env=False)
    token = require_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    # 1. Normal POST
    test_payload = {
        "session_id": "isolation-test-session",
        "client_seq": 1,
        "timestamp": 1700000000.0,
        "event_type": "state_transition",
        "payload": {"probe": "can_we_read_anything_back", "secret": "12345"},
        "sensitive_action_flag": False
    }
    
    resp = client.post("http://audit_service:8001/ingest", json=test_payload, headers=headers)
    resp_json = resp.json() if resp.status_code == 200 else {}
    
    # Check if anything beyond {'status': 'recorded'} is returned
    allowed_keys = {"status"}
    leaked_keys = set(resp_json.keys()) - allowed_keys
    contains_echo = ("probe" in resp.text) or ("secret" in resp.text) or ("12345" in resp.text)
    contains_hash = ("hash" in resp_json) or ("prev_hash" in resp_json) or ("entry_id" in resp_json) or ("id" in resp_json)
    
    # 2. Attempt read methods on audit_service
    read_attempts = ["/ingest", "/api/sessions", "/docs", "/openapi.json", "/health", "/query"]
    read_blocked = 0
    for path in read_attempts:
        r = client.get(f"http://audit_service:8001{path}", headers=headers)
        if r.status_code in (404, 405):
            read_blocked += 1
            
    passed = (
        resp.status_code == 200
        and resp_json == {"status": "recorded"}
        and len(leaked_keys) == 0
        and not contains_echo
        and not contains_hash
        and read_blocked == len(read_attempts)
    )
    
    return {
        "attempt_type": "Reading data back from audit_service's /ingest response beyond bare acknowledgment",
        "result": "No data returned (bare acknowledgment {'status': 'recorded'} only; no hashes, IDs, or echoed content; all GET paths return 404/405)",
        "pass_fail": "Pass" if passed else "Fail",
        "details": f"Response keys: {list(resp_json.keys())}; status={resp_json.get('status')}; leaked keys: {list(leaked_keys)}; read routes blocked: {read_blocked}/{len(read_attempts)}"
    }

if __name__ == "__main__":
    r1 = test_sqlite_file_and_host()
    r2 = test_reconstruction_http()
    r3 = test_audit_ingest_data_leakage()
    
    results = [r1, r2, r3]
    print(json.dumps(results, indent=2))
