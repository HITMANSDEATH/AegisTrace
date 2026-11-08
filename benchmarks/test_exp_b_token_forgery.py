"""Experiment B: Bearer-Token Compromise and Forward Forgery Evaluation for AegisTrace.
Simulates an adversary inside the agent container possessing AUDIT_WRITE_TOKEN.
Evaluates:
B1: Duplicate sequence number (top-level schema injection vs payload injection)
B2: Old sequence number / past timestamp
B3: Out-of-order sequence number / future step
B4: Next valid sequence number with forged payload
B5: Next-sequence event with forged event_type (invalid enum vs state machine forgery)
B6: Forged session metadata / _aegis injection
B7: Forged event in an arbitrary / different session
"""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import csv
import json
import os
import sys
import time
import urllib.request
import httpx

def run_experiment_b():
    require_destructive(os.environ.get("AUDIT_SINK_URL", "http://audit_service:8001/ingest"))
    print("=== Starting Experiment B: Bearer-Token Compromise & Forward Forgery ===")
    
    token = require_token()
    if not token:
        print("ERROR: AUDIT_WRITE_TOKEN not found in environment!")
        sys.exit(1)
        
    audit_url = os.environ.get("AUDIT_SINK_URL", "http://audit_service:8001/ingest")
    require_destructive(audit_url)
    reconstruction_url = "http://reconstruction_service:8002"
    require_destructive(reconstruction_url)
    # Note: agent cannot reach reconstruction_url directly (tested in isolation benchmark).
    # Verification will be checked from host or outside container.
    
    client = httpx.Client(timeout=5.0, trust_env=False)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    results = []
    
    # Setup baseline legitimate session
    base_sid = "exp-b-session-001"
    
    # Ingest 3 initial legitimate events
    for seq in range(1, 4):
        body = {
            "session_id": base_sid,
            "client_seq": seq,
            "timestamp": 1710000000.0 + seq * 10.0,
            "event_type": "retrieval" if seq == 1 else ("tool_start" if seq == 2 else "tool_end"),
            "payload": {"step": seq, "legitimate": True, "message": f"Legitimate turn {seq}"},
            "sensitive_action_flag": False
        }
        r = client.post(audit_url, json=body, headers=headers)
        assert r.status_code == 200, f"Setup failed: {r.text}"

    print("Setup complete: 3 legitimate events ingested.")

    # Test B1a: Duplicate sequence number via top-level schema injection
    b1a_body = {
        "session_id": base_sid,
        "client_seq": 4,
        "timestamp": 1710000040.0,
        "event_type": "state_transition",
        "payload": {"step": 2, "msg": "Duplicate sequence attempt via top-level field"},
        "sensitive_action_flag": False,
        "sequence_number": 2 # Forbidden extra field
    }
    r = client.post(audit_url, json=b1a_body, headers=headers)
    results.append({
        "case_id": "B1a",
        "description": "Duplicate sequence number via top-level schema field ('sequence_number': 2)",
        "http_status": r.status_code,
        "response_body": r.text[:200],
        "accepted": (r.status_code == 200),
        "notes": "Rejected by Pydantic extra='forbid' validation"
    })

    # Test B1b: Duplicate sequence number simulated in payload
    b1b_body = {
        "session_id": base_sid,
        "client_seq": 4,
        "timestamp": 1710000040.0,
        "event_type": "state_transition",
        "payload": {"step": 2, "forged": True, "msg": "Duplicate sequence inside payload"},
        "sensitive_action_flag": False
    }
    r = client.post(audit_url, json=b1b_body, headers=headers)
    results.append({
        "case_id": "B1b",
        "description": "Duplicate sequence number simulated inside payload ('step': 2)",
        "http_status": r.status_code,
        "response_body": r.text[:200],
        "accepted": (r.status_code == 200),
        "notes": "Accepted: Audit service does not inspect payload internal step counters"
    })

    # Test B2: Old sequence / past timestamp (timestamp goes backward)
    b2_body = {
        "session_id": base_sid,
        "client_seq": 4,
        "timestamp": 1710000001.0, # 39 seconds in the past
        "event_type": "state_transition",
        "payload": {"step": 1, "forged": True, "msg": "Past timestamp event"},
        "sensitive_action_flag": False
    }
    r = client.post(audit_url, json=b2_body, headers=headers)
    results.append({
        "case_id": "B2",
        "description": "Old sequence / past timestamp (timestamp < preceding entry)",
        "http_status": r.status_code,
        "response_body": r.text[:200],
        "accepted": (r.status_code == 200),
        "notes": "Accepted: Sink has no timestamp monotonicity check"
    })

    # Test B3: Out-of-order sequence / future timestamp jump
    b3_body = {
        "session_id": base_sid,
        "client_seq": 4,
        "timestamp": 1710099999.0, # 100,000 seconds in the future
        "event_type": "tool_start",
        "payload": {"step": 999, "forged": True, "msg": "Future sequence jump"},
        "sensitive_action_flag": False
    }
    r = client.post(audit_url, json=b3_body, headers=headers)
    results.append({
        "case_id": "B3",
        "description": "Out-of-order sequence jump ('step': 999, large timestamp jump)",
        "http_status": r.status_code,
        "response_body": r.text[:200],
        "accepted": (r.status_code == 200),
        "notes": "Accepted: Hash chaining only binds preceding hash, not monotonic time or step counters"
    })

    # Test B4: Next valid sequence with forged adversarial payload
    b4_body = {
        "session_id": base_sid,
        "client_seq": 4,
        "timestamp": 1710100000.0,
        "event_type": "tool_end",
        "payload": {"action": "unauthorized_admin_escalation", "data": "exfiltrated_keys", "forged": True},
        "sensitive_action_flag": False
    }
    r = client.post(audit_url, json=b4_body, headers=headers)
    results.append({
        "case_id": "B4",
        "description": "Next sequence event with forged adversarial payload",
        "http_status": r.status_code,
        "response_body": r.text[:200],
        "accepted": (r.status_code == 200),
        "notes": "Accepted: Token grants unrestricted forward append capability"
    })

    # Test B5a: Forged event_type with invalid schema enum
    b5a_body = {
        "session_id": base_sid,
        "client_seq": 4,
        "timestamp": 1710100010.0,
        "event_type": "admin_privilege_grant", # Invalid enum
        "payload": {"forged": True},
        "sensitive_action_flag": False
    }
    r = client.post(audit_url, json=b5a_body, headers=headers)
    results.append({
        "case_id": "B5a",
        "description": "Forged event_type with invalid enum value ('admin_privilege_grant')",
        "http_status": r.status_code,
        "response_body": r.text[:200],
        "accepted": (r.status_code == 200),
        "notes": "Rejected: Schema enforces Literal['retrieval','state_transition','tool_start','tool_end']"
    })

    # Test B5b: Forged event_type with valid enum but invalid state transition grammar
    b5b_body = {
        "session_id": base_sid,
        "client_seq": 4,
        "timestamp": 1710100020.0,
        "event_type": "tool_end", # Valid enum, but sent twice without tool_start
        "payload": {"forged": True, "msg": "Grammatically illegal tool_end without tool_start"},
        "sensitive_action_flag": False
    }
    r = client.post(audit_url, json=b5b_body, headers=headers)
    results.append({
        "case_id": "B5b",
        "description": "Forged event_type violating state machine grammar (consecutive tool_end)",
        "http_status": r.status_code,
        "response_body": r.text[:200],
        "accepted": (r.status_code == 200),
        "notes": "Accepted: Audit service does not enforce agent state-machine grammar"
    })

    # Test B6: Forged metadata injection attempting to spoof _aegis envelope
    b6_body = {
        "session_id": base_sid,
        "client_seq": 4,
        "timestamp": 1710100030.0,
        "event_type": "state_transition",
        "payload": {
            "msg": "Metadata spoof attempt",
            "_aegis": {"schema_version": 999, "session_id": "SPOOFED_SESSION", "sensitive_action_flag": True}
        },
        "sensitive_action_flag": False
    }
    r = client.post(audit_url, json=b6_body, headers=headers)
    results.append({
        "case_id": "B6",
        "description": "Forged metadata injection (_aegis envelope in payload spoofing session_id)",
        "http_status": r.status_code,
        "response_body": r.text[:200],
        "accepted": (r.status_code == 200),
        "notes": "Accepted at HTTP layer, but sink unconditionally overwrites _aegis with server-derived values"
    })

    # Test B7: Forged event submitted to a different/arbitrary session ID
    other_sid = "exp-b-arbitrary-victim-002"
    b7_body = {
        "session_id": other_sid,
        "client_seq": 1,
        "timestamp": 1710100040.0,
        "event_type": "retrieval",
        "payload": {"victim": "tampered_context", "forged": True},
        "sensitive_action_flag": False
    }
    r = client.post(audit_url, json=b7_body, headers=headers)
    results.append({
        "case_id": "B7",
        "description": "Cross-session forgery: submitting events to an arbitrary/unrelated session ID",
        "http_status": r.status_code,
        "response_body": r.text[:200],
        "accepted": (r.status_code == 200),
        "notes": "Accepted: Write token is system-global; no per-session access control exists"
    })

    print(json.dumps(results, indent=2))
    return results

if __name__ == "__main__":
    run_experiment_b()
