"""Experiment F: Malformed Event and Sequence Validation Suite.
Executes inside aegistrace-agent_service-1 against http://audit_service:8001/ingest.
"""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import os
import sys
import json
import time
import httpx

def run_suite():
    require_destructive("http://audit_service:8001/ingest")
    token = require_token()
    if not token:
        print("ERROR: AUDIT_WRITE_TOKEN not set", file=sys.stderr)
        sys.exit(1)
        
    url = "http://audit_service:8001/ingest"
    auth_headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    cases = [
        {
            "test_id": "F01_CONTROL_VALID",
            "category": "Control",
            "description": "Baseline compliant event payload",
            "body": {
                "event_type": "state_transition",
                "session_id": "exp-f-session-ctrl",
                "client_seq": 1,
                "payload": {"state": "init", "value": 42},
                "sensitive_action_flag": False,
                "timestamp": time.time()
            },
            "headers": auth_headers,
            "expected_status": 200,
            "raw_body": None
        },
        {
            "test_id": "F02_MISSING_TIMESTAMP",
            "category": "Required Field",
            "description": "Missing required timestamp field",
            "body": {
                "event_type": "state_transition",
                "session_id": "exp-f-session-f02",
                "client_seq": 1,
                "payload": {"state": "init"}
            },
            "headers": auth_headers,
            "expected_status": 422,
            "raw_body": None
        },
        {
            "test_id": "F03_MISSING_EVENT_TYPE",
            "category": "Required Field",
            "description": "Missing required event_type field",
            "body": {
                "session_id": "exp-f-session-f03",
                "client_seq": 1,
                "payload": {"state": "init"},
                "timestamp": time.time()
            },
            "headers": auth_headers,
            "expected_status": 422,
            "raw_body": None
        },
        {
            "test_id": "F04_MISSING_SESSION_ID",
            "category": "Required Field",
            "description": "Missing required session_id field",
            "body": {
                "event_type": "state_transition",
                "client_seq": 1,
                "payload": {"state": "init"},
                "timestamp": time.time()
            },
            "headers": auth_headers,
            "expected_status": 422,
            "raw_body": None
        },
        {
            "test_id": "F05_MISSING_PAYLOAD",
            "category": "Required Field",
            "description": "Missing required payload field",
            "body": {
                "event_type": "state_transition",
                "session_id": "exp-f-session-f05",
                "client_seq": 1,
                "timestamp": time.time()
            },
            "headers": auth_headers,
            "expected_status": 422,
            "raw_body": None
        },
        {
            "test_id": "F06_INVALID_EVENT_TYPE_ENUM",
            "category": "Schema Enum",
            "description": "Unsupported event_type 'malicious_exec'",
            "body": {
                "event_type": "malicious_exec",
                "session_id": "exp-f-session-f06",
                "client_seq": 1,
                "payload": {"cmd": "whoami"},
                "timestamp": time.time()
            },
            "headers": auth_headers,
            "expected_status": 422,
            "raw_body": None
        },
        {
            "test_id": "F07_SESSION_ID_PATH_TRAVERSAL",
            "category": "Regex / Path Traversal",
            "description": "Session ID containing path traversal characters '../etc/passwd'",
            "body": {
                "event_type": "state_transition",
                "session_id": "../../etc/passwd",
                "client_seq": 1,
                "payload": {"data": "test"},
                "timestamp": time.time()
            },
            "headers": auth_headers,
            "expected_status": 422,
            "raw_body": None
        },
        {
            "test_id": "F08_SESSION_ID_ILLEGAL_CHARS",
            "category": "Regex / Special Chars",
            "description": "Session ID containing spaces and punctuation 'sess ion@123!'",
            "body": {
                "event_type": "state_transition",
                "session_id": "sess ion@123!",
                "client_seq": 1,
                "payload": {"data": "test"},
                "timestamp": time.time()
            },
            "headers": auth_headers,
            "expected_status": 422,
            "raw_body": None
        },
        {
            "test_id": "F09_SESSION_ID_EXCESSIVE_LENGTH",
            "category": "Field Length",
            "description": "Session ID length 120 chars exceeding 96-char max pattern",
            "body": {
                "event_type": "state_transition",
                "session_id": "a" * 120,
                "client_seq": 1,
                "payload": {"data": "test"},
                "timestamp": time.time()
            },
            "headers": auth_headers,
            "expected_status": 422,
            "raw_body": None
        },
        {
            "test_id": "F10_EXTRA_ROOT_FIELD_FORBIDDEN",
            "category": "Schema Extra Fields",
            "description": "Injected unauthorized root field 'injected_admin' forbidden by extra='forbid'",
            "body": {
                "event_type": "state_transition",
                "session_id": "exp-f-session-f10",
                "client_seq": 1,
                "payload": {"data": "test"},
                "timestamp": time.time(),
                "injected_admin": True
            },
            "headers": auth_headers,
            "expected_status": 422,
            "raw_body": None
        },
        {
            "test_id": "F11_STRING_TIMESTAMP",
            "category": "Type Coercion",
            "description": "ISO 8601 string timestamp instead of float",
            "body": {
                "event_type": "state_transition",
                "session_id": "exp-f-session-f11",
                "client_seq": 1,
                "payload": {"data": "test"},
                "timestamp": "2026-09-18T22:00:00Z"
            },
            "headers": auth_headers,
            "expected_status": 422,
            "raw_body": None
        },
        {
            "test_id": "F12_NAN_TIMESTAMP",
            "category": "Non-finite Float",
            "description": "NaN string timestamp rejected by allow_inf_nan=False",
            "body": {
                "event_type": "state_transition",
                "session_id": "exp-f-session-f12",
                "client_seq": 1,
                "payload": {"data": "test"},
                "timestamp": "nan"
            },
            "headers": auth_headers,
            "expected_status": 422,
            "raw_body": None
        },
        {
            "test_id": "F13_INFINITY_TIMESTAMP",
            "category": "Non-finite Float",
            "description": "Infinity string timestamp rejected by allow_inf_nan=False",
            "body": {
                "event_type": "state_transition",
                "session_id": "exp-f-session-f13",
                "client_seq": 1,
                "payload": {"data": "test"},
                "timestamp": "inf"
            },
            "headers": auth_headers,
            "expected_status": 422,
            "raw_body": None
        },
        {
            "test_id": "F14_NAN_IN_PAYLOAD",
            "category": "Non-finite Float in Payload",
            "description": "NaN inside nested dictionary payload rejected by canonical_json",
            "body": None,
            "raw_body": b'{"event_type": "state_transition", "session_id": "exp-f-session-f14", "client_seq": 1, "payload": {"val": NaN}, "timestamp": 1700000000.0}',
            "headers": auth_headers,
            "expected_status": 422
        },
        {
            "test_id": "F15_NON_DICT_PAYLOAD",
            "category": "Payload Type",
            "description": "String payload instead of dict object",
            "body": {
                "event_type": "state_transition",
                "session_id": "exp-f-session-f15",
                "client_seq": 1,
                "payload": "this is a raw string, not a dict",
                "timestamp": time.time()
            },
            "headers": auth_headers,
            "expected_status": 422,
            "raw_body": None
        },
        {
            "test_id": "F16_OVERSIZED_PAYLOAD_140KIB",
            "category": "Payload Size Limit",
            "description": "140 KiB payload exceeding strict 128 KiB (131,072 byte) ceiling",
            "body": {
                "event_type": "state_transition",
                "session_id": "exp-f-session-f16",
                "client_seq": 1,
                "payload": {"blob": "X" * 143360},
                "timestamp": time.time()
            },
            "headers": auth_headers,
            "expected_status": 422,
            "raw_body": None
        },
        {
            "test_id": "F17_MALFORMED_JSON_SYNTAX",
            "category": "Wire Syntax",
            "description": "Truncated / invalid JSON byte stream",
            "body": None,
            "headers": auth_headers,
            "expected_status": 422,
            "raw_body": b'{"event_type": "state_transition", "session_id": "exp-f-syntax", "timestamp": '
        },
        {
            "test_id": "F18_MISSING_AUTH_HEADER",
            "category": "Authentication",
            "description": "Request omitting Authorization header",
            "body": {
                "event_type": "state_transition",
                "session_id": "exp-f-session-f18",
                "client_seq": 1,
                "payload": {"data": "test"},
                "timestamp": time.time()
            },
            "headers": {"Content-Type": "application/json"},
            "expected_status": 403,
            "raw_body": None
        },
        {
            "test_id": "F19_INVALID_BEARER_TOKEN",
            "category": "Authentication",
            "description": "Forged / invalid bearer token",
            "body": {
                "event_type": "state_transition",
                "session_id": "exp-f-session-f19",
                "client_seq": 1,
                "payload": {"data": "test"},
                "timestamp": time.time()
            },
            "headers": {"Authorization": "Bearer forged_invalid_token_9999", "Content-Type": "application/json"},
            "expected_status": 403,
            "raw_body": None
        },
        {
            "test_id": "F20_EMPTY_BEARER_TOKEN",
            "category": "Authentication",
            "description": "Bearer header with empty token",
            "body": {
                "event_type": "state_transition",
                "session_id": "exp-f-session-f20",
                "client_seq": 1,
                "payload": {"data": "test"},
                "timestamp": time.time()
            },
            "headers": {"Authorization": "Bearer", "Content-Type": "application/json"},
            "expected_status": 403,
            "raw_body": None
        },
        {
            "test_id": "F21_MISSING_CLIENT_SEQ",
            "category": "Sequence Validation",
            "description": "Missing required client_seq field",
            "body": {
                "event_type": "state_transition",
                "session_id": "exp-f-session-f21",
                "payload": {"state": "init"},
                "timestamp": time.time()
            },
            "headers": auth_headers,
            "expected_status": 422,
            "raw_body": None
        },
        {
            "test_id": "F22_ZERO_CLIENT_SEQ",
            "category": "Sequence Validation",
            "description": "Zero client_seq rejected by ge=1",
            "body": {
                "event_type": "state_transition",
                "session_id": "exp-f-session-f22",
                "client_seq": 0,
                "payload": {"state": "init"},
                "timestamp": time.time()
            },
            "headers": auth_headers,
            "expected_status": 422,
            "raw_body": None
        },
        {
            "test_id": "F23_NEGATIVE_CLIENT_SEQ",
            "category": "Sequence Validation",
            "description": "Negative client_seq rejected by ge=1",
            "body": {
                "event_type": "state_transition",
                "session_id": "exp-f-session-f23",
                "client_seq": -1,
                "payload": {"state": "init"},
                "timestamp": time.time()
            },
            "headers": auth_headers,
            "expected_status": 422,
            "raw_body": None
        },
        {
            "test_id": "F24_STRING_CLIENT_SEQ",
            "category": "Sequence Validation",
            "description": "String client_seq rejected by strict int typing",
            "body": {
                "event_type": "state_transition",
                "session_id": "exp-f-session-f24",
                "client_seq": "1",
                "payload": {"state": "init"},
                "timestamp": time.time()
            },
            "headers": auth_headers,
            "expected_status": 422,
            "raw_body": None
        },
        {
            "test_id": "F25_FLOAT_CLIENT_SEQ",
            "category": "Sequence Validation",
            "description": "Float client_seq rejected by strict int typing",
            "body": {
                "event_type": "state_transition",
                "session_id": "exp-f-session-f25",
                "client_seq": 1.5,
                "payload": {"state": "init"},
                "timestamp": time.time()
            },
            "headers": auth_headers,
            "expected_status": 422,
            "raw_body": None
        }
    ]

    client = httpx.Client(timeout=5.0, trust_env=False)
    results = []
    
    for case in cases:
        test_id = case["test_id"]
        headers = case["headers"]
        expected = case["expected_status"]
        
        try:
            if case.get("raw_body") is not None:
                resp = client.post(url, content=case["raw_body"], headers=headers)
            else:
                resp = client.post(url, json=case["body"], headers=headers)
            
            actual_status = resp.status_code
            try:
                resp_data = resp.json()
            except Exception:
                resp_data = resp.text[:200]
                
            passed = (actual_status == expected)
            results.append({
                "test_id": test_id,
                "category": case["category"],
                "description": case["description"],
                "expected_status": expected,
                "actual_status": actual_status,
                "passed": passed,
                "response_excerpt": str(resp_data)[:120]
            })
        except Exception as e:
            results.append({
                "test_id": test_id,
                "category": case["category"],
                "description": case["description"],
                "expected_status": expected,
                "actual_status": -1,
                "passed": False,
                "response_excerpt": f"Exception: {str(e)}"
            })

    print(json.dumps(results))

if __name__ == "__main__":
    run_suite()
