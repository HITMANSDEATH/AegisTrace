"""Tail Rewrite Class: Mutation and downstream hash recomputation touching only rows 21 to 25.
10 sessions x 25 events ingested live through audit_service.
Anchors emitted at count=10 and count=20.
Evaluates anchor_status when tampering is restricted to the unanchored tail.
"""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import concurrent.futures
import hashlib
import json
import os
import random
import subprocess
import sys
import time
import urllib.request

def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)

def entry_hash(timestamp, payload_str, prev_hash):
    return hashlib.sha256((str(float(timestamp)) + payload_str + prev_hash).encode("utf-8")).hexdigest()

def run_tail_rewrite_test():
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    reconstruction_url = "http://127.0.0.1:8002"
    require_destructive(reconstruction_url)
    sessions = [f"live-s1337-tail_rewrite-{i:03d}" for i in range(10)]
    
    # 1. Ingest 10 sessions live through audit_service
    ingest_script = f"""
import httpx, json, os

EVENT_TYPES = ['state_transition', 'tool_start', 'retrieval', 'tool_end']
audit_url = "http://audit_service:8001/ingest"
require_destructive(audit_url)
token = require_token()
headers = {{"Authorization": f"Bearer {{token}}", "Content-Type": "application/json"}}

sessions = {repr(sessions)}

client = httpx.Client(timeout=15.0, trust_env=False)
base_time = 1710900000.0

for sid in sessions:
    for i in range(1, 26):
        etype = EVENT_TYPES[(i - 1) % len(EVENT_TYPES)]
        sens = (i % 7 == 0)
        body = {{
            "session_id": sid,
            "client_seq": i,
            "timestamp": base_time + i * 1.5,
            "event_type": etype,
            "payload": {{"step": i, "label": f"Step {{i}}", "message": f"Step {{i}} for {{sid}}"}},
            "sensitive_action_flag": sens
        }}
        resp = client.post(audit_url, json=body, headers=headers)
        if resp.status_code != 200:
            raise RuntimeError(f"Failed {{sid}} step {{i}}: {{resp.status_code}} {{resp.text}}")
client.close()
print("INGEST_COMPLETE")
"""
    proc = subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-agent_service-1", "python", "-"],
                          input=guarded_python(ingest_script), text=True, capture_output=True, check=True)
    print(proc.stdout.strip())
    time.sleep(1.0) # allow background anchor dispatch to settle

    # 2. Retrieve row data for these 10 sessions from SQLite
    query_sql = f"""
import sqlite3, json
conn = sqlite3.connect('/data/audit.db')
rows = conn.execute("SELECT id, session_id, timestamp, event_type, payload, sensitive_action_flag, prev_hash, hash FROM audit_log WHERE session_id LIKE 'live-s1337-tail_rewrite-%' ORDER BY id").fetchall()
conn.close()
m = {{}}
for r in rows:
    m.setdefault(r[1], []).append({{'id': r[0], 'ts': r[2], 'type': r[3], 'pld': r[4], 'flag': r[5], 'prev': r[6], 'hash': r[7]}})
print(json.dumps(m))
"""
    proc = subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"],
                          input=guarded_python(query_sql), text=True, capture_output=True, check=True)
    session_rows = json.loads(proc.stdout.strip())

    # 3. Apply mutations: mutate at row 21 (or random row in 21..24) and recompute downstream hashes up to row 25
    rng = random.Random(42)
    mut_stmts = []
    mutation_info = {}

    for sid in sessions:
        rows = session_rows[sid] # 25 rows
        # Choose mutation point p in 21..23
        p = rng.randint(21, 23)
        curr_prev = rows[p - 2]['hash'] # valid prev hash from row p-1
        mutation_info[sid] = {"mutated_row": p}
        for idx in range(p - 1, 25):
            r = rows[idx]
            if idx == p - 1:
                pld = json.loads(r['pld'])
                pld['rewritten'] = "tail_rewrite_unanchored"
                ser = canonical_json(pld)
            else:
                ser = r['pld']
            h = entry_hash(r['ts'], ser, curr_prev)
            mut_stmts.append(("UPDATE audit_log SET payload = ?, prev_hash = ?, hash = ? WHERE id = ?", (ser, curr_prev, h, r['id'])))
            curr_prev = h

    # Execute updates in SQLite
    apply_sql = f"""
import sqlite3
conn = sqlite3.connect('/data/audit.db', isolation_level=None)
cur = conn.cursor()
cur.execute('BEGIN IMMEDIATE')
for stmt, params in {repr(mut_stmts)}:
    cur.execute(stmt, params)
cur.execute('COMMIT')
conn.close()
"""
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"],
                          input=guarded_python(apply_sql), text=True, capture_output=True, check=True)
    print(f"Applied {len(mut_stmts)} row updates across {len(sessions)} tail-rewrite sessions.")

    # 4. Verify each session
    results = []
    for sid in sessions:
        url = f"{reconstruction_url}/api/session/{sid}/verify"
        with urllib.request.urlopen(url) as resp:
            v = json.loads(resp.read().decode())
        res = {
            "session_id": sid,
            "mutated_row": mutation_info[sid]["mutated_row"],
            "touching_rows": f"{mutation_info[sid]['mutated_row']}..25",
            "chain_intact": v.get("chain_intact"),
            "sequence_complete": v.get("sequence_complete"),
            "anchor_status": v.get("anchor_status"),
            "anchored_count": v.get("anchored_count"),
            "unanchored_tail_events": v.get("unanchored_tail_events")
        }
        results.append(res)

    print("\n================ TAIL REWRITE TEST RESULTS ================")
    print(f"{'Session ID':<36} {'Mutated Row':<14} {'Chain Intact':<14} {'Anchor Status':<16} {'Anchored Cnt':<14}")
    print("-" * 95)
    for r in results:
        print(f"{r['session_id']:<36} {r['mutated_row']:<14} {str(r['chain_intact']):<14} {r['anchor_status']:<16} {r['anchored_count']:<14}")

    os.makedirs("results/raw_v2", exist_ok=True)
    with open("results/raw_v2/tail_rewrite_results.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    run_tail_rewrite_test()
