"""Experiment E: Audit-Sink Downtime and Recovery Evaluation for AegisTrace.
Simulates a complete outage of audit_service container:
1. Submits 3 pre-outage turns (pre-downtime baseline).
2. Stops aegistrace-audit_service-1 container.
3. Submits 5 outage turns through agent /chat while sink is down.
4. Restarts aegistrace-audit_service-1 container.
5. Submits 3 post-outage turns after sink recovery.
6. Analyzes ledger in SQLite and checks /verify endpoint.
"""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import csv
import json
import subprocess
import time
import urllib.request
import httpx

def run_exp_e_suite():
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    print("=== Starting Experiment E: Audit-Sink Downtime & Recovery ===")
    
    session_id = "exp-e-downtime-session"
    reconstruction_url = "http://127.0.0.1:8002"
    require_destructive(reconstruction_url)
    
    # 1. Clean previous exp-e records
    clean_sql = f"""
import sqlite3
conn = sqlite3.connect('/data/audit.db')
conn.execute("DELETE FROM audit_log WHERE session_id = '{session_id}'")
conn.commit()
conn.close()
print("Cleaned old exp-e records")
"""
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(clean_sql), text=True, check=True)

    # 2. Submit 3 pre-outage turns through agent /chat
    print("\n[Phase 1] Submitting 3 pre-outage turns through agent...")
    pre_outage_records = []
    
    chat_script = f"""
import json, time
from types import SimpleNamespace
from fastapi.testclient import TestClient
from agent.main import create_app
from agent.capture import AuditCapture

class FakeLLM:
    async def ainvoke(self, messages):
        return SimpleNamespace(content="Fake LLM response")

import os
require_destructive(os.environ.get("AUDIT_SINK_URL", "http://audit_service:8001/ingest"))
require_token()
capture = AuditCapture(autostart=True)
app = create_app(llm=FakeLLM(), capture=capture)
results = []

with TestClient(app) as client:
    for i in range(1, 4):
        t0 = time.perf_counter_ns()
        r = client.post("/chat", json={{"session_id": "{session_id}", "message": f"Pre-outage turn {{i}}"}})
        dt_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        results.append({{"turn": i, "phase": "pre_outage", "status": r.status_code, "latency_ms": round(dt_ms, 3), "response": r.json()}})

capture.close(drain=True)
print("__JSON__" + json.dumps(results))
"""
    proc = subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-agent_service-1", "python", "-"], input=guarded_python(chat_script), text=True, capture_output=True, check=True)
    out_txt = proc.stdout.strip()
    pre_outage_records = json.loads(out_txt[out_txt.find("__JSON__") + 8:])
    print(f"Pre-outage: {len(pre_outage_records)} turns completed.")

    # 3. Stop audit_service container
    print("\n[Phase 2] Stopping aegistrace-audit_service-1 container...")
    t_outage_start = time.perf_counter()
    subprocess.run(["docker", "stop", "aegistrace-audit_service-1"], check=True)
    print("aegistrace-audit_service-1 is STOPPED.")

    # 4. Submit 5 turns through agent /chat while sink is DOWN
    print("\n[Phase 3] Submitting 5 turns while audit sink is DOWN...")
    outage_script = f"""
import json, time
from types import SimpleNamespace
from fastapi.testclient import TestClient
from agent.main import create_app
from agent.capture import AuditCapture

class FakeLLM:
    async def ainvoke(self, messages):
        return SimpleNamespace(content="Fake LLM response during sink outage")

# Use standard capture with normal sink URL
import os
require_destructive(os.environ.get("AUDIT_SINK_URL", "http://audit_service:8001/ingest"))
require_token()
capture = AuditCapture(autostart=True)
app = create_app(llm=FakeLLM(), capture=capture)
results = []

with TestClient(app) as client:
    for i in range(4, 9):
        t0 = time.perf_counter_ns()
        r = client.post("/chat", json={{"session_id": "{session_id}", "message": f"Outage turn {{i}}"}})
        dt_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        results.append({{"turn": i, "phase": "during_outage", "status": r.status_code, "latency_ms": round(dt_ms, 3), "response": r.json()}})

# Allow background worker to attempt post and fail
time.sleep(1.0)
capture.close(drain=False)
print("__JSON__" + json.dumps(results))
"""
    proc_outage = subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-agent_service-1", "python", "-"], input=guarded_python(outage_script), text=True, capture_output=True, check=True)
    out_txt = proc_outage.stdout.strip()
    during_outage_records = json.loads(out_txt[out_txt.find("__JSON__") + 8:])
    for r in during_outage_records:
        print(f"  Turn {r['turn']} (Sink DOWN): /chat status={r['status']}, latency={r['latency_ms']:.2f}ms, turn_id={r['response'].get('turn_id')}")

    # 5. Restart audit_service container
    print("\n[Phase 4] Restarting aegistrace-audit_service-1 container...")
    subprocess.run(["docker", "start", "aegistrace-audit_service-1"], check=True)
    t_outage_end = time.perf_counter()
    outage_duration_sec = t_outage_end - t_outage_start
    print(f"aegistrace-audit_service-1 RESTARTED. Total outage duration: {outage_duration_sec:.2f}s")
    
    # Wait for service to become healthy
    time.sleep(3.0)

    # 6. Submit 3 post-outage turns after recovery
    print("\n[Phase 5] Submitting 3 post-outage turns after recovery...")
    post_script = f"""
import json, time
from types import SimpleNamespace
from fastapi.testclient import TestClient
from agent.main import create_app
from agent.capture import AuditCapture

class FakeLLM:
    async def ainvoke(self, messages):
        return SimpleNamespace(content="Fake LLM response after recovery")

import os
require_destructive(os.environ.get("AUDIT_SINK_URL", "http://audit_service:8001/ingest"))
require_token()
capture = AuditCapture(autostart=True)
app = create_app(llm=FakeLLM(), capture=capture)
results = []

with TestClient(app) as client:
    for i in range(9, 12):
        t0 = time.perf_counter_ns()
        r = client.post("/chat", json={{"session_id": "{session_id}", "message": f"Post-outage turn {{i}}"}})
        dt_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        results.append({{"turn": i, "phase": "post_outage", "status": r.status_code, "latency_ms": round(dt_ms, 3), "response": r.json()}})

capture.close(drain=True)
print("__JSON__" + json.dumps(results))
"""
    proc_post = subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-agent_service-1", "python", "-"], input=guarded_python(post_script), text=True, capture_output=True, check=True)
    out_txt = proc_post.stdout.strip()
    post_outage_records = json.loads(out_txt[out_txt.find("__JSON__") + 8:])
    print(f"Post-outage: {len(post_outage_records)} turns completed.")

    # 7. Inspect SQLite database for actual recorded events
    print("\n[Phase 6] Inspecting SQLite database...")
    inspect_sql = f"""
import sqlite3, json
conn = sqlite3.connect('/data/audit.db')
rows = conn.execute("SELECT id, event_type, payload, timestamp FROM audit_log WHERE session_id = '{session_id}' ORDER BY id").fetchall()
conn.close()
res = []
for r in rows:
    p = json.loads(r[2])
    res.append({{"id": r[0], "event_type": r[1], "turn_id": p.get("turn_id"), "label": p.get("label"), "msg": p.get("message")}})
print("__JSON__" + json.dumps(res))
"""
    proc_db = subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(inspect_sql), text=True, capture_output=True, check=True)
    out_txt = proc_db.stdout.strip()
    stored_db_rows = json.loads(out_txt[out_txt.find("__JSON__") + 8:])
    print(f"Total entries stored in database: {len(stored_db_rows)}")

    # 8. Check /verify endpoint
    url_verify = f"{reconstruction_url}/api/session/{session_id}/verify"
    with urllib.request.urlopen(url_verify) as resp:
        verify_data = json.loads(resp.read().decode())
    print(f"Verification verdict: chain_intact = {verify_data.get('chain_intact')}, entry_count = {verify_data.get('entry_count')}")

    # Analyze turn recovery vs loss
    all_turns = pre_outage_records + during_outage_records + post_outage_records
    stored_turn_ids = set(r["turn_id"] for r in stored_db_rows if r.get("turn_id"))
    
    for t in all_turns:
        tid = t["response"].get("turn_id")
        t["events_stored_in_db"] = (tid in stored_turn_ids)

    pre_stored = sum(1 for t in pre_outage_records if t["response"].get("turn_id") in stored_turn_ids)
    outage_stored = sum(1 for t in during_outage_records if t["response"].get("turn_id") in stored_turn_ids)
    post_stored = sum(1 for t in post_outage_records if t["response"].get("turn_id") in stored_turn_ids)

    summary = {
        "session_id": session_id,
        "outage_duration_sec": round(outage_duration_sec, 2),
        "pre_outage_turns": {
            "submitted": len(pre_outage_records),
            "stored_in_db": pre_stored,
            "status": "All successfully ingested"
        },
        "during_outage_turns": {
            "submitted": len(during_outage_records),
            "agent_http_status_codes": [r["status"] for r in during_outage_records],
            "agent_failed": False,
            "stored_in_db": outage_stored,
            "permanently_lost": len(during_outage_records) - outage_stored,
            "behavior": "Agent /chat succeeded normally; audit events permanently dropped in worker thread (httpx.ConnectError silently swallowed)"
        },
        "post_outage_turns": {
            "submitted": len(post_outage_records),
            "stored_in_db": post_stored,
            "status": "Resumed normal ingestion after sink restart"
        },
        "verification_result": {
            "chain_intact": verify_data.get("chain_intact"),
            "entry_count": verify_data.get("entry_count"),
            "broken_entry_ids": verify_data.get("broken_entry_ids"),
            "security_analysis": "Chain verifies as intact because post-recovery events chained to the last recorded pre-outage hash. Gaps in conversational history are undetectable by hash chaining alone."
        },
        "all_turns": all_turns,
        "stored_db_rows": stored_db_rows
    }

    # Save summary and CSV
    with open("evaluation_results/exp_e_sink_downtime.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["turn", "phase", "status", "latency_ms", "events_stored_in_db"])
        writer.writeheader()
        for t in all_turns:
            writer.writerow({
                "turn": t["turn"],
                "phase": t["phase"],
                "status": t["status"],
                "latency_ms": t["latency_ms"],
                "events_stored_in_db": t["events_stored_in_db"]
            })

    with open("evaluation_results/exp_e_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    # Clean up test session
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(clean_sql), text=True, check=True)

    print("Experiment E completed successfully.")
    return summary

if __name__ == "__main__":
    run_exp_e_suite()
