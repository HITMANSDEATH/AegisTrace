"""V2 Failure Modes Benchmark: Bounded Queue Saturation & Sink Outage.
Evaluates:
a) Burst 513 (10 trials): sink paused, burst 513, resume/drain, send 1 final event, verify sequence gap.
b) Burst 1000 (10 trials): sink paused, burst 1000, resume/drain, send 1 final event, verify sequence gap.
c) Outage ~3s (10 trials): 3 pre turns, pause/stop audit service for ~3s with 5 outage turns, restart audit service,
   send 1 final turn after recovery, verify sequence gap.
Measures and compares dropped_count vs missing_events_total per trial.
Saves to results/raw_v2/e2_failure_modes_v2.csv and results/raw_v2/e2_failure_modes_summary.json.
"""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import csv
import json
import os
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from benchmarks.eval_common import reset_ledger_and_restart_services

BURST_RUNNER_CONTAINER_SCRIPT = """
import json, threading, time, os
from agent.capture import AuditCapture

token = require_token()
audit_url = os.environ.get("AUDIT_SINK_URL", "http://audit_service:8001/ingest")
require_destructive(audit_url)

def run_burst_trial(trial, burst_size):
    sid = f"v2-burst-{burst_size}-t{trial:02d}"
    
    # Capture with worker stopped so bounded queue (512) fills
    real_cap = AuditCapture(audit_url=audit_url, token=token, maxsize=512, autostart=False)
    
    enqueued = 0
    dropped = 0
    for i in range(1, burst_size + 1):
        s = real_cap.capture(
            session_id=sid,
            event_type="state_transition",
            payload={"step": i, "burst": burst_size},
            timestamp=1710100000.0 + i
        )
        if s:
            enqueued += 1
        else:
            dropped += 1
            
    # Drain enqueued events to real audit_service
    real_cap.start()
    real_cap.close(drain=True)
    
    # Send one final event after recovery
    final_cap = AuditCapture(audit_url=audit_url, token=token, maxsize=512, autostart=True)
    final_cap._session_seq[sid] = real_cap._session_seq[sid]
    final_seq = burst_size + 1
    s_fin = final_cap.capture(
        session_id=sid,
        event_type="state_transition",
        payload={"step": final_seq, "post_recovery": True},
        timestamp=1710100000.0 + final_seq
    )
    final_cap.close(drain=True)
    
    return {
        "trial": trial,
        "burst_size": burst_size,
        "session_id": sid,
        "enqueued": enqueued,
        "dropped": dropped,
        "final_event_sent": s_fin
    }

results_513 = [run_burst_trial(t, 513) for t in range(1, 11)]
results_1000 = [run_burst_trial(t, 1000) for t in range(1, 11)]

print("__BURST_START__" + json.dumps({"b513": results_513, "b1000": results_1000}) + "__BURST_END__")
"""

def execute_chat_turns_in_container(session_id, start_step, end_step, message_prefix, initial_seq=0, close_drain=True):
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    script = f"""
import json, time, os
from types import SimpleNamespace
from fastapi.testclient import TestClient
from agent.capture import AuditCapture
from agent.main import create_app

class FakeLLM:
    async def ainvoke(self, m): return SimpleNamespace(content="Fake response")
    def invoke(self, m): return SimpleNamespace(content="Fake response")

token = require_token()
audit_url = os.environ.get("AUDIT_SINK_URL", "http://audit_service:8001/ingest")
require_destructive(audit_url)
cap = AuditCapture(audit_url=audit_url, token=token, autostart=True)
if {initial_seq} > 0:
    cap._session_seq["{session_id}"] = {initial_seq}

app = create_app(llm=FakeLLM(), capture=cap)
results = []

with TestClient(app) as client:
    for i in range({start_step}, {end_step + 1}):
        t0 = time.perf_counter_ns()
        r = client.post("/chat", json={{"session_id": "{session_id}", "message": f"{message_prefix} {{i}}"}})
        dt_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        results.append({{"step": i, "status": r.status_code, "latency_ms": round(dt_ms, 3)}})

final_seq = cap._session_seq.get("{session_id}", {initial_seq})
events_created = final_seq - {initial_seq}

if {close_drain}:
    cap.close(drain=True)
else:
    cap.close(drain=False)

print("__TURNS_START__" + json.dumps({{"turns": results, "final_seq": final_seq, "events_created": events_created}}) + "__TURNS_END__")
"""
    proc = subprocess.run(
        ["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-agent_service-1", "python", "-"],
        input=guarded_python(script), text=True, capture_output=True, check=True
    )
    out = proc.stdout.strip()
    s_idx = out.find("__TURNS_START__")
    e_idx = out.find("__TURNS_END__")
    return json.loads(out[s_idx + len("__TURNS_START__"):e_idx])

def run_v2_failure_modes_suite():
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    os.makedirs("results/raw_v2", exist_ok=True)
    os.makedirs("results/logs_v2", exist_ok=True)
    log_file = open("results/logs_v2/e2_failure_modes_v2.log", "w", encoding="utf-8")

    def log(msg):
        print(msg)
        log_file.write(msg + "\n")
        log_file.flush()

    log("=== Starting V2 Failure Modes Benchmark (10 trials each) ===")
    reset_ledger_and_restart_services()
    reconstruction_url = "http://127.0.0.1:8002"
    require_destructive(reconstruction_url)

    # Part 1: Burst 513 and Burst 1000
    log("\n[Part 1] Running Burst 513 & Burst 1000 inside agent container...")
    proc = subprocess.run(
        ["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-agent_service-1", "python", "-"],
        input=guarded_python(BURST_RUNNER_CONTAINER_SCRIPT), text=True, capture_output=True, check=True
    )
    out = proc.stdout.strip()
    s_idx = out.find("__BURST_START__")
    e_idx = out.find("__BURST_END__")
    burst_data = json.loads(out[s_idx + len("__BURST_START__"):e_idx])

    csv_rows = []

    # Reconcile Burst 513
    for b in burst_data["b513"]:
        sid = b["session_id"]
        url = f"{reconstruction_url}/api/session/{sid}/verify"
        with urllib.request.urlopen(url) as resp:
            v = json.loads(resp.read().decode())
        missing = v.get("missing_events_total", 0)
        match = (b["dropped"] == missing)
        csv_rows.append({
            "test_type": "burst_513",
            "trial": b["trial"],
            "session_id": sid,
            "enqueued": b["enqueued"],
            "dropped_count": b["dropped"],
            "missing_events_total": missing,
            "counts_match": match,
            "chain_intact": v.get("chain_intact", False),
            "sequence_complete": v.get("sequence_complete", False),
            "stored_entries": v.get("entry_count", 0)
        })
        log(f"Burst 513 Trial {b['trial']:02d}: dropped={b['dropped']}, missing_events_total={missing}, match={match}")

    # Reconcile Burst 1000
    for b in burst_data["b1000"]:
        sid = b["session_id"]
        url = f"{reconstruction_url}/api/session/{sid}/verify"
        with urllib.request.urlopen(url) as resp:
            v = json.loads(resp.read().decode())
        missing = v.get("missing_events_total", 0)
        match = (b["dropped"] == missing)
        csv_rows.append({
            "test_type": "burst_1000",
            "trial": b["trial"],
            "session_id": sid,
            "enqueued": b["enqueued"],
            "dropped_count": b["dropped"],
            "missing_events_total": missing,
            "counts_match": match,
            "chain_intact": v.get("chain_intact", False),
            "sequence_complete": v.get("sequence_complete", False),
            "stored_entries": v.get("entry_count", 0)
        })
        log(f"Burst 1000 Trial {b['trial']:02d}: dropped={b['dropped']}, missing_events_total={missing}, match={match}")

    # Part 2: Sink Outage ~3s (10 trials)
    log("\n[Part 2] Running Sink Outage ~3s (10 trials)...")
    for trial in range(1, 11):
        reset_ledger_and_restart_services()
        sid = f"v2-outage-3s-t{trial:02d}"

        # 1. Pre turns: 3 turns
        pre_info = execute_chat_turns_in_container(sid, 1, 3, "Pre turn", initial_seq=0, close_drain=True)
        seq_after_pre = pre_info["final_seq"]

        # 2. Stop audit service
        t0_out = time.perf_counter()
        subprocess.run(["docker", "stop", "aegistrace-audit_service-1"], check=True, stdout=subprocess.DEVNULL)

        # 3. Outage turns: 5 turns
        out_info = execute_chat_turns_in_container(sid, 4, 8, "Outage turn", initial_seq=seq_after_pre, close_drain=False)
        seq_after_outage = out_info["final_seq"]
        dropped_events = out_info["events_created"]

        rem = 3.02 - (time.perf_counter() - t0_out)
        if rem > 0:
            time.sleep(rem)

        # 4. Restart audit service
        subprocess.run(["docker", "start", "aegistrace-audit_service-1"], check=True, stdout=subprocess.DEVNULL)
        # Wait for audit service to be ready
        for _ in range(50):
            try:
                with urllib.request.urlopen("http://127.0.0.1:8002/health") as resp:
                    if resp.status == 200:
                        break
            except Exception:
                time.sleep(0.1)

        time.sleep(0.5)

        # 5. Send one final event (1 post-recovery turn)
        post_info = execute_chat_turns_in_container(sid, 9, 9, "Post recovery turn", initial_seq=seq_after_outage, close_drain=True)

        # 6. Verify
        url = f"{reconstruction_url}/api/session/{sid}/verify"
        with urllib.request.urlopen(url) as resp:
            v = json.loads(resp.read().decode())

        missing = v.get("missing_events_total", 0)
        match = (missing == dropped_events)

        csv_rows.append({
            "test_type": "outage_3s",
            "trial": trial,
            "session_id": sid,
            "enqueued": v.get("entry_count", 0),
            "dropped_count": dropped_events,
            "missing_events_total": missing,
            "counts_match": match,
            "chain_intact": v.get("chain_intact", False),
            "sequence_complete": v.get("sequence_complete", False),
            "stored_entries": v.get("entry_count", 0)
        })
        log(f"Outage ~3s Trial {trial:02d}: dropped={dropped_events}, missing_events_total={missing}, match={match}")

    # Write CSV
    csv_path = "results/raw_v2/e2_failure_modes_v2.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(csv_rows[0].keys()))
        w.writeheader()
        w.writerows(csv_rows)

    # Write summary JSON
    summary_path = "results/raw_v2/e2_failure_modes_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(csv_rows, f, indent=2)

    log(f"\nRaw CSV saved to {csv_path}")
    log(f"Summary JSON saved to {summary_path}")

if __name__ == "__main__":
    run_v2_failure_modes_suite()
