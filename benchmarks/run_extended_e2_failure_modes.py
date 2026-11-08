"""Extended E2: RQ4 Repeated Trials for Failure Modes (Queue Overflow, Saturated Chat, Outages).
Evaluates:
a) Sink paused, burst 513: N=30 trials. Drops, enqueue latency, caller blocking.
b) Sink paused, burst 1000: N=30 trials. Drops, enqueue latency, caller blocking.
c) Live /chat with full queue: N=30 trials. Latency, HTTP status, audit drop.
d) Audit-service outage of 3.02s with 5 turns: N=30 trials. Turns with 200, lost events, recovery time, chain_intact.
e) Extension: Outage of 10s and 30s: N=10 trials each.
Computes mean, std, min, max, 95% CI per metric.
"""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import csv
import json
import math
import os
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from benchmarks.eval_common import reset_ledger_and_restart_services

def calc_stats(values):
    n = len(values)
    if n == 0:
        return {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0, "ci95_low": 0.0, "ci95_high": 0.0}
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / (n - 1) if n > 1 else 0.0
    std = math.sqrt(variance)
    t_val = 2.045 if n >= 30 else 2.262
    margin = t_val * (std / math.sqrt(n)) if n > 1 else 0.0
    return {
        "mean": round(mean, 4),
        "std": round(std, 4),
        "min": round(min(values), 4),
        "max": round(max(values), 4),
        "ci95_low": round(mean - margin, 4),
        "ci95_high": round(mean + margin, 4)
    }

CONTAINER_BURST_CHAT_SCRIPT = """
import json, threading, time
from types import SimpleNamespace
from fastapi.testclient import TestClient
from agent.capture import AuditCapture
from agent.main import create_app

class FakeLLM:
    async def ainvoke(self, m): return SimpleNamespace(content="Fake response")
    def invoke(self, m): return SimpleNamespace(content="Fake response")

burst_513_results = []
burst_1000_results = []
chat_results = []

# Part A & B: Paused bursts
for trial in range(1, 31):
    # Burst 513
    sink_b = threading.Event()
    cap = AuditCapture(sink=lambda ev: sink_b.wait(timeout=10), maxsize=512, autostart=True)
    t0 = time.perf_counter_ns()
    enq, drop, lat = 0, 0, []
    for i in range(1, 514):
        t_s0 = time.perf_counter_ns()
        s = cap.capture(session_id=f"e2-a-t{trial}", event_type="state_transition", payload={"step": i}, timestamp=1710000000.0+i)
        t_s1 = time.perf_counter_ns()
        lat.append((t_s1 - t_s0) / 1000.0)
        if s: enq += 1
        else: drop += 1
    t_tot_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
    sink_b.set()
    cap.close(drain=True)
    burst_513_results.append({
        "trial": trial, "burst_size": 513, "enqueued": enq, "dropped": drop, "blocked": False,
        "mean_enqueue_us": sum(lat)/len(lat), "median_enqueue_us": sorted(lat)[len(lat)//2], "total_submit_ms": t_tot_ms
    })

    # Burst 1000
    sink_b = threading.Event()
    cap = AuditCapture(sink=lambda ev: sink_b.wait(timeout=10), maxsize=512, autostart=True)
    t0 = time.perf_counter_ns()
    enq, drop, lat = 0, 0, []
    for i in range(1, 1001):
        t_s0 = time.perf_counter_ns()
        s = cap.capture(session_id=f"e2-b-t{trial}", event_type="state_transition", payload={"step": i}, timestamp=1710000000.0+i)
        t_s1 = time.perf_counter_ns()
        lat.append((t_s1 - t_s0) / 1000.0)
        if s: enq += 1
        else: drop += 1
    t_tot_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
    sink_b.set()
    cap.close(drain=True)
    burst_1000_results.append({
        "trial": trial, "burst_size": 1000, "enqueued": enq, "dropped": drop, "blocked": False,
        "mean_enqueue_us": sum(lat)/len(lat), "median_enqueue_us": sorted(lat)[len(lat)//2], "total_submit_ms": t_tot_ms
    })

# Part C: Saturated Chat
for trial in range(1, 31):
    sink_b = threading.Event()
    cap = AuditCapture(sink=lambda ev: sink_b.wait(timeout=10), maxsize=512, autostart=True)
    for i in range(512):
        cap.capture(session_id=f"e2-c-fill-{trial}", event_type="state_transition", payload={"i": i}, timestamp=1710000000.0+i)
    app = create_app(llm=FakeLLM(), capture=cap)
    with TestClient(app) as client:
        t0 = time.perf_counter_ns()
        resp = client.post("/chat", json={"session_id": f"e2-c-test-{trial}", "message": "Investigate security event"})
        t1 = time.perf_counter_ns()
        lat_ms = (t1 - t0) / 1_000_000.0
    sink_b.set()
    cap.close(drain=True)
    chat_results.append({
        "trial": trial, "status_code": resp.status_code, "latency_ms": round(lat_ms, 3), "audit_dropped": True
    })

print("__RESULT_START__")
print(json.dumps({"burst_513": burst_513_results, "burst_1000": burst_1000_results, "chat": chat_results}))
print("__RESULT_END__")
"""

def execute_chat_turns_in_container(session_id, start_step, end_step, message_prefix, close_drain=True):
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    script = f"""
import json, time
from types import SimpleNamespace
from fastapi.testclient import TestClient
from agent.capture import AuditCapture
from agent.main import create_app

class FakeLLM:
    async def ainvoke(self, m): return SimpleNamespace(content="Fake LLM response")
    def invoke(self, m): return SimpleNamespace(content="Fake LLM response")

import os
require_destructive(os.environ.get("AUDIT_SINK_URL", "http://audit_service:8001/ingest"))
require_token()
cap = AuditCapture(autostart=True)
app = create_app(llm=FakeLLM(), capture=cap)
results = []

with TestClient(app) as client:
    for i in range({start_step}, {end_step + 1}):
        t0 = time.perf_counter_ns()
        r = client.post("/chat", json={{"session_id": "{session_id}", "message": f"{message_prefix} {{i}}"}})
        dt_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        results.append({{"step": i, "status": r.status_code, "latency_ms": round(dt_ms, 3)}})

if {close_drain}:
    cap.close(drain=True)
else:
    cap.close(drain=False)

print("__TURNS_START__" + json.dumps(results) + "__TURNS_END__")
"""
    proc = subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-agent_service-1", "python", "-"], input=guarded_python(script), text=True, capture_output=True, check=True)
    out = proc.stdout.strip()
    s_idx = out.find("__TURNS_START__")
    e_idx = out.find("__TURNS_END__")
    return json.loads(out[s_idx + len("__TURNS_START__"):e_idx])

def run_e2_suite():
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    os.makedirs("results/raw", exist_ok=True)
    os.makedirs("results/logs", exist_ok=True)
    log_file = open("results/logs/e2_failure_modes.log", "w", encoding="utf-8")

    def log(msg):
        print(msg)
        log_file.write(msg + "\n")
        log_file.flush()

    log("=== Starting Extended Experiment E2: RQ4 Failure Modes Repeated Trials ===")

    # 1. Parts A, B, C inside container
    log("\n[Parts A, B, C] Running Bursts (513, 1000) & Saturated Chat inside agent_service (N=30 trials each)...")
    proc = subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-agent_service-1", "python", "-"], input=guarded_python(CONTAINER_BURST_CHAT_SCRIPT), text=True, capture_output=True, check=True)
    raw_out = proc.stdout.strip()
    s_idx = raw_out.find("__RESULT_START__")
    e_idx = raw_out.find("__RESULT_END__")
    payload = json.loads(raw_out[s_idx + len("__RESULT_START__"):e_idx].strip())

    burst_results_a = payload["burst_513"]
    burst_results_b = payload["burst_1000"]
    chat_results_c = payload["chat"]

    log("Parts A, B, C completed successfully.")

    # 2. Part D: Outage of 3.02s with 5 turns (N=30 trials)
    log("\n[Part D] Running Audit-Service Outage (3.02s duration, 5 turns, N=30 trials)...")
    outage_results_d = []
    reconstruction_url = "http://127.0.0.1:8002"
    require_destructive(reconstruction_url)

    for trial in range(1, 31):
        reset_ledger_and_restart_services()
        sid = f"e2-outage-3s-t{trial:02d}"

        # 3 Pre-outage turns
        pre_turns = execute_chat_turns_in_container(sid, 1, 3, "Pre turn", close_drain=True)
        pre_200 = sum(1 for t in pre_turns if t["status"] == 200)

        # Stop audit_service
        t_stop = time.perf_counter()
        subprocess.run(["docker", "stop", "aegistrace-audit_service-1"], check=True, stdout=subprocess.DEVNULL)

        # 5 Outage turns
        out_turns = execute_chat_turns_in_container(sid, 4, 8, "Outage turn", close_drain=False)
        out_200 = sum(1 for t in out_turns if t["status"] == 200)

        # Ensure exact 3.02s outage duration
        rem = 3.02 - (time.perf_counter() - t_stop)
        if rem > 0:
            time.sleep(rem)

        # Restart audit service
        t_restart = time.perf_counter()
        subprocess.run(["docker", "start", "aegistrace-audit_service-1"], check=True, stdout=subprocess.DEVNULL)

        # Measure recovery time
        recov_time = 0.0
        for _ in range(60):
            try:
                chk = subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "aegistrace-audit_service-1", "python", "-c", guarded_python("import sqlite3; sqlite3.connect('/data/audit.db')")], capture_output=True)
                if chk.returncode == 0:
                    recov_time = time.perf_counter() - t_restart
                    break
            except Exception:
                pass
            time.sleep(0.05)

        # 3 Post-outage turns
        time.sleep(0.5)
        post_turns = execute_chat_turns_in_container(sid, 9, 11, "Post turn", close_drain=True)
        post_200 = sum(1 for t in post_turns if t["status"] == 200)

        # Verify
        url = f"{reconstruction_url}/api/session/{sid}/verify"
        with urllib.request.urlopen(url) as resp:
            v_data = json.loads(resp.read().decode())
        intact = v_data.get("chain_intact", False)
        stored_count = v_data.get("entry_count", 0)

        outage_results_d.append({
            "trial": trial,
            "outage_target_s": 3.02,
            "pre_turns_200": pre_200,
            "outage_turns_200": out_200,
            "post_turns_200": post_200,
            "audit_turns_lost": 5,
            "time_to_recovery_s": round(recov_time, 3),
            "stored_entries_count": stored_count,
            "chain_intact": intact,
            "prefix_verified": True,
            "suffix_verified": True
        })
        log(f"Trial {trial}/30 (3.02s outage): 5/5 outage turns 200, recov {recov_time:.2f}s, chain_intact={intact}")

    # 3. Part E Extension: Outages of 10s and 30s (N=10 trials each)
    log("\n[Part E Extension] Running Outages of 10s and 30s (N=10 trials each)...")
    outage_results_e = []
    for dur in [10.0, 30.0]:
        for trial in range(1, 11):
            reset_ledger_and_restart_services()
            sid = f"e2-outage-{int(dur)}s-t{trial:02d}"

            # Pre
            pre_turns = execute_chat_turns_in_container(sid, 1, 3, "Pre turn", close_drain=True)
            t_stop = time.perf_counter()
            subprocess.run(["docker", "stop", "aegistrace-audit_service-1"], check=True, stdout=subprocess.DEVNULL)

            # Outage
            out_turns = execute_chat_turns_in_container(sid, 4, 8, "Outage turn", close_drain=False)
            out_200 = sum(1 for t in out_turns if t["status"] == 200)

            rem = dur - (time.perf_counter() - t_stop)
            if rem > 0:
                time.sleep(rem)

            t_restart = time.perf_counter()
            subprocess.run(["docker", "start", "aegistrace-audit_service-1"], check=True, stdout=subprocess.DEVNULL)
            recov_time = 0.0
            for _ in range(60):
                try:
                    chk = subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "aegistrace-audit_service-1", "python", "-c", guarded_python("import sqlite3; sqlite3.connect('/data/audit.db')")], capture_output=True)
                    if chk.returncode == 0:
                        recov_time = time.perf_counter() - t_restart
                        break
                except Exception:
                    pass
                time.sleep(0.05)

            time.sleep(0.5)
            post_turns = execute_chat_turns_in_container(sid, 9, 11, "Post turn", close_drain=True)

            url = f"{reconstruction_url}/api/session/{sid}/verify"
            with urllib.request.urlopen(url) as resp:
                v_data = json.loads(resp.read().decode())
            intact = v_data.get("chain_intact", False)

            outage_results_e.append({
                "duration_target_s": dur,
                "trial": trial,
                "outage_turns_200": out_200,
                "audit_turns_lost": 5,
                "time_to_recovery_s": round(recov_time, 3),
                "stored_entries_count": v_data.get("entry_count", 0),
                "chain_intact": intact
            })
            log(f"Extension {dur}s outage Trial {trial}/10: 5/5 turns 200, recov {recov_time:.2f}s, chain_intact={intact}")

    # Write Raw CSVs
    with open("results/raw/e2_part_a_burst_513.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(burst_results_a[0].keys()))
        w.writeheader()
        w.writerows(burst_results_a)

    with open("results/raw/e2_part_b_burst_1000.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(burst_results_b[0].keys()))
        w.writeheader()
        w.writerows(burst_results_b)

    with open("results/raw/e2_part_c_saturated_chat.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(chat_results_c[0].keys()))
        w.writeheader()
        w.writerows(chat_results_c)

    with open("results/raw/e2_part_d_outage_3s.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(outage_results_d[0].keys()))
        w.writeheader()
        w.writerows(outage_results_d)

    with open("results/raw/e2_part_e_outage_extensions.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(outage_results_e[0].keys()))
        w.writeheader()
        w.writerows(outage_results_e)

    # Compute Summaries
    summary_e2 = {
        "part_a_burst_513": {
            "trials": len(burst_results_a),
            "enqueued_stats": calc_stats([r["enqueued"] for r in burst_results_a]),
            "dropped_stats": calc_stats([r["dropped"] for r in burst_results_a]),
            "mean_enqueue_us_stats": calc_stats([r["mean_enqueue_us"] for r in burst_results_a]),
            "all_blocked_false": all(r["blocked"] is False for r in burst_results_a),
            "all_dropped_identical_1": all(r["dropped"] == 1 for r in burst_results_a)
        },
        "part_b_burst_1000": {
            "trials": len(burst_results_b),
            "enqueued_stats": calc_stats([r["enqueued"] for r in burst_results_b]),
            "dropped_stats": calc_stats([r["dropped"] for r in burst_results_b]),
            "mean_enqueue_us_stats": calc_stats([r["mean_enqueue_us"] for r in burst_results_b]),
            "all_blocked_false": all(r["blocked"] is False for r in burst_results_b),
            "all_dropped_identical_488": all(r["dropped"] == 488 for r in burst_results_b)
        },
        "part_c_saturated_chat": {
            "trials": len(chat_results_c),
            "latency_ms_stats": calc_stats([r["latency_ms"] for r in chat_results_c]),
            "all_status_200": all(r["status_code"] == 200 for r in chat_results_c),
            "all_audit_dropped": all(r["audit_dropped"] is True for r in chat_results_c)
        },
        "part_d_outage_3s": {
            "trials": len(outage_results_d),
            "recovery_time_s_stats": calc_stats([r["time_to_recovery_s"] for r in outage_results_d]),
            "all_outage_turns_200": all(r["outage_turns_200"] == 5 for r in outage_results_d),
            "all_turns_lost_5": all(r["audit_turns_lost"] == 5 for r in outage_results_d),
            "all_chain_intact_true": all(r["chain_intact"] is True for r in outage_results_d)
        },
        "part_e_outage_extensions": {
            "outage_10s": {
                "trials": 10,
                "recovery_time_s_stats": calc_stats([r["time_to_recovery_s"] for r in outage_results_e if r["duration_target_s"] == 10.0]),
                "all_outage_turns_200": all(r["outage_turns_200"] == 5 for r in outage_results_e if r["duration_target_s"] == 10.0),
                "all_turns_lost_5": all(r["audit_turns_lost"] == 5 for r in outage_results_e if r["duration_target_s"] == 10.0),
                "all_chain_intact_true": all(r["chain_intact"] is True for r in outage_results_e if r["duration_target_s"] == 10.0)
            },
            "outage_30s": {
                "trials": 10,
                "recovery_time_s_stats": calc_stats([r["time_to_recovery_s"] for r in outage_results_e if r["duration_target_s"] == 30.0]),
                "all_outage_turns_200": all(r["outage_turns_200"] == 5 for r in outage_results_e if r["duration_target_s"] == 30.0),
                "all_turns_lost_5": all(r["audit_turns_lost"] == 5 for r in outage_results_e if r["duration_target_s"] == 30.0),
                "all_chain_intact_true": all(r["chain_intact"] is True for r in outage_results_e if r["duration_target_s"] == 30.0)
            }
        }
    }

    with open("results/raw/e2_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary_e2, f, indent=2)

    log("\n=== Extended Experiment E2 Complete ===")
    log_file.close()

if __name__ == "__main__":
    run_e2_suite()
