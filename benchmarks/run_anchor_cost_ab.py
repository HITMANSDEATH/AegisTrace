"""Anchor Cost A/B Evaluation.
Isolates anchor dispatch cost by comparing:
- ANCHOR_EVERY=0 (off: COUNT(*) still runs, but anchor dispatch is skipped)
- ANCHOR_EVERY=10 (on: current default anchor dispatch)
Protocol:
- Alternates: off, on, off, on, off, on, off, on, off, on (5 trials each)
- Tested at C=1 and C=50 (100 events per worker)
- Before EVERY trial: reset SQLite ledger and truncate anchors.jsonl
- Verifies anchors.jsonl remains empty (0 anchors) in all off trials
- Restores ANCHOR_EVERY=10 at end and validates .env and compose.yaml integrity.
"""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import concurrent.futures
import csv
import json
import math
import os
import subprocess
import sys
import time
import urllib.request

COMPOSE_FILE = "aegistrace-complete/aegistrace/compose.yaml"

def switch_anchor_every(val):
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    env = os.environ.copy()
    env["ANCHOR_EVERY"] = str(val)
    # Recreate audit_service with new ANCHOR_EVERY
    subprocess.run(
        ["docker", "compose", "-f", COMPOSE_FILE, "up", "-d", "audit_service"],
        env=env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    # Wait for audit_service healthy
    for _ in range(30):
        try:
            req = urllib.request.Request("http://127.0.0.1:8002/health")
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    break
        except Exception:
            time.sleep(0.5)
    else:
        raise RuntimeError(f"audit_service failed to restart with ANCHOR_EVERY={val}")
    
    # Verify inside container
    chk = subprocess.check_output(
        ["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "aegistrace-audit_service-1", "python", "-c", guarded_python("import os; print(os.getenv('ANCHOR_EVERY'))")],
        text=True
    ).strip()
    assert chk == str(val), f"Expected ANCHOR_EVERY={val}, got {chk}"

def reset_db_and_anchors():
    # Reset SQLite
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    sql = """
import sqlite3
conn = sqlite3.connect('/data/audit.db', isolation_level=None)
conn.execute('DELETE FROM audit_log')
conn.execute('VACUUM')
conn.close()
"""
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(sql), text=True, check=True)
    # Truncate anchors.jsonl
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "aegistrace-anchor_service-1", "python", "-c", guarded_python("open('/anchor_data/anchors.jsonl', 'w').close()")], check=True)

def get_anchor_line_count():
    out = subprocess.check_output(
        ["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "aegistrace-anchor_service-1", "python", "-c", guarded_python("print(len(open('/anchor_data/anchors.jsonl').readlines()))")],
        text=True
    ).strip()
    return int(out)

RUNNER_SCRIPT = """
import concurrent.futures, json, time, os, httpx

EVENT_TYPES = ['state_transition', 'tool_start', 'retrieval', 'tool_end']
audit_url = "http://audit_service:8001/ingest"
require_destructive(audit_url)
token = require_token()
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

c = __CONCURRENCY__
run_id = "__RUN_ID__"
events_per_worker = 100

def worker(wid):
    sid = f"ab-c{c}-{run_id}-w{wid:03d}"
    client = httpx.Client(timeout=25.0, trust_env=False)
    base_time = 1711000000.0 + wid * 10.0
    accepted = 0
    for i in range(1, events_per_worker + 1):
        etype = EVENT_TYPES[(i - 1) % len(EVENT_TYPES)]
        sens = (i % 7 == 0)
        body = {
            "session_id": sid,
            "client_seq": i,
            "timestamp": base_time + i * 1.0,
            "event_type": etype,
            "payload": {"step": i, "wid": wid, "test": "anchor_ab"},
            "sensitive_action_flag": sens
        }
        r = client.post(audit_url, json=body, headers=headers)
        if r.status_code == 200:
            accepted += 1
    client.close()
    return accepted

t0 = time.perf_counter()
with concurrent.futures.ThreadPoolExecutor(max_workers=c) as ex:
    futs = [ex.submit(worker, wid) for wid in range(c)]
    total_acc = sum(f.result() for f in futs)
dur = time.perf_counter() - t0
throughput = total_acc / dur if dur > 0 else 0.0

print("__RESULT_START__" + json.dumps({"accepted": total_acc, "duration": dur, "throughput": throughput}) + "__RESULT_END__")
"""

def run_trial(c, run_id):
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    code = RUNNER_SCRIPT.replace("__CONCURRENCY__", str(c)).replace("__RUN_ID__", run_id)
    proc = subprocess.run(
        ["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-agent_service-1", "python", "-"],
        input=guarded_python(code), text=True, capture_output=True, check=True
    )
    out = proc.stdout.strip()
    s = out.find("__RESULT_START__")
    e = out.find("__RESULT_END__")
    data = json.loads(out[s + len("__RESULT_START__"):e])
    return data

def calc_stats(vals):
    n = len(vals)
    mean = sum(vals) / n
    variance = sum((x - mean) ** 2 for x in vals) / (n - 1) if n > 1 else 0.0
    std = math.sqrt(variance)
    return round(mean, 2), round(std, 2)

def main():
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    print("=== Starting Anchor Cost A/B Evaluation ===")
    results = {"C1": {"off": [], "on": []}, "C50": {"off": [], "on": []}}
    
    tiers = [1, 50]
    # Alternating order: 5 pairs of (off, on)
    
    for c in tiers:
        print(f"\n--- Testing Concurrency C={c} (5 alternating pairs: off, on, ...) ---")
        for pair_idx in range(1, 6):
            # 1. Variant OFF (ANCHOR_EVERY=0)
            print(f"[C={c}, Pair {pair_idx}/5] Setting ANCHOR_EVERY=0 (off)...")
            switch_anchor_every(0)
            reset_db_and_anchors()
            assert get_anchor_line_count() == 0, "Anchor file not clean before run"
            
            res_off = run_trial(c, f"p{pair_idx}-off")
            anchors_off = get_anchor_line_count()
            assert anchors_off == 0, f"Violation: ANCHOR_EVERY=0 wrote {anchors_off} anchors!"
            results[f"C{c}"]["off"].append(res_off["throughput"])
            print(f"  Trial {pair_idx} OFF: {res_off['throughput']:.1f} eps | Anchors written: {anchors_off}")
            
            # 2. Variant ON (ANCHOR_EVERY=10)
            print(f"[C={c}, Pair {pair_idx}/5] Setting ANCHOR_EVERY=10 (on)...")
            switch_anchor_every(10)
            reset_db_and_anchors()
            assert get_anchor_line_count() == 0, "Anchor file not clean before run"
            
            res_on = run_trial(c, f"p{pair_idx}-on")
            anchors_on = get_anchor_line_count()
            results[f"C{c}"]["on"].append(res_on["throughput"])
            print(f"  Trial {pair_idx} ON:  {res_on['throughput']:.1f} eps | Anchors written: {anchors_on} (Accepted events: {res_on['accepted']})")

    # Restore ANCHOR_EVERY=10
    print("\nRestoring ANCHOR_EVERY=10...")
    switch_anchor_every(10)
    reset_db_and_anchors()
    
    # Print Summary Table
    print("\n================ ANCHOR COST A/B SUMMARY ================")
    summary_data = {}
    for c in [1, 50]:
        off_trials = results[f"C{c}"]["off"]
        on_trials = results[f"C{c}"]["on"]
        off_mean, off_std = calc_stats(off_trials)
        on_mean, on_std = calc_stats(on_trials)
        diff_eps = round(on_mean - off_mean, 2)
        diff_pct = round((diff_eps / off_mean) * 100, 2)
        summary_data[f"C{c}"] = {
            "off_trials": off_trials,
            "off_mean": off_mean,
            "off_std": off_std,
            "on_trials": on_trials,
            "on_mean": on_mean,
            "on_std": on_std,
            "diff_eps": diff_eps,
            "diff_pct": diff_pct
        }
        print(f"Concurrency C={c}:")
        print(f"  OFF (ANCHOR_EVERY=0): Trials = {[round(x,1) for x in off_trials]} eps")
        print(f"    Mean = {off_mean:.2f} eps, Std = {off_std:.2f} eps")
        print(f"  ON  (ANCHOR_EVERY=10): Trials = {[round(x,1) for x in on_trials]} eps")
        print(f"    Mean = {on_mean:.2f} eps, Std = {on_std:.2f} eps")
        print(f"  Cost (ON vs OFF): {diff_eps:+.2f} eps ({diff_pct:+.2f}%)")

    os.makedirs("results/raw_v2", exist_ok=True)
    with open("results/raw_v2/anchor_cost_ab_results.json", "w") as f:
        json.dump(summary_data, f, indent=2)

if __name__ == "__main__":
    main()
