"""Experiment B2: Next-Unused-Counter Forgery Evaluation for AegisTrace.

Tests whether an adversary possessing AUDIT_WRITE_TOKEN who submits the next
unused monotonic client_seq counter can evade detection, and characterizes
boundary conditions (counter skips, collisions with legitimate agents, and anchor interactions).

Cases:
C1: Same-session forward forgery, correct counter (3 legit [1,2,3] + 3 forged [4,5,6])
C2: Same-session forward forgery, skipped counter (3 legit [1,2,3] + 1 forged [9])
C3: Cross-session forgery, correct counter (3 victim legit [1,2,3] + 3 forged [4,5,6])
C4: Collision with a live legitimate agent (3 legit [1,2,3] + 3 forged [4,5,6] + 3 legit [4,5,6])
C5: Anchor interaction (9 legit [1..9] + 6 forged [10..15], anchor fires at 10)
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
from typing import Any, Dict, List

# In-container injection script: runs inside aegistrace-agent_service-1
CONTAINER_SCRIPT = """
import json
import os
import sys
import time
import httpx

token = require_token()
if not token:
    print(json.dumps({"error": "AUDIT_WRITE_TOKEN not found"}), file=sys.stderr)
    sys.exit(1)

audit_url = os.environ.get("AUDIT_SINK_URL", "http://audit_service:8001/ingest")
require_destructive(audit_url)
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
client = httpx.Client(timeout=5.0, trust_env=False)

def post_event(session_id: str, seq: int, event_type: str, payload: dict, sensitive: bool = False):
    body = {
        "session_id": session_id,
        "client_seq": seq,
        "timestamp": float(time.time()),
        "event_type": event_type,
        "payload": payload,
        "sensitive_action_flag": sensitive
    }
    r = client.post(audit_url, json=body, headers=headers)
    return r.status_code, r.text[:200]

def legit_payload(seq: int):
    return {"step": seq, "legitimate": True, "message": f"Legitimate turn {seq}"}

def forged_payload(seq: int):
    return {
        "step": seq,
        "forged": True,
        "action": "unauthorized_data_exfiltration",
        "message": f"Adversarial forged event {seq}"
    }

results = []
trials_per_case = 10

# --- C1: Same-session forward forgery, correct counter ---
for t in range(1, trials_per_case + 1):
    sid = f"exp-b2-c1-t{t:02d}"
    legit_statuses = []
    for s in [1, 2, 3]:
        etype = "retrieval" if s == 1 else ("tool_start" if s == 2 else "tool_end")
        code, _ = post_event(sid, s, etype, legit_payload(s))
        legit_statuses.append(code)
    
    forged_statuses = []
    for s in [4, 5, 6]:
        etype = "tool_start" if s == 4 else ("tool_end" if s == 5 else "state_transition")
        code, _ = post_event(sid, s, etype, forged_payload(s))
        forged_statuses.append(code)
    
    results.append({
        "case": "C1",
        "trial": t,
        "session_id": sid,
        "legit_statuses": legit_statuses,
        "forged_statuses": forged_statuses,
        "target_session_id": sid
    })

# --- C2: Same-session forward forgery, skipped counter ---
for t in range(1, trials_per_case + 1):
    sid = f"exp-b2-c2-t{t:02d}"
    legit_statuses = []
    for s in [1, 2, 3]:
        etype = "retrieval" if s == 1 else ("tool_start" if s == 2 else "tool_end")
        code, _ = post_event(sid, s, etype, legit_payload(s))
        legit_statuses.append(code)
    
    forged_statuses = []
    # Skipped counter: submit client_seq=9 (skipping 4..8)
    code, _ = post_event(sid, 9, "state_transition", forged_payload(9))
    forged_statuses.append(code)
    
    results.append({
        "case": "C2",
        "trial": t,
        "session_id": sid,
        "legit_statuses": legit_statuses,
        "forged_statuses": forged_statuses,
        "target_session_id": sid
    })

# --- C3: Cross-session forgery, correct counter ---
for t in range(1, trials_per_case + 1):
    sid = f"exp-b2-c3-victim-t{t:02d}"
    legit_statuses = []
    for s in [1, 2, 3]:
        etype = "retrieval" if s == 1 else ("tool_start" if s == 2 else "tool_end")
        code, _ = post_event(sid, s, etype, legit_payload(s))
        legit_statuses.append(code)
    
    forged_statuses = []
    for s in [4, 5, 6]:
        etype = "tool_start" if s == 4 else ("tool_end" if s == 5 else "state_transition")
        code, _ = post_event(sid, s, etype, forged_payload(s))
        forged_statuses.append(code)
    
    results.append({
        "case": "C3",
        "trial": t,
        "session_id": sid,
        "legit_statuses": legit_statuses,
        "forged_statuses": forged_statuses,
        "target_session_id": sid
    })

# --- C4: Collision with a live legitimate agent ---
for t in range(1, trials_per_case + 1):
    sid = f"exp-b2-c4-t{t:02d}"
    legit_statuses = []
    # 1. Honest agent starts with 1, 2, 3
    for s in [1, 2, 3]:
        etype = "retrieval" if s == 1 else ("tool_start" if s == 2 else "tool_end")
        code, _ = post_event(sid, s, etype, legit_payload(s))
        legit_statuses.append(code)
    
    # 2. Forger injects 4, 5, 6
    forged_statuses = []
    for s in [4, 5, 6]:
        etype = "tool_start" if s == 4 else ("tool_end" if s == 5 else "state_transition")
        code, _ = post_event(sid, s, etype, forged_payload(s))
        forged_statuses.append(code)
    
    # 3. Honest agent continues without knowing, emitting 4, 5, 6 from its memory counter
    colliding_legit_statuses = []
    for s in [4, 5, 6]:
        etype = "retrieval" if s == 4 else ("tool_start" if s == 5 else "tool_end")
        code, _ = post_event(sid, s, etype, legit_payload(s))
        colliding_legit_statuses.append(code)
    
    results.append({
        "case": "C4",
        "trial": t,
        "session_id": sid,
        "legit_statuses": legit_statuses + colliding_legit_statuses,
        "forged_statuses": forged_statuses,
        "target_session_id": sid
    })

# --- C5: Anchor interaction ---
for t in range(1, trials_per_case + 1):
    sid = f"exp-b2-c5-t{t:02d}"
    legit_statuses = []
    # 1. 9 legitimate events (1..9)
    for s in range(1, 10):
        etype = "retrieval" if s == 1 else ("tool_start" if s % 2 == 0 else "tool_end")
        code, _ = post_event(sid, s, etype, legit_payload(s))
        legit_statuses.append(code)
    
    # 2. Forger injects 10..15 (anchor fires at event 10!)
    forged_statuses = []
    for s in range(10, 16):
        etype = "tool_start" if s % 2 == 0 else "tool_end"
        code, _ = post_event(sid, s, etype, forged_payload(s))
        forged_statuses.append(code)
    
    results.append({
        "case": "C5",
        "trial": t,
        "session_id": sid,
        "legit_statuses": legit_statuses,
        "forged_statuses": forged_statuses,
        "target_session_id": sid
    })

print("__EXP_B2_START__" + json.dumps(results) + "__EXP_B2_END__")
"""

def verify_session(reconstruction_url: str, session_id: str) -> Dict[str, Any]:
    url = f"{reconstruction_url}/api/session/{session_id}/verify"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=10.0) as resp:
        return json.loads(resp.read().decode())

def run_experiment_b2():
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    print("=== Starting Experiment B2: Next-Unused-Counter Forgery Evaluation ===")
    
    reconstruction_url = "http://127.0.0.1:8002"
    require_destructive(reconstruction_url)
    
    # 1. Execute the in-container script inside aegistrace-agent_service-1
    print("Executing attack scenarios inside container aegistrace-agent_service-1...")
    proc = subprocess.run(
        ["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-agent_service-1", "python", "-"],
        input=guarded_python(CONTAINER_SCRIPT),
        text=True,
        capture_output=True,
        check=True
    )
    
    raw_out = proc.stdout.strip()
    s_marker = "__EXP_B2_START__"
    e_marker = "__EXP_B2_END__"
    s_idx = raw_out.find(s_marker)
    e_idx = raw_out.find(e_marker)
    if s_idx == -1 or e_idx == -1:
        print("ERROR: Could not parse output from container execution!")
        print("STDOUT:", raw_out)
        print("STDERR:", proc.stderr)
        sys.exit(1)
        
    container_trials = json.loads(raw_out[s_idx + len(s_marker):e_idx])
    print(f"Container execution completed: {len(container_trials)} trials executed across C1-C5.")
    
    # Allow background anchor dispatch thread to flush
    time.sleep(1.0)
    
    # 2. Query reconstruction service for every session
    print("Querying reconstruction service verification for each trial...")
    csv_rows = []
    raw_verifier_records = {}
    sample_verifications = {}
    
    for item in container_trials:
        case = item["case"]
        trial = item["trial"]
        sid = item["session_id"]
        forged_statuses = item["forged_statuses"]
        
        v = verify_session(reconstruction_url, sid)
        raw_verifier_records[f"{case}_t{trial:02d}"] = {
            "case": case,
            "trial": trial,
            "session_id": sid,
            "forged_statuses": forged_statuses,
            "verification": v
        }
        
        # Save sample verification for output report (trial 1 of each case)
        if trial == 1:
            sample_verifications[case] = v
            
        chain_intact = v.get("chain_intact", False)
        sequence_complete = v.get("sequence_complete", False)
        anchor_status = v.get("anchor_status", "n/a")
        broken_entry_ids = v.get("broken_entry_ids", [])
        duplicate_seq = v.get("duplicate_seq", [])
        out_of_order_seq = v.get("out_of_order_seq", [])
        sequence_gaps = v.get("sequence_gaps", [])
        missing_events_total = v.get("missing_events_total", 0)
        
        # Consistent anchor status definition: 'verified' or 'no_anchor'
        anchors_consistent = (anchor_status in ("verified", "no_anchor"))
        
        # Definition: "verifier reported anything other than chain_intact=True AND sequence_complete=True AND anchors consistent"
        detected = not (chain_intact is True and sequence_complete is True and anchors_consistent)
        
        # Missing ranges representation
        missing_ranges_str = json.dumps(sequence_gaps) if sequence_gaps else "none"
        
        csv_rows.append({
            "case": case,
            "trial": trial,
            "session_id": sid,
            "forged_statuses": json.dumps(forged_statuses),
            "all_forged_200": all(code == 200 for code in forged_statuses),
            "chain_intact": chain_intact,
            "sequence_complete": sequence_complete,
            "missing_ranges": missing_ranges_str,
            "missing_events_total": missing_events_total,
            "duplicate_seq": json.dumps(duplicate_seq),
            "out_of_order": json.dumps(out_of_order_seq),
            "anchor_status": anchor_status,
            "broken_entry_ids": json.dumps(broken_entry_ids),
            "detected": detected
        })

    # 3. Save to results/raw_v2/exp_b2_next_counter.csv and .json
    os.makedirs("results/raw_v2", exist_ok=True)
    csv_path = "results/raw_v2/exp_b2_next_counter.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(csv_rows[0].keys()))
        writer.writeheader()
        writer.writerows(csv_rows)
        
    json_path = "results/raw_v2/exp_b2_next_counter.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(raw_verifier_records, f, indent=2)
        
    print(f"\nRaw CSV saved to: {csv_path}")
    print(f"Raw JSON saved to: {json_path}")
    
    # 4. Generate summary table
    print("\n" + "="*80)
    print("EXPERIMENT B2: SUMMARY TABLE")
    print("="*80)
    summary_by_case = {}
    for case in ["C1", "C2", "C3", "C4", "C5"]:
        case_rows = [r for r in csv_rows if r["case"] == case]
        n_trials = len(case_rows)
        all_200 = sum(1 for r in case_rows if r["all_forged_200"])
        n_detected = sum(1 for r in case_rows if r["detected"])
        sample_v = sample_verifications[case]
        
        rep_intact = sample_v.get("chain_intact")
        rep_seq = sample_v.get("sequence_complete")
        rep_dup = sample_v.get("duplicate_seq")
        rep_gaps = sample_v.get("missing_events_total")
        rep_anchor = sample_v.get("anchor_status")
        
        summary_by_case[case] = {
            "trials": n_trials,
            "accepted_200": f"{all_200}/{n_trials}",
            "detected_ratio": f"{n_detected}/{n_trials}",
            "report_summary": f"chain_intact={rep_intact}, seq_complete={rep_seq}, dups={rep_dup}, missing={rep_gaps}, anchor={rep_anchor}"
        }
        print(f"Case {case} | Trials: {n_trials} | Forged Accepted (200): {all_200}/{n_trials} | Detected: {n_detected}/{n_trials} | Verifier: {summary_by_case[case]['report_summary']}")
    print("="*80)
    
    return summary_by_case, sample_verifications

if __name__ == "__main__":
    run_experiment_b2()
