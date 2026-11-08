"""Live-Ingest Tamper and Truncation Benchmark for AegisTrace.
All events are ingested through live audit_service /ingest so that:
1. Rows are genuine schema_version: 2 rows with client_seq sealed in _aegis by audit_service.
2. Anchors are emitted by audit_service into anchor_service at count=10 and count=20 (ANCHOR_EVERY=10).
3. Sessions have 25 events, giving an unanchored tail of 5 events (events 21..25).

Classes evaluated:
- Clean_Control (30 sessions x 25 events)
- 6 Original classes (30 sessions each = 180 sessions)
  A1_single_event_payload, A2_timestamp_modification, A3_prev_hash_modification,
  A4_envelope_tamper_session, A5_envelope_tamper_event_type, A6_envelope_tamper_flag
- New / Extended classes (10 sessions each = 130 sessions):
  mid_chain_row_deletion, duplicate_row, reordered_rows,
  full_history_rewrite,
  suffix_truncation_N1, suffix_truncation_N2, suffix_truncation_N3, suffix_truncation_N4,
  suffix_truncation_N5, suffix_truncation_N6, suffix_truncation_N7, suffix_truncation_N10, suffix_truncation_N15
Total: 340 sessions x 25 events = 8,500 events ingested live.
"""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import concurrent.futures
import csv
import hashlib
import json
import os
import random
import subprocess
import sys
import time
import urllib.request
import httpx

sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from benchmarks.eval_common import reset_ledger_and_restart_services

EVENT_TYPES = ['state_transition', 'tool_start', 'retrieval', 'tool_end']

def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)

def entry_hash(timestamp, payload_str, prev_hash):
    return hashlib.sha256((str(float(timestamp)) + payload_str + prev_hash).encode("utf-8")).hexdigest()

ORIGINAL_CONDITIONS = [
    "A1_single_event_payload",
    "A2_timestamp_modification",
    "A3_prev_hash_modification",
    "A4_envelope_tamper_session",
    "A5_envelope_tamper_event_type",
    "A6_envelope_tamper_flag"
]

EXTENDED_CONDITIONS = [
    "mid_chain_row_deletion",
    "duplicate_row",
    "reordered_rows",
    "full_history_rewrite",
    "suffix_truncation_N1",
    "suffix_truncation_N2",
    "suffix_truncation_N3",
    "suffix_truncation_N4",
    "suffix_truncation_N5",
    "suffix_truncation_N6",
    "suffix_truncation_N7",
    "suffix_truncation_N10",
    "suffix_truncation_N15"
]

TRUNC_MAP = {
    "suffix_truncation_N1": 1,
    "suffix_truncation_N2": 2,
    "suffix_truncation_N3": 3,
    "suffix_truncation_N4": 4,
    "suffix_truncation_N5": 5,
    "suffix_truncation_N6": 6,
    "suffix_truncation_N7": 7,
    "suffix_truncation_N10": 10,
    "suffix_truncation_N15": 15
}

def map_reasons_to_checks(errors):
    checks = []
    for e in errors:
        r = e.get("reason", "")
        if "hash mismatch" in r.lower():
            checks.append("TamperDetected")
        elif "link mismatch" in r.lower():
            checks.append("LinkBreak")
        elif "envelope" in r.lower() or "sealed" in r.lower():
            checks.append("EnvelopeMismatch")
        else:
            checks.append(r)
    return list(dict.fromkeys(checks))

def run_live_tamper_suite():
    token = require_token()
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    os.makedirs("results/raw_v2", exist_ok=True)
    os.makedirs("results/logs_v2", exist_ok=True)
    log_file = open("results/logs_v2/e1_tamper_live_ingest.log", "w", encoding="utf-8")

    def log(msg):
        print(msg)
        log_file.write(msg + "\n")
        log_file.flush()

    log("=== Starting Live-Ingest Tamper & Truncation Benchmark (Real Audit & Anchor Code Paths) ===")
    reset_ledger_and_restart_services()

    # Clear anchor log in anchor_service container
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "aegistrace-anchor_service-1", "python", "-c",
                    guarded_python("open('/anchor_data/anchors.jsonl', 'w').close()")], check=True)
    log("Ledger reset and anchor log truncated.")

    seed = 1337
    rng = random.Random(seed)
    token = require_token()
    reconstruction_url = "http://127.0.0.1:8002"
    require_destructive(reconstruction_url)

    # Build session list
    # Part A: 30 clean + 180 tampered = 210 sessions
    clean_sids = [f"live-s{seed}-clean-{i:03d}" for i in range(30)]
    orig_sessions = {}
    for cond in ORIGINAL_CONDITIONS:
        orig_sessions[cond] = [f"live-s{seed}-{cond}-{i:03d}" for i in range(30)]

    # New / Extended classes: 10 sessions each
    ext_sessions = {}
    for cond in EXTENDED_CONDITIONS:
        ext_sessions[cond] = [f"live-s{seed}-{cond}-{i:03d}" for i in range(10)]

    all_sessions_to_ingest = []
    for sid in clean_sids:
        all_sessions_to_ingest.append(("Clean_Control", sid))
    for cond in ORIGINAL_CONDITIONS:
        for sid in orig_sessions[cond]:
            all_sessions_to_ingest.append((cond, sid))
    for cond in EXTENDED_CONDITIONS:
        for sid in ext_sessions[cond]:
            all_sessions_to_ingest.append((cond, sid))

    log(f"Ingesting {len(all_sessions_to_ingest)} sessions (25 events each = {len(all_sessions_to_ingest)*25} total) via live audit_service...")

    # We run the ingestion inside agent_service container for fastest networking
    ingest_runner_code = f"""
import concurrent.futures, json, time, os, httpx

EVENT_TYPES = ['state_transition', 'tool_start', 'retrieval', 'tool_end']
audit_url = "http://audit_service:8001/ingest"
require_destructive(audit_url)
token = require_token()
headers = {{"Authorization": f"Bearer {{token}}", "Content-Type": "application/json"}}

sessions = {repr([s[1] for s in all_sessions_to_ingest])}

def ingest_one(sid):
    client = httpx.Client(timeout=15.0, trust_env=False)
    base_time = 1710000000.0
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
            raise RuntimeError(f"Ingest failed for {{sid}} seq {{i}}: {{resp.status_code}} {{resp.text}}")
    client.close()
    return sid

t0 = time.perf_counter()
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
    results = list(ex.map(ingest_one, sessions))
dur = time.perf_counter() - t0
print(f"INGEST_DONE: {{len(results)}} sessions in {{dur:.2f}}s ({{len(results)*25/dur:.1f}} eps)")
"""
    proc = subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-agent_service-1", "python", "-"],
                          input=guarded_python(ingest_runner_code), text=True, capture_output=True, check=True)
    log(proc.stdout.strip())

    # Wait 1.0s to ensure any asynchronous anchor background dispatch is flushed
    time.sleep(1.0)

    # Check anchor count recorded in anchor service
    chk_a = subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "aegistrace-anchor_service-1", "python", "-c",
                            guarded_python("print(len(open('/anchor_data/anchors.jsonl').readlines()))")],
                           capture_output=True, text=True, check=True)
    log(f"Anchors automatically recorded by anchor_service: {chk_a.stdout.strip()} (Expected: {len(all_sessions_to_ingest) * 2})")

    # Fetch all inserted row data from SQLite
    query_sql = """
import sqlite3, json
conn = sqlite3.connect('/data/audit.db')
rows = conn.execute("SELECT id, session_id, timestamp, event_type, payload, sensitive_action_flag, prev_hash, hash FROM audit_log ORDER BY id").fetchall()
conn.close()
m = {}
for r in rows:
    m.setdefault(r[1], []).append({'id': r[0], 'ts': r[2], 'type': r[3], 'pld': r[4], 'flag': r[5], 'prev': r[6], 'hash': r[7]})
print(json.dumps(m))
"""
    proc = subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"],
                          input=guarded_python(query_sql), text=True, capture_output=True, check=True)
    all_db_rows = json.loads(proc.stdout.strip())

    # Plan and apply database mutations
    mut_stmts = []

    # 1. Mutate Original 6 Conditions (Part A)
    for cond in ORIGINAL_CONDITIONS:
        for sid in orig_sessions[cond]:
            rows = all_db_rows[sid] # 25 rows
            p = rng.randint(2, 24)
            target = rows[p - 1]
            tid = target['id']

            if cond == "A1_single_event_payload":
                pld = json.loads(target['pld'])
                pld['message'] = "Tampered message payload in live ingest"
                mut_stmts.append(("UPDATE audit_log SET payload = ? WHERE id = ?", (canonical_json(pld), tid)))
            elif cond == "A2_timestamp_modification":
                mut_stmts.append(("UPDATE audit_log SET timestamp = ? WHERE id = ?", (target['ts'] + 10.0, tid)))
            elif cond == "A3_prev_hash_modification":
                mut_stmts.append(("UPDATE audit_log SET prev_hash = ? WHERE id = ?", ("c" * 64, tid)))
            elif cond == "A4_envelope_tamper_session":
                mut_stmts.append(("UPDATE audit_log SET session_id = ? WHERE id = ?", ("forged-sid-live", tid)))
            elif cond == "A5_envelope_tamper_event_type":
                alt = "retrieval" if target['type'] == "state_transition" else "state_transition"
                mut_stmts.append(("UPDATE audit_log SET event_type = ? WHERE id = ?", (alt, tid)))
            elif cond == "A6_envelope_tamper_flag":
                mut_stmts.append(("UPDATE audit_log SET sensitive_action_flag = ? WHERE id = ?", (1 - target['flag'], tid)))

    # 2. Mutate Extended Conditions
    for cond in EXTENDED_CONDITIONS:
        for sid in ext_sessions[cond]:
            rows = all_db_rows[sid] # 25 rows
            if cond == "mid_chain_row_deletion":
                p = rng.randint(2, 24)
                tid = rows[p - 1]['id']
                mut_stmts.append(("DELETE FROM audit_log WHERE id = ?", (tid,)))
            elif cond == "duplicate_row":
                p = rng.randint(2, 23)
                dup = rows[p - 1]
                mut_stmts.append(("INSERT INTO audit_log(session_id, timestamp, event_type, payload, sensitive_action_flag, prev_hash, hash) VALUES(?,?,?,?,?,?,?)",
                                  (sid, dup['ts'] + 0.001, dup['type'], dup['pld'], dup['flag'], dup['prev'], dup['hash'])))
            elif cond == "reordered_rows":
                p = rng.randint(2, 23)
                r1 = rows[p - 1]
                r2 = rows[p]
                mut_stmts.append(("UPDATE audit_log SET timestamp = ?, payload = ?, sensitive_action_flag = ? WHERE id = ?", (r2['ts'], r2['pld'], r2['flag'], r1['id'])))
                mut_stmts.append(("UPDATE audit_log SET timestamp = ?, payload = ?, sensitive_action_flag = ? WHERE id = ?", (r1['ts'], r1['pld'], r1['flag'], r2['id'])))
            elif cond == "full_history_rewrite":
                # Mutate payload at row p (e.g. p=5), and recompute all valid downstream hashes to row 25
                p = rng.randint(2, 15)
                curr_prev = rows[p - 2]['hash']
                for idx in range(p - 1, 25):
                    r = rows[idx]
                    if idx == p - 1:
                        pld = json.loads(r['pld'])
                        pld['rewritten'] = "full_history_rewrite_live"
                        ser = canonical_json(pld)
                    else:
                        ser = r['pld']
                    h = entry_hash(r['ts'], ser, curr_prev)
                    mut_stmts.append(("UPDATE audit_log SET payload = ?, prev_hash = ?, hash = ? WHERE id = ?", (ser, curr_prev, h, r['id'])))
                    curr_prev = h
            elif cond in TRUNC_MAP:
                n = TRUNC_MAP[cond]
                del_ids = [rows[idx]['id'] for idx in range(25 - n, 25)]
                for did in del_ids:
                    mut_stmts.append(("DELETE FROM audit_log WHERE id = ?", (did,)))

    # Execute mutations in SQLite
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
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(apply_sql), text=True, check=True)
    log(f"Applied {len(mut_stmts)} mutations across Part A and extended classes.")

    # Verification
    results_records = []
    class_stats = {}

    for cond, sid in all_sessions_to_ingest:
        url = f"{reconstruction_url}/api/session/{sid}/verify"
        try:
            with urllib.request.urlopen(url) as resp:
                v = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            v = {"chain_intact": False, "anchor_status": "error", "errors": [{"reason": f"HTTP_{e.code}"}]}

        chain_intact = v.get("chain_intact", False)
        seq_complete = v.get("sequence_complete", False)
        anchor_status = v.get("anchor_status", "no_anchor")
        errors = v.get("errors", [])
        checks_fired = map_reasons_to_checks(errors)

        detected_without_anchor = (not chain_intact) or (not seq_complete)
        detected_with_anchor = detected_without_anchor or (anchor_status != 'verified')

        rec = {
            "session_id": sid,
            "condition": cond,
            "entry_count": v.get("entry_count", 0),
            "chain_intact": chain_intact,
            "sequence_complete": seq_complete,
            "anchor_status": anchor_status,
            "anchored_count": v.get("anchored_count", 0),
            "unanchored_tail_events": v.get("unanchored_tail_events", 0),
            "detected_without_anchor": detected_without_anchor,
            "detected_with_anchor": detected_with_anchor,
            "checks_fired": ";".join(checks_fired),
            "missing_events_total": v.get("missing_events_total", 0)
        }
        results_records.append(rec)

        if cond not in class_stats:
            class_stats[cond] = {
                "total": 0,
                "detected_without_anchor": 0,
                "detected_with_anchor": 0,
                "anchor_statuses": {}
            }
        class_stats[cond]["total"] += 1
        if detected_without_anchor:
            class_stats[cond]["detected_without_anchor"] += 1
        if detected_with_anchor:
            class_stats[cond]["detected_with_anchor"] += 1
        st = class_stats[cond]["anchor_statuses"]
        st[anchor_status] = st.get(anchor_status, 0) + 1

    # Save to CSV
    csv_path = "results/raw_v2/e1_tamper_v2.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(results_records[0].keys()))
        writer.writeheader()
        writer.writerows(results_records)

    # Save summary JSON
    summary_path = "results/raw_v2/e1_tamper_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(class_stats, f, indent=2)

    log("\n================ LIVE-INGEST TAMPER RESULTS SUMMARY ================")
    log(f"{'Condition':<30} {'Total':<6} {'No Anchor':<12} {'With Anchor':<12} {'Anchor Status Breakdown'}")
    log("-" * 88)
    for cond, st in class_stats.items():
        astat_str = ", ".join(f"{k}:{v}" for k, v in st["anchor_statuses"].items())
        log(f"{cond:<30} {st['total']:<6} {st['detected_without_anchor']:<12} {st['detected_with_anchor']:<12} {astat_str}")

    log(f"\nSaved results to {csv_path} and {summary_path}")

if __name__ == "__main__":
    run_live_tamper_suite()
