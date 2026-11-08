"""Extended E1: RQ1 Repeated Seeds (30 seeds) and Broader Mutations Benchmark.
Evaluates:
a) 30 seeds (1337, 1..29) on the original 6 mutation conditions (A1-A6) + Clean Control:
   - 30 clean sessions + 180 tampered sessions (30 per condition) per seed
   - 900 clean sessions, 5,400 tampered sessions total
   - Calculates per-seed & pooled detection rate, false-positive rate, exact-localization rate, Wilson 95% CIs
b) 8 Extended Mutation Classes over the same 30 seeds (10 sessions per class per seed = 300 sessions/class, 2,400 total):
   - single_field_payload
   - middle_row_deletion
   - middle_row_insertion
   - adjacent_row_swap
   - duplicated_row
   - prev_hash_rewrite_only
   - full_chain_rewrite (expected evasion)
   - suffix_truncation (expected evasion)
   - Records which check fired: LinkBreak, EnvelopeMismatch, TamperDetected, none
   - Records localization correctness
"""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import csv
import hashlib
import json
import os
import random
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from benchmarks.eval_common import wilson_interval, reset_ledger_and_restart_services

def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)

def entry_hash(timestamp, payload_str, prev_hash):
    return hashlib.sha256((str(float(timestamp)) + payload_str + prev_hash).encode("utf-8")).hexdigest()

EVENT_TYPES = ['state_transition', 'tool_start', 'retrieval', 'tool_end']

def generate_session_events(session_id, count=20, base_time=1710000000.0):
    events = []
    prev_hash = '0' * 64
    for i in range(1, count + 1):
        ts = base_time + i * 1.5
        event_type = EVENT_TYPES[(i - 1) % len(EVENT_TYPES)]
        sensitive = (i % 7 == 0)
        payload = {
            "step": i,
            "label": f"Step {i} execution",
            "message": f"Execution step {i} for {session_id}",
            "tool": "mock_executor" if "tool" in event_type else None,
            "_aegis": {
                "schema_version": 1,
                "session_id": session_id,
                "event_type": event_type,
                "sensitive_action_flag": sensitive
            }
        }
        serialized = canonical_json(payload)
        digest = entry_hash(ts, serialized, prev_hash)
        events.append({
            "session_id": session_id,
            "seq": i,
            "timestamp": ts,
            "event_type": event_type,
            "payload": payload,
            "serialized": serialized,
            "sensitive": int(sensitive),
            "prev_hash": prev_hash,
            "hash": digest
        })
        prev_hash = digest
    return events

ORIGINAL_CONDITIONS = [
    "A1_two_payload",
    "A2_five_payload",
    "A3_payload_plus_timestamp",
    "A4_payload_plus_metadata",
    "A5_adjacent_mutations",
    "A6_non_adjacent_mutations"
]

EXTENDED_CONDITIONS = [
    "ext_single_field_payload",
    "ext_middle_row_deletion",
    "ext_middle_row_insertion",
    "ext_adjacent_row_swap",
    "ext_duplicated_row",
    "ext_prev_hash_rewrite_only",
    "ext_full_chain_rewrite",
    "ext_suffix_truncation"
]

def map_reasons_to_checks(errors):
    checks = set()
    for err in errors:
        reason = err.get("reason", "")
        if "Previous-hash link mismatch" in reason:
            checks.add("LinkBreak")
        if "Sealed metadata differs" in reason:
            checks.add("EnvelopeMismatch")
        if "Payload or timestamp hash mismatch" in reason:
            checks.add("TamperDetected")
    if not checks:
        return "none"
    return "+".join(sorted(checks))

def run_e1_suite():
    require_destructive("http://127.0.0.1:8002", docker=True)
    os.makedirs("results/raw", exist_ok=True)
    os.makedirs("results/logs", exist_ok=True)
    log_file = open("results/logs/e1_tamper.log", "w", encoding="utf-8")

    def log(msg):
        print(msg)
        log_file.write(msg + "\n")
        log_file.flush()

    log("=== Starting Extended Experiment E1: RQ1 Repeated Seeds and Extended Mutations ===")
    
    seeds = [1337] + list(range(1, 30))
    reconstruction_url = "http://127.0.0.1:8002"
    require_destructive(reconstruction_url)

    part_a_csv_records = []
    part_b_csv_records = []

    seed_summaries_a = []
    seed_summaries_b = []

    for seed_idx, seed in enumerate(seeds, 1):
        log(f"\n--- [Seed {seed_idx}/30: seed={seed}] Resetting DB & Restarting Services ---")
        reset_ledger_and_restart_services()
        rng = random.Random(seed)

        # ------------------------------------------------------------------
        # PART A: Original 6 Conditions (30 clean + 180 tampered)
        # ------------------------------------------------------------------
        clean_sids = [f"e1a-s{seed}-clean-{i:03d}" for i in range(30)]
        all_clean_tuples = []
        for sid in clean_sids:
            for ev in generate_session_events(sid, count=20):
                all_clean_tuples.append((ev['session_id'], ev['timestamp'], ev['event_type'], ev['serialized'], ev['sensitive'], ev['prev_hash'], ev['hash']))

        # Prepare base events for original 6 conditions (30 sessions each = 180)
        orig_sessions = {}
        all_tamper_tuples = []
        for cond in ORIGINAL_CONDITIONS:
            sids = [f"e1a-s{seed}-{cond}-{i:03d}" for i in range(30)]
            orig_sessions[cond] = sids
            for sid in sids:
                for ev in generate_session_events(sid, count=20):
                    all_tamper_tuples.append((ev['session_id'], ev['timestamp'], ev['event_type'], ev['serialized'], ev['sensitive'], ev['prev_hash'], ev['hash']))

        # Bulk insert Part A base records
        insert_sql = f"""
import sqlite3
conn = sqlite3.connect('/data/audit.db', isolation_level=None)
cur = conn.cursor()
cur.execute('BEGIN IMMEDIATE')
cur.executemany("INSERT INTO audit_log(session_id, timestamp, event_type, payload, sensitive_action_flag, prev_hash, hash) VALUES(?,?,?,?,?,?,?)", {repr(all_clean_tuples + all_tamper_tuples)})
cur.execute('COMMIT')
conn.close()
"""
        subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(insert_sql), text=True, check=True)

        # Fetch row IDs for Part A tampered sessions
        query_sql = f"""
import sqlite3, json
conn = sqlite3.connect('/data/audit.db')
rows = conn.execute("SELECT id, session_id FROM audit_log WHERE session_id LIKE 'e1a-s{seed}-A%' ORDER BY id").fetchall()
conn.close()
m = {{}}
for r in rows:
    m.setdefault(r[1], []).append(r[0])
print(json.dumps(m))
"""
        proc = subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(query_sql), text=True, capture_output=True, check=True)
        id_mapping = json.loads(proc.stdout.strip())

        # Plan mutations for Part A
        sql_updates_a = []
        mutation_plans_a = {}
        for cond in ORIGINAL_CONDITIONS:
            for sid in orig_sessions[cond]:
                row_ids = id_mapping[sid]
                if cond == "A1_two_payload":
                    pos = sorted(rng.sample(range(1, 21), 2))
                    tids = [row_ids[p - 1] for p in pos]
                    for p, tid in zip(pos, tids):
                        pld = {"step": p, "tampered": True, "mutation": "A1", "_aegis": {"schema_version": 1, "session_id": sid, "event_type": EVENT_TYPES[(p - 1) % 4], "sensitive_action_flag": (p % 7 == 0)}}
                        sql_updates_a.append(("UPDATE audit_log SET payload = ? WHERE id = ?", (canonical_json(pld), tid)))
                    mutation_plans_a[sid] = {"expected_seqs": pos, "expected_ids": tids}
                elif cond == "A2_five_payload":
                    pos = sorted(rng.sample(range(1, 21), 5))
                    tids = [row_ids[p - 1] for p in pos]
                    for p, tid in zip(pos, tids):
                        pld = {"step": p, "tampered": True, "mutation": "A2", "_aegis": {"schema_version": 1, "session_id": sid, "event_type": EVENT_TYPES[(p - 1) % 4], "sensitive_action_flag": (p % 7 == 0)}}
                        sql_updates_a.append(("UPDATE audit_log SET payload = ? WHERE id = ?", (canonical_json(pld), tid)))
                    mutation_plans_a[sid] = {"expected_seqs": pos, "expected_ids": tids}
                elif cond == "A3_payload_plus_timestamp":
                    p1, p2 = rng.sample(range(1, 21), 2)
                    t1, t2 = row_ids[p1 - 1], row_ids[p2 - 1]
                    pld = {"step": p1, "tampered": True, "mutation": "A3", "_aegis": {"schema_version": 1, "session_id": sid, "event_type": EVENT_TYPES[(p1 - 1) % 4], "sensitive_action_flag": (p1 % 7 == 0)}}
                    sql_updates_a.append(("UPDATE audit_log SET payload = ? WHERE id = ?", (canonical_json(pld), t1)))
                    sql_updates_a.append(("UPDATE audit_log SET timestamp = timestamp + 999.0 WHERE id = ?", (t2,)))
                    exp_seqs = sorted([p1, p2])
                    mutation_plans_a[sid] = {"expected_seqs": exp_seqs, "expected_ids": [row_ids[p - 1] for p in exp_seqs]}
                elif cond == "A4_payload_plus_metadata":
                    p1, p2 = rng.sample(range(1, 21), 2)
                    t1, t2 = row_ids[p1 - 1], row_ids[p2 - 1]
                    pld = {"step": p1, "tampered": True, "mutation": "A4", "_aegis": {"schema_version": 1, "session_id": sid, "event_type": EVENT_TYPES[(p1 - 1) % 4], "sensitive_action_flag": (p1 % 7 == 0)}}
                    sql_updates_a.append(("UPDATE audit_log SET payload = ? WHERE id = ?", (canonical_json(pld), t1)))
                    sql_updates_a.append(("UPDATE audit_log SET sensitive_action_flag = 1 - sensitive_action_flag WHERE id = ?", (t2,)))
                    exp_seqs = sorted([p1, p2])
                    mutation_plans_a[sid] = {"expected_seqs": exp_seqs, "expected_ids": [row_ids[p - 1] for p in exp_seqs]}
                elif cond == "A5_adjacent_mutations":
                    sp = rng.randint(1, 19)
                    pos = [sp, sp + 1]
                    tids = [row_ids[p - 1] for p in pos]
                    for p, tid in zip(pos, tids):
                        pld = {"step": p, "tampered": True, "mutation": "A5", "_aegis": {"schema_version": 1, "session_id": sid, "event_type": EVENT_TYPES[(p - 1) % 4], "sensitive_action_flag": (p % 7 == 0)}}
                        sql_updates_a.append(("UPDATE audit_log SET payload = ? WHERE id = ?", (canonical_json(pld), tid)))
                    mutation_plans_a[sid] = {"expected_seqs": pos, "expected_ids": tids}
                elif cond == "A6_non_adjacent_mutations":
                    while True:
                        p1, p2 = sorted(rng.sample(range(1, 21), 2))
                        if p2 - p1 >= 3:
                            break
                    pos = [p1, p2]
                    tids = [row_ids[p - 1] for p in pos]
                    for p, tid in zip(pos, tids):
                        pld = {"step": p, "tampered": True, "mutation": "A6", "_aegis": {"schema_version": 1, "session_id": sid, "event_type": EVENT_TYPES[(p - 1) % 4], "sensitive_action_flag": (p % 7 == 0)}}
                        sql_updates_a.append(("UPDATE audit_log SET payload = ? WHERE id = ?", (canonical_json(pld), tid)))
                    mutation_plans_a[sid] = {"expected_seqs": pos, "expected_ids": tids}

        # Apply Part A mutations
        apply_mut_sql = f"""
import sqlite3
conn = sqlite3.connect('/data/audit.db', isolation_level=None)
cur = conn.cursor()
cur.execute('BEGIN IMMEDIATE')
for stmt, params in {repr(sql_updates_a)}:
    cur.execute(stmt, params)
cur.execute('COMMIT')
conn.close()
"""
        subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(apply_mut_sql), text=True, check=True)

        # Verify Part A clean sessions
        clean_fp = 0
        for sid in clean_sids:
            url = f"{reconstruction_url}/api/session/{sid}/verify"
            with urllib.request.urlopen(url) as resp:
                data = json.loads(resp.read().decode())
            intact = data.get("chain_intact", False)
            broken = data.get("broken_entry_ids", [])
            fp = (not intact) or (len(broken) > 0)
            if fp:
                clean_fp += 1
            part_a_csv_records.append({
                "seed": seed,
                "session_id": sid,
                "condition": "Clean_Control",
                "detected": not intact,
                "first_broken_match": True,
                "exact_localization_match": (len(broken) == 0),
                "checks_fired": map_reasons_to_checks(data.get("errors", []))
            })

        # Verify Part A tampered sessions
        tamper_detected = 0
        first_broken_matches = 0
        all_broken_matches = 0
        for cond in ORIGINAL_CONDITIONS:
            for sid in orig_sessions[cond]:
                exp_seqs = mutation_plans_a[sid]["expected_seqs"]
                exp_ids = mutation_plans_a[sid]["expected_ids"]
                url = f"{reconstruction_url}/api/session/{sid}/verify"
                with urllib.request.urlopen(url) as resp:
                    data = json.loads(resp.read().decode())
                intact = data.get("chain_intact", True)
                broken = data.get("broken_entry_ids", [])
                fb_seq = data.get("firstBroken")
                is_detected = (not intact)
                fb_match = (fb_seq == min(exp_seqs))
                all_match = (set(broken) == set(exp_ids))
                if is_detected:
                    tamper_detected += 1
                if fb_match:
                    first_broken_matches += 1
                if all_match:
                    all_broken_matches += 1
                part_a_csv_records.append({
                    "seed": seed,
                    "session_id": sid,
                    "condition": cond,
                    "detected": is_detected,
                    "first_broken_match": fb_match,
                    "exact_localization_match": all_match,
                    "checks_fired": map_reasons_to_checks(data.get("errors", []))
                })

        seed_summaries_a.append({
            "seed": seed,
            "clean_total": len(clean_sids),
            "false_positives": clean_fp,
            "fp_rate": clean_fp / len(clean_sids),
            "tampered_total": 180,
            "tamper_detected": tamper_detected,
            "detection_rate": tamper_detected / 180,
            "first_broken_matches": first_broken_matches,
            "first_broken_rate": first_broken_matches / 180,
            "all_broken_matches": all_broken_matches,
            "all_broken_rate": all_broken_matches / 180
        })
        log(f"Seed {seed} Part A: FP={clean_fp}/30, Detected={tamper_detected}/180, FirstMatch={first_broken_matches}/180, AllMatch={all_broken_matches}/180")

        # ------------------------------------------------------------------
        # PART B: 8 Extended Mutation Classes (10 sessions each = 80 per seed)
        # ------------------------------------------------------------------
        # Reset DB for Part B of this seed so mutations do not interfere
        reset_ledger_and_restart_services()

        ext_sessions = {}
        all_ext_tuples = []
        for cond in EXTENDED_CONDITIONS:
            sids = [f"e1b-s{seed}-{cond}-{i:03d}" for i in range(10)]
            ext_sessions[cond] = sids
            for sid in sids:
                for ev in generate_session_events(sid, count=20):
                    all_ext_tuples.append((ev['session_id'], ev['timestamp'], ev['event_type'], ev['serialized'], ev['sensitive'], ev['prev_hash'], ev['hash']))

        ins_ext_sql = f"""
import sqlite3
conn = sqlite3.connect('/data/audit.db', isolation_level=None)
cur = conn.cursor()
cur.execute('BEGIN IMMEDIATE')
cur.executemany("INSERT INTO audit_log(session_id, timestamp, event_type, payload, sensitive_action_flag, prev_hash, hash) VALUES(?,?,?,?,?,?,?)", {repr(all_ext_tuples)})
cur.execute('COMMIT')
conn.close()
"""
        subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(ins_ext_sql), text=True, check=True)

        # Fetch IDs for Part B
        proc = subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"],
                              input=guarded_python(f"""
import sqlite3, json
conn = sqlite3.connect('/data/audit.db')
rows = conn.execute("SELECT id, session_id, timestamp, event_type, payload, sensitive_action_flag, prev_hash, hash FROM audit_log WHERE session_id LIKE 'e1b-s{seed}-%' ORDER BY id").fetchall()
conn.close()
m = {{}}
for r in rows:
    m.setdefault(r[1], []).append({{'id': r[0], 'ts': r[2], 'type': r[3], 'pld': r[4], 'flag': r[5], 'prev': r[6], 'hash': r[7]}})
print(json.dumps(m))
"""), text=True, capture_output=True, check=True)
        ext_row_data = json.loads(proc.stdout.strip())

        # Execute customized mutations per extended class
        sql_stmts_b = []
        mutation_plans_b = {}

        for cond in EXTENDED_CONDITIONS:
            for sid in ext_sessions[cond]:
                rows = ext_row_data[sid] # 20 row dicts
                if cond == "ext_single_field_payload":
                    # Mutate 1 field in 1 payload (e.g. step=9999), keep _aegis intact
                    p = rng.randint(2, 19)
                    tid = rows[p - 1]['id']
                    pld = json.loads(rows[p - 1]['pld'])
                    pld['step'] = 9999
                    pld['message'] = "Single field mutated payload"
                    sql_stmts_b.append(("UPDATE audit_log SET payload = ? WHERE id = ?", (canonical_json(pld), tid)))
                    mutation_plans_b[sid] = {"expected_first_seq": p, "expected_detected": True, "target_id": tid}

                elif cond == "ext_middle_row_deletion":
                    # Delete 1 row at position p (2 <= p <= 19)
                    p = rng.randint(2, 19)
                    tid = rows[p - 1]['id']
                    sql_stmts_b.append(("DELETE FROM audit_log WHERE id = ?", (tid,)))
                    # When row p is deleted, row p+1 (now at index p in surviving rows) has prev_hash of deleted row,
                    # whereas prior row in DB is row p-1. So verifier flags row p+1 as LinkBreak!
                    mutation_plans_b[sid] = {"expected_first_seq": p, "expected_detected": True, "target_id": tid}

                elif cond == "ext_middle_row_insertion":
                    # Insert a forged row between row p and row p+1
                    p = rng.randint(2, 18)
                    prev_h = rows[p - 1]['hash']
                    forged_ts = rows[p - 1]['ts'] + 0.5
                    forged_pld = {"step": 999, "forged": True, "_aegis": {"schema_version": 1, "session_id": sid, "event_type": "state_transition", "sensitive_action_flag": False}}
                    forged_ser = canonical_json(forged_pld)
                    forged_hash = entry_hash(forged_ts, forged_ser, prev_h)
                    # Insert forged row
                    sql_stmts_b.append(("INSERT INTO audit_log(session_id, timestamp, event_type, payload, sensitive_action_flag, prev_hash, hash) VALUES(?,?,?,?,?,?,?)",
                                       (sid, forged_ts, "state_transition", forged_ser, 0, prev_h, forged_hash)))
                    mutation_plans_b[sid] = {"expected_first_seq": p + 1, "expected_detected": True}

                elif cond == "ext_adjacent_row_swap":
                    # Swap payloads and timestamps of rows p and p+1
                    p = rng.randint(2, 18)
                    r1 = rows[p - 1]
                    r2 = rows[p]
                    # Swap their payloads, timestamps, sensitive flags
                    sql_stmts_b.append(("UPDATE audit_log SET timestamp = ?, payload = ?, sensitive_action_flag = ? WHERE id = ?", (r2['ts'], r2['pld'], r2['flag'], r1['id'])))
                    sql_stmts_b.append(("UPDATE audit_log SET timestamp = ?, payload = ?, sensitive_action_flag = ? WHERE id = ?", (r1['ts'], r1['pld'], r1['flag'], r2['id'])))
                    mutation_plans_b[sid] = {"expected_first_seq": p, "expected_detected": True}

                elif cond == "ext_duplicated_row":
                    # Duplicate row p directly
                    p = rng.randint(2, 18)
                    dup = rows[p - 1]
                    sql_stmts_b.append(("INSERT INTO audit_log(session_id, timestamp, event_type, payload, sensitive_action_flag, prev_hash, hash) VALUES(?,?,?,?,?,?,?)",
                                       (sid, dup['ts'] + 0.001, dup['type'], dup['pld'], dup['flag'], dup['prev'], dup['hash'])))
                    mutation_plans_b[sid] = {"expected_first_seq": p, "expected_detected": True}

                elif cond == "ext_prev_hash_rewrite_only":
                    # Mutate prev_hash column of row p to all 'a's
                    p = rng.randint(2, 19)
                    tid = rows[p - 1]['id']
                    bogus_prev = "a" * 64
                    sql_stmts_b.append(("UPDATE audit_log SET prev_hash = ? WHERE id = ?", (bogus_prev, tid)))
                    mutation_plans_b[sid] = {"expected_first_seq": p, "expected_detected": True}

                elif cond == "ext_full_chain_rewrite":
                    # Mutate payload at row p, then recompute all downstream hashes and prev_hashes to row 20
                    p = rng.randint(2, 15)
                    # Recompute downstream chain
                    curr_prev = rows[p - 2]['hash'] # row p's valid prev
                    for idx in range(p - 1, 20):
                        r = rows[idx]
                        if idx == p - 1:
                            pld = json.loads(r['pld'])
                            pld['tampered'] = "full_chain_rewrite"
                            ser = canonical_json(pld)
                        else:
                            ser = r['pld']
                        h = entry_hash(r['ts'], ser, curr_prev)
                        sql_stmts_b.append(("UPDATE audit_log SET payload = ?, prev_hash = ?, hash = ? WHERE id = ?", (ser, curr_prev, h, r['id'])))
                        curr_prev = h
                    # Expected to EVADE detection because internal chain is completely consistent
                    mutation_plans_b[sid] = {"expected_first_seq": None, "expected_detected": False}

                elif cond == "ext_suffix_truncation":
                    # Drop the last k rows (e.g. drop 5 rows: rows 16..20)
                    drop_k = 5
                    drop_ids = [rows[idx]['id'] for idx in range(20 - drop_k, 20)]
                    for did in drop_ids:
                        sql_stmts_b.append(("DELETE FROM audit_log WHERE id = ?", (did,)))
                    # Expected to EVADE detection because surviving prefix is completely consistent
                    mutation_plans_b[sid] = {"expected_first_seq": None, "expected_detected": False}

        # Apply Part B mutations
        apply_mut_b_sql = f"""
import sqlite3
conn = sqlite3.connect('/data/audit.db', isolation_level=None)
cur = conn.cursor()
cur.execute('BEGIN IMMEDIATE')
for stmt, params in {repr(sql_stmts_b)}:
    cur.execute(stmt, params)
cur.execute('COMMIT')
conn.close()
"""
        subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(apply_mut_b_sql), text=True, check=True)

        # Verify Part B sessions
        for cond in EXTENDED_CONDITIONS:
            for sid in ext_sessions[cond]:
                plan = mutation_plans_b[sid]
                url = f"{reconstruction_url}/api/session/{sid}/verify"
                with urllib.request.urlopen(url) as resp:
                    data = json.loads(resp.read().decode())
                intact = data.get("chain_intact", True)
                is_detected = (not intact)
                fb_seq = data.get("firstBroken")
                checks = map_reasons_to_checks(data.get("errors", []))
                
                exp_det = plan["expected_detected"]
                exp_fb = plan["expected_first_seq"]
                
                loc_correct = False
                if exp_det and is_detected:
                    loc_correct = (fb_seq == exp_fb) or (exp_fb is not None and abs(fb_seq - exp_fb) <= 1)
                elif not exp_det and not is_detected:
                    loc_correct = True  # evasive class correctly evades without false localization

                part_b_csv_records.append({
                    "seed": seed,
                    "session_id": sid,
                    "condition": cond,
                    "detected": is_detected,
                    "expected_detected": exp_det,
                    "first_broken_seq": fb_seq,
                    "expected_first_seq": exp_fb,
                    "localization_correct": loc_correct,
                    "checks_fired": checks
                })

        log(f"Seed {seed} Part B complete.")

    # Write CSVs
    raw_csv_a = "results/raw/e1_part_a_repeated_seeds.csv"
    with open(raw_csv_a, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(part_a_csv_records[0].keys()))
        writer.writeheader()
        writer.writerows(part_a_csv_records)

    raw_csv_b = "results/raw/e1_part_b_extended_mutations.csv"
    with open(raw_csv_b, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(part_b_csv_records[0].keys()))
        writer.writeheader()
        writer.writerows(part_b_csv_records)

    # Calculate Part A Pooled and per-condition metrics
    total_clean_a = sum(s["clean_total"] for s in seed_summaries_a)
    total_fp_a = sum(s["false_positives"] for s in seed_summaries_a)
    total_tampered_a = sum(s["tampered_total"] for s in seed_summaries_a)
    total_detected_a = sum(s["tamper_detected"] for s in seed_summaries_a)
    total_first_match_a = sum(s["first_broken_matches"] for s in seed_summaries_a)
    total_all_match_a = sum(s["all_broken_matches"] for s in seed_summaries_a)

    fp_ci = wilson_interval(total_fp_a, total_clean_a)
    det_ci = wilson_interval(total_detected_a, total_tampered_a)
    loc_ci = wilson_interval(total_first_match_a, total_tampered_a)

    # Per-condition breakdown for Part A
    cond_stats_a = {}
    for cond in ORIGINAL_CONDITIONS:
        c_records = [r for r in part_a_csv_records if r["condition"] == cond]
        c_total = len(c_records)
        c_det = sum(1 for r in c_records if r["detected"])
        c_fb = sum(1 for r in c_records if r["first_broken_match"])
        c_all = sum(1 for r in c_records if r["exact_localization_match"])
        cond_stats_a[cond] = {
            "total": c_total,
            "detected": c_det,
            "detection_rate": c_det / c_total,
            "detection_ci": wilson_interval(c_det, c_total),
            "first_broken_matches": c_fb,
            "first_broken_rate": c_fb / c_total,
            "all_broken_matches": c_all,
            "all_broken_rate": c_all / c_total
        }

    # Part B breakdown
    cond_stats_b = {}
    for cond in EXTENDED_CONDITIONS:
        c_records = [r for r in part_b_csv_records if r["condition"] == cond]
        c_total = len(c_records)
        c_det = sum(1 for r in c_records if r["detected"])
        checks_counter = {}
        for r in c_records:
            checks_counter[r["checks_fired"]] = checks_counter.get(r["checks_fired"], 0) + 1
        c_loc = sum(1 for r in c_records if r["localization_correct"])
        cond_stats_b[cond] = {
            "total": c_total,
            "detected": c_det,
            "detection_rate": c_det / c_total,
            "detection_ci": wilson_interval(c_det, c_total),
            "checks_fired_distribution": checks_counter,
            "localization_correct": c_loc,
            "localization_rate": c_loc / c_total
        }

    summary_e1 = {
        "part_a": {
            "seeds_evaluated": len(seeds),
            "clean_sessions_total": total_clean_a,
            "false_positives_total": total_fp_a,
            "false_positive_rate": total_fp_a / total_clean_a,
            "fp_wilson_ci_95": fp_ci,
            "tampered_sessions_total": total_tampered_a,
            "tamper_detected_total": total_detected_a,
            "detection_rate_pooled": total_detected_a / total_tampered_a,
            "detection_wilson_ci_95": det_ci,
            "first_broken_matches_total": total_first_match_a,
            "first_broken_rate_pooled": total_first_match_a / total_tampered_a,
            "first_broken_wilson_ci_95": loc_ci,
            "all_broken_matches_total": total_all_match_a,
            "all_broken_rate_pooled": total_all_match_a / total_tampered_a,
            "condition_breakdown": cond_stats_a,
            "seed_summaries": seed_summaries_a
        },
        "part_b": {
            "seeds_evaluated": len(seeds),
            "total_extended_sessions": len(part_b_csv_records),
            "classes": cond_stats_b
        }
    }

    with open("results/raw/e1_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary_e1, f, indent=2)

    log("\n=== Extended Experiment E1 Complete ===")
    log(f"Part A Pooled: Detection={total_detected_a}/{total_tampered_a} ({total_detected_a/total_tampered_a*100:.2f}%, 95% CI: [{det_ci[0]*100:.2f}%, {det_ci[1]*100:.2f}%])")
    log(f"Part A Pooled: False Positives={total_fp_a}/{total_clean_a} ({total_fp_a/total_clean_a*100:.2f}%, 95% CI: [{fp_ci[0]*100:.2f}%, {fp_ci[1]*100:.2f}%])")
    log(f"Part A Pooled: FirstBroken Exact Match={total_first_match_a}/{total_tampered_a} ({total_first_match_a/total_tampered_a*100:.2f}%)")
    log_file.close()

if __name__ == "__main__":
    run_e1_suite()
