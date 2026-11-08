"""Experiment A: Multi-Entry Tamper Detection for AegisTrace.
Evaluates detection rate, localization accuracy, and verifier behavior across 6 mutation classes:
A1: Two payload mutations in one session
A2: Five payload mutations in one session
A3: Payload mutation plus timestamp mutation
A4: Payload mutation plus _aegis metadata mutation
A5: Multiple mutations at adjacent positions
A6: Multiple mutations at non-adjacent positions
Includes 30 clean sessions as control baseline.
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
import time
import urllib.request

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
            "message": f"Deterministic execution message for step {i} in session {session_id}",
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

def run_experiment_a(seed=1337, sessions_per_condition=30, events_per_session=20):
    require_destructive("http://127.0.0.1:8002", docker=True)
    print(f"=== Starting Experiment A: Multi-Entry Tamper Detection (Seed: {seed}) ===")
    rng = random.Random(seed)
    reconstruction_url = "http://127.0.0.1:8002"
    require_destructive(reconstruction_url)

    conditions = [
        "A1_two_payload",
        "A2_five_payload",
        "A3_payload_plus_timestamp",
        "A4_payload_plus_metadata",
        "A5_adjacent_mutations",
        "A6_non_adjacent_mutations"
    ]

    all_sessions_data = [] # for CSV export

    # 1. Clean up any existing exp-a sessions
    cleanup_sql = """
import sqlite3
conn = sqlite3.connect('/data/audit.db')
conn.execute("DELETE FROM audit_log WHERE session_id LIKE 'exp-a-%'")
conn.commit()
conn.close()
print("Cleaned existing exp-a records")
"""
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(cleanup_sql), text=True, check=True)

    # 2. Control Baseline: 30 Clean Sessions
    print(f"\n[Baseline] Generating {sessions_per_condition} clean control sessions...")
    clean_sessions = [f"exp-a-clean-{i:03d}" for i in range(sessions_per_condition)]
    all_clean_tuples = []
    for sid in clean_sessions:
        events = generate_session_events(sid, count=events_per_session)
        for ev in events:
            all_clean_tuples.append((ev['session_id'], ev['timestamp'], ev['event_type'], ev['serialized'], ev['sensitive'], ev['prev_hash'], ev['hash']))

    # Batch insert clean sessions
    insert_sql = f"""
import sqlite3
conn = sqlite3.connect('/data/audit.db')
cursor = conn.cursor()
events = {repr(all_clean_tuples)}
cursor.executemany("INSERT INTO audit_log(session_id, timestamp, event_type, payload, sensitive_action_flag, prev_hash, hash) VALUES(?,?,?,?,?,?,?)", events)
conn.commit()
conn.close()
print("Clean sessions inserted: " + str(len(events)))
"""
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(insert_sql), text=True, check=True)

    # Verify clean sessions
    clean_false_positives = 0
    clean_latencies = []
    for sid in clean_sessions:
        t0 = time.perf_counter_ns()
        url = f"{reconstruction_url}/api/session/{sid}/verify"
        with urllib.request.urlopen(url) as resp:
            data = json.loads(resp.read().decode())
        t_elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        clean_latencies.append(t_elapsed_ms)

        intact = data.get("chain_intact", False)
        broken = data.get("broken_entry_ids", [])
        if not intact or len(broken) > 0:
            clean_false_positives += 1

        all_sessions_data.append({
            "session_id": sid,
            "condition": "Clean_Control",
            "events_count": events_per_session,
            "mutations_count": 0,
            "expected_broken_seqs": "",
            "expected_broken_ids": "",
            "detected": not intact,
            "first_broken_seq": data.get("firstBroken"),
            "first_broken_match": True,
            "reported_broken_ids": str(broken),
            "exact_localization_match": (len(broken) == 0),
            "reconstruction_duration_ms": data.get("durationMs", 0.0),
            "http_roundtrip_ms": t_elapsed_ms,
            "error_reasons": "; ".join([e.get("reason", "") for e in data.get("errors", [])])
        })

    print(f"Clean Control False Positives: {clean_false_positives}/{sessions_per_condition}")

    # 3. Generate base events for all mutation conditions
    condition_sessions = {}
    all_tamper_tuples = []
    for cond in conditions:
        sids = [f"exp-a-{cond}-{i:03d}" for i in range(sessions_per_condition)]
        condition_sessions[cond] = sids
        for sid in sids:
            events = generate_session_events(sid, count=events_per_session)
            for ev in events:
                all_tamper_tuples.append((ev['session_id'], ev['timestamp'], ev['event_type'], ev['serialized'], ev['sensitive'], ev['prev_hash'], ev['hash']))

    # Batch insert tamper base sessions
    chunk_size = 2000
    for chunk_idx in range(0, len(all_tamper_tuples), chunk_size):
        chunk = all_tamper_tuples[chunk_idx:chunk_idx + chunk_size]
        ins_sql = f"""
import sqlite3
conn = sqlite3.connect('/data/audit.db')
cursor = conn.cursor()
events = {repr(chunk)}
cursor.executemany("INSERT INTO audit_log(session_id, timestamp, event_type, payload, sensitive_action_flag, prev_hash, hash) VALUES(?,?,?,?,?,?,?)", events)
conn.commit()
conn.close()
"""
        subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(ins_sql), text=True, check=True)

    # 4. Fetch database IDs for all inserted sessions to prepare precise mutations
    query_sql = """
import sqlite3, json
conn = sqlite3.connect('/data/audit.db')
cursor = conn.cursor()
rows = cursor.execute("SELECT id, session_id FROM audit_log WHERE session_id LIKE 'exp-a-%' AND session_id NOT LIKE 'exp-a-clean-%' ORDER BY id").fetchall()
conn.close()
mapping = {}
for r in rows:
    mapping.setdefault(r[1], []).append(r[0])
print(json.dumps(mapping))
"""
    proc = subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(query_sql), text=True, capture_output=True, check=True)
    id_mapping = json.loads(proc.stdout.strip())

    # 5. Apply mutations according to each condition
    # Updates will be collected: (sql_stmt, params)
    mutation_plans = {} # sid -> {"expected_seqs": [...], "expected_ids": [...]}
    sql_updates = []

    for cond in conditions:
        for sid in condition_sessions[cond]:
            row_ids = id_mapping[sid] # 20 database IDs
            if cond == "A1_two_payload":
                # 2 random non-overlapping positions
                pos = sorted(rng.sample(range(1, events_per_session + 1), 2))
                target_ids = [row_ids[p - 1] for p in pos]
                for p, tid in zip(pos, target_ids):
                    payload = {"step": p, "tampered": True, "mutation": "A1_two_payload_tamper",
                               "_aegis": {"schema_version": 1, "session_id": sid, "event_type": EVENT_TYPES[(p - 1) % 4], "sensitive_action_flag": (p % 7 == 0)}}
                    sql_updates.append(("UPDATE audit_log SET payload = ? WHERE id = ?", (canonical_json(payload), tid)))
                mutation_plans[sid] = {"expected_seqs": pos, "expected_ids": target_ids}

            elif cond == "A2_five_payload":
                # 5 random non-overlapping positions
                pos = sorted(rng.sample(range(1, events_per_session + 1), 5))
                target_ids = [row_ids[p - 1] for p in pos]
                for p, tid in zip(pos, target_ids):
                    payload = {"step": p, "tampered": True, "mutation": "A2_five_payload_tamper",
                               "_aegis": {"schema_version": 1, "session_id": sid, "event_type": EVENT_TYPES[(p - 1) % 4], "sensitive_action_flag": (p % 7 == 0)}}
                    sql_updates.append(("UPDATE audit_log SET payload = ? WHERE id = ?", (canonical_json(payload), tid)))
                mutation_plans[sid] = {"expected_seqs": pos, "expected_ids": target_ids}

            elif cond == "A3_payload_plus_timestamp":
                # 1 payload mutation at p1, 1 timestamp mutation at p2
                p1, p2 = rng.sample(range(1, events_per_session + 1), 2)
                t1, t2 = row_ids[p1 - 1], row_ids[p2 - 1]
                # payload mutation on t1
                payload = {"step": p1, "tampered": True, "mutation": "A3_payload",
                           "_aegis": {"schema_version": 1, "session_id": sid, "event_type": EVENT_TYPES[(p1 - 1) % 4], "sensitive_action_flag": (p1 % 7 == 0)}}
                sql_updates.append(("UPDATE audit_log SET payload = ? WHERE id = ?", (canonical_json(payload), t1)))
                # timestamp mutation on t2 (offset by 999.0 seconds)
                sql_updates.append(("UPDATE audit_log SET timestamp = timestamp + 999.0 WHERE id = ?", (t2,)))
                expected_seqs = sorted([p1, p2])
                expected_ids = [row_ids[p - 1] for p in expected_seqs]
                mutation_plans[sid] = {"expected_seqs": expected_seqs, "expected_ids": expected_ids}

            elif cond == "A4_payload_plus_metadata":
                # 1 payload mutation at p1, 1 metadata mismatch at p2
                p1, p2 = rng.sample(range(1, events_per_session + 1), 2)
                t1, t2 = row_ids[p1 - 1], row_ids[p2 - 1]
                # payload mutation on t1
                payload = {"step": p1, "tampered": True, "mutation": "A4_payload",
                           "_aegis": {"schema_version": 1, "session_id": sid, "event_type": EVENT_TYPES[(p1 - 1) % 4], "sensitive_action_flag": (p1 % 7 == 0)}}
                sql_updates.append(("UPDATE audit_log SET payload = ? WHERE id = ?", (canonical_json(payload), t1)))
                # metadata mutation on t2: flip sensitive_action_flag in column without touching payload envelope
                sql_updates.append(("UPDATE audit_log SET sensitive_action_flag = 1 - sensitive_action_flag WHERE id = ?", (t2,)))
                expected_seqs = sorted([p1, p2])
                expected_ids = [row_ids[p - 1] for p in expected_seqs]
                mutation_plans[sid] = {"expected_seqs": expected_seqs, "expected_ids": expected_ids}

            elif cond == "A5_adjacent_mutations":
                # 2 adjacent positions: start_p and start_p + 1
                start_p = rng.randint(1, events_per_session - 1)
                pos = [start_p, start_p + 1]
                target_ids = [row_ids[p - 1] for p in pos]
                for p, tid in zip(pos, target_ids):
                    payload = {"step": p, "tampered": True, "mutation": "A5_adjacent",
                               "_aegis": {"schema_version": 1, "session_id": sid, "event_type": EVENT_TYPES[(p - 1) % 4], "sensitive_action_flag": (p % 7 == 0)}}
                    sql_updates.append(("UPDATE audit_log SET payload = ? WHERE id = ?", (canonical_json(payload), tid)))
                mutation_plans[sid] = {"expected_seqs": pos, "expected_ids": target_ids}

            elif cond == "A6_non_adjacent_mutations":
                # 2 non-adjacent positions: p1 and p2 with |p1 - p2| >= 3
                while True:
                    p1, p2 = sorted(rng.sample(range(1, events_per_session + 1), 2))
                    if p2 - p1 >= 3:
                        break
                pos = [p1, p2]
                target_ids = [row_ids[p - 1] for p in pos]
                for p, tid in zip(pos, target_ids):
                    payload = {"step": p, "tampered": True, "mutation": "A6_non_adjacent",
                               "_aegis": {"schema_version": 1, "session_id": sid, "event_type": EVENT_TYPES[(p - 1) % 4], "sensitive_action_flag": (p % 7 == 0)}}
                    sql_updates.append(("UPDATE audit_log SET payload = ? WHERE id = ?", (canonical_json(payload), tid)))
                mutation_plans[sid] = {"expected_seqs": pos, "expected_ids": target_ids}

    # Execute all mutation updates in audit_service SQLite
    execute_mutations_sql = f"""
import sqlite3
conn = sqlite3.connect('/data/audit.db')
cursor = conn.cursor()
updates = {repr(sql_updates)}
for stmt, params in updates:
    cursor.execute(stmt, params)
conn.commit()
conn.close()
print("Mutations applied: " + str(len(updates)))
"""
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(execute_mutations_sql), text=True, check=True)

    # 6. Verify all tampered sessions and record results
    condition_results = {}

    for cond in conditions:
        print(f"\nVerifying Condition {cond} ({sessions_per_condition} sessions)...")
        detected_count = 0
        all_broken_matched_count = 0
        first_broken_matched_count = 0
        latencies = []

        for sid in condition_sessions[cond]:
            expected_seqs = mutation_plans[sid]["expected_seqs"]
            expected_ids = mutation_plans[sid]["expected_ids"]

            t0 = time.perf_counter_ns()
            url = f"{reconstruction_url}/api/session/{sid}/verify"
            with urllib.request.urlopen(url) as resp:
                data = json.loads(resp.read().decode())
            t_elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
            latencies.append(t_elapsed_ms)

            intact = data.get("chain_intact", True)
            reported_broken_ids = data.get("broken_entry_ids", [])
            first_broken_seq = data.get("firstBroken")
            expected_first_seq = min(expected_seqs)

            if not intact:
                detected_count += 1

            first_match = (first_broken_seq == expected_first_seq)
            if first_match:
                first_broken_matched_count += 1

            # Exact match: does broken_entry_ids exactly equal the set of expected mutated IDs?
            exact_match = (set(reported_broken_ids) == set(expected_ids))
            if exact_match:
                all_broken_matched_count += 1

            reasons = [e.get("reason", "") for e in data.get("errors", [])]

            all_sessions_data.append({
                "session_id": sid,
                "condition": cond,
                "events_count": events_per_session,
                "mutations_count": len(expected_ids),
                "expected_broken_seqs": ";".join(map(str, expected_seqs)),
                "expected_broken_ids": ";".join(map(str, expected_ids)),
                "detected": not intact,
                "first_broken_seq": first_broken_seq,
                "first_broken_match": first_match,
                "reported_broken_ids": ";".join(map(str, reported_broken_ids)),
                "exact_localization_match": exact_match,
                "reconstruction_duration_ms": data.get("durationMs", 0.0),
                "http_roundtrip_ms": t_elapsed_ms,
                "error_reasons": "; ".join(reasons)
            })

        condition_results[cond] = {
            "total_sessions": sessions_per_condition,
            "detected_count": detected_count,
            "detection_rate": detected_count / sessions_per_condition,
            "first_broken_matched_count": first_broken_matched_count,
            "first_broken_match_rate": first_broken_matched_count / sessions_per_condition,
            "all_broken_matched_count": all_broken_matched_count,
            "all_broken_match_rate": all_broken_matched_count / sessions_per_condition,
            "latency_p50": sorted(latencies)[int(len(latencies) * 0.5)],
            "latency_p95": sorted(latencies)[min(int(len(latencies) * 0.95), len(latencies) - 1)],
            "latency_mean": sum(latencies) / len(latencies)
        }
        print(f"Condition {cond}: Detected {detected_count}/{sessions_per_condition}, FirstBroken Match {first_broken_matched_count}/{sessions_per_condition}, AllBroken Match {all_broken_matched_count}/{sessions_per_condition}")

    # Export raw CSV
    csv_file = "evaluation_results/exp_a_multi_tamper.csv"
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(all_sessions_data[0].keys()))
        writer.writeheader()
        writer.writerows(all_sessions_data)
    print(f"\nSaved CSV report to {csv_file}")

    # Clean up test sessions from database
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(cleanup_sql), text=True, check=True)

    summary_output = {
        "random_seed": seed,
        "clean_control": {
            "total_sessions": sessions_per_condition,
            "false_positives": clean_false_positives,
            "false_positive_rate": clean_false_positives / sessions_per_condition,
            "latency_p50": sorted(clean_latencies)[int(len(clean_latencies) * 0.5)],
            "latency_p95": sorted(clean_latencies)[min(int(len(clean_latencies) * 0.95), len(clean_latencies) - 1)],
            "latency_mean": sum(clean_latencies) / len(clean_latencies)
        },
        "mutation_conditions": condition_results
    }
    return summary_output

if __name__ == "__main__":
    results = run_experiment_a()
    with open("evaluation_results/exp_a_summary.json", "w") as f:
        json.dump(results, f, indent=2)
