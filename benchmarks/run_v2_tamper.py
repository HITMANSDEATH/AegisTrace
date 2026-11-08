"""V2 Tamper Detection Benchmark for Seed 1337.
Evaluates:
- 210 sessions for original Part A: 30 Clean + 180 Tampered (30 per 6 original classes: A1-A6)
- New / extended classes with v2 envelopes and anchors:
  - mid-chain row deletion (10 sessions)
  - duplicate row (10 sessions)
  - reordered rows (10 sessions)
  - suffix truncation N=1 (10 sessions)
  - suffix truncation N=5 (10 sessions)
  - suffix truncation N=9 (10 sessions)
  - suffix truncation N=10 (10 sessions)
  - suffix truncation N=15 (10 sessions)
All events are generated with schema_version: 2 and client_seq.
Anchors are written to /anchor_data/anchors.jsonl at intervals of ANCHOR_EVERY=10.
Records detection per class both with and without anchor.
Saves to results/raw_v2/e1_tamper_v2.csv and results/raw_v2/e1_tamper_summary.json.
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

from benchmarks.eval_common import reset_ledger_and_restart_services

def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)

def entry_hash(timestamp, payload_str, prev_hash):
    return hashlib.sha256((str(float(timestamp)) + payload_str + prev_hash).encode("utf-8")).hexdigest()

def anchor_hash(session_id, count, head_hash, last_client_seq, ts, prev_anchor_hash):
    preimage = f"{session_id}|{count}|{head_hash}|{last_client_seq}|{float(ts):.6f}|{prev_anchor_hash}"
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()

EVENT_TYPES = ['state_transition', 'tool_start', 'retrieval', 'tool_end']

def generate_v2_session_events(session_id, count=20, base_time=1710000000.0):
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
                "schema_version": 2,
                "session_id": session_id,
                "event_type": event_type,
                "sensitive_action_flag": sensitive,
                "client_seq": i
            }
        }
        ser = canonical_json(payload)
        h = entry_hash(ts, ser, prev_hash)
        events.append({
            "session_id": session_id,
            "seq": i,
            "client_seq": i,
            "timestamp": ts,
            "event_type": event_type,
            "sensitive": int(sensitive),
            "payload": payload,
            "serialized": ser,
            "prev_hash": prev_hash,
            "hash": h
        })
        prev_hash = h
    return events

ORIGINAL_CONDITIONS = [
    "A1_single_event_payload",
    "A2_timestamp_modification",
    "A3_prev_hash_modification",
    "A4_envelope_tamper_session",
    "A5_envelope_tamper_event_type",
    "A6_envelope_tamper_flag"
]

NEW_CLASSES = [
    "mid_chain_row_deletion",
    "duplicate_row",
    "reordered_rows",
    "suffix_truncation_N1",
    "suffix_truncation_N5",
    "suffix_truncation_N9",
    "suffix_truncation_N10",
    "suffix_truncation_N15"
]

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

def run_v2_tamper_suite():
    require_destructive("http://127.0.0.1:8002", docker=True)
    os.makedirs("results/raw_v2", exist_ok=True)
    os.makedirs("results/logs_v2", exist_ok=True)
    log_file = open("results/logs_v2/e1_tamper_v2.log", "w", encoding="utf-8")

    def log(msg):
        print(msg)
        log_file.write(msg + "\n")
        log_file.flush()

    log("=== Starting V2 Tamper Detection Benchmark (Seed 1337) ===")
    reset_ledger_and_restart_services()

    reconstruction_url = "http://127.0.0.1:8002"
    require_destructive(reconstruction_url)
    seed = 1337
    rng = random.Random(seed)

    # 1. Generate Part A: 30 clean + 180 tampered (30 per class A1-A6) = 210 sessions
    clean_sids = [f"v2-s{seed}-clean-{i:03d}" for i in range(30)]
    all_tuples = []
    all_events_by_sid = {}

    for sid in clean_sids:
        evs = generate_v2_session_events(sid, count=20)
        all_events_by_sid[sid] = evs
        for ev in evs:
            all_tuples.append((ev['session_id'], ev['timestamp'], ev['event_type'], ev['serialized'], ev['sensitive'], ev['prev_hash'], ev['hash']))

    orig_sessions = {}
    for cond in ORIGINAL_CONDITIONS:
        sids = [f"v2-s{seed}-{cond}-{i:03d}" for i in range(30)]
        orig_sessions[cond] = sids
        for sid in sids:
            evs = generate_v2_session_events(sid, count=20)
            all_events_by_sid[sid] = evs
            for ev in evs:
                all_tuples.append((ev['session_id'], ev['timestamp'], ev['event_type'], ev['serialized'], ev['sensitive'], ev['prev_hash'], ev['hash']))

    # 2. Generate New Classes: 10 sessions each
    new_sessions = {}
    for cond in NEW_CLASSES:
        sids = [f"v2-s{seed}-{cond}-{i:03d}" for i in range(10)]
        new_sessions[cond] = sids
        for sid in sids:
            evs = generate_v2_session_events(sid, count=20)
            all_events_by_sid[sid] = evs
            for ev in evs:
                all_tuples.append((ev['session_id'], ev['timestamp'], ev['event_type'], ev['serialized'], ev['sensitive'], ev['prev_hash'], ev['hash']))

    # 3. Create Anchors at count=10 and count=20 for every session
    # We construct a valid anchor chain in the anchor service
    anchor_lines = []
    prev_a_hash = '0' * 64
    base_anchor_ts = 1710001000.0
    a_idx = 0

    all_all_sids = clean_sids + [sid for c in ORIGINAL_CONDITIONS for sid in orig_sessions[c]] + [sid for c in NEW_CLASSES for sid in new_sessions[c]]

    for sid in all_all_sids:
        evs = all_events_by_sid[sid]
        # Anchor 1 at count=10
        ev10 = evs[9]
        ts10 = base_anchor_ts + a_idx * 0.1
        a_idx += 1
        ah10 = anchor_hash(sid, 10, ev10['hash'], 10, ts10, prev_a_hash)
        rec10 = {
            "session_id": sid,
            "count": 10,
            "head_hash": ev10['hash'],
            "last_client_seq": 10,
            "ts": ts10,
            "prev_anchor_hash": prev_a_hash,
            "anchor_hash": ah10
        }
        anchor_lines.append(json.dumps(rec10))
        prev_a_hash = ah10

        # Anchor 2 at count=20
        ev20 = evs[19]
        ts20 = base_anchor_ts + a_idx * 0.1
        a_idx += 1
        ah20 = anchor_hash(sid, 20, ev20['hash'], 20, ts20, prev_a_hash)
        rec20 = {
            "session_id": sid,
            "count": 20,
            "head_hash": ev20['hash'],
            "last_client_seq": 20,
            "ts": ts20,
            "prev_anchor_hash": prev_a_hash,
            "anchor_hash": ah20
        }
        anchor_lines.append(json.dumps(rec20))
        prev_a_hash = ah20

    # Write anchor log inside anchor_service container
    anchor_log_content = "\n".join(anchor_lines) + "\n"
    proc = subprocess.run(
        ["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-anchor_service-1", "python", "-c",
         guarded_python("import sys; f=open('/anchor_data/anchors.jsonl', 'w'); f.write(sys.stdin.read()); f.close(); print('anchors written')")],
        input=anchor_log_content, text=True, capture_output=True, check=True
    )
    log(f"Wrote {len(anchor_lines)} anchor records: {proc.stdout.strip()}")

    # Insert all event rows into audit.db
    insert_sql = f"""
import sqlite3
conn = sqlite3.connect('/data/audit.db', isolation_level=None)
cur = conn.cursor()
cur.execute('BEGIN IMMEDIATE')
cur.executemany("INSERT INTO audit_log(session_id, timestamp, event_type, payload, sensitive_action_flag, prev_hash, hash) VALUES(?,?,?,?,?,?,?)", {repr(all_tuples)})
cur.execute('COMMIT')
conn.close()
"""
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(insert_sql), text=True, check=True)
    log(f"Inserted {len(all_tuples)} baseline rows into audit_log.")

    # Retrieve row IDs
    proc = subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"],
                          input=guarded_python("""
import sqlite3, json
conn = sqlite3.connect('/data/audit.db')
rows = conn.execute("SELECT id, session_id, timestamp, event_type, payload, sensitive_action_flag, prev_hash, hash FROM audit_log ORDER BY id").fetchall()
conn.close()
m = {}
for r in rows:
    m.setdefault(r[1], []).append({'id': r[0], 'ts': r[2], 'type': r[3], 'pld': r[4], 'flag': r[5], 'prev': r[6], 'hash': r[7]})
print(json.dumps(m))
"""), text=True, capture_output=True, check=True)
    all_db_rows = json.loads(proc.stdout.strip())

    # Build mutations
    mut_stmts = []
    mutation_meta = {}

    # Mutate Part A
    for cond in ORIGINAL_CONDITIONS:
        for sid in orig_sessions[cond]:
            rows = all_db_rows[sid]
            p = rng.randint(2, 19)
            target = rows[p - 1]
            tid = target['id']

            if cond == "A1_single_event_payload":
                pld = json.loads(target['pld'])
                pld['message'] = "Tampered message payload"
                mut_stmts.append(("UPDATE audit_log SET payload = ? WHERE id = ?", (canonical_json(pld), tid)))
            elif cond == "A2_timestamp_modification":
                mut_stmts.append(("UPDATE audit_log SET timestamp = ? WHERE id = ?", (target['ts'] + 10.0, tid)))
            elif cond == "A3_prev_hash_modification":
                mut_stmts.append(("UPDATE audit_log SET prev_hash = ? WHERE id = ?", ("b" * 64, tid)))
            elif cond == "A4_envelope_tamper_session":
                mut_stmts.append(("UPDATE audit_log SET session_id = ? WHERE id = ?", ("forged-sid-000", tid)))
            elif cond == "A5_envelope_tamper_event_type":
                alt = "retrieval" if target['type'] == "state_transition" else "state_transition"
                mut_stmts.append(("UPDATE audit_log SET event_type = ? WHERE id = ?", (alt, tid)))
            elif cond == "A6_envelope_tamper_flag":
                mut_stmts.append(("UPDATE audit_log SET sensitive_action_flag = ? WHERE id = ?", (1 - target['flag'], tid)))

            mutation_meta[sid] = {"pos": p, "target_id": tid}

    # Mutate New Classes
    trunc_map = {
        "suffix_truncation_N1": 1,
        "suffix_truncation_N5": 5,
        "suffix_truncation_N9": 9,
        "suffix_truncation_N10": 10,
        "suffix_truncation_N15": 15
    }

    for cond in NEW_CLASSES:
        for sid in new_sessions[cond]:
            rows = all_db_rows[sid]
            if cond == "mid_chain_row_deletion":
                p = rng.randint(2, 19)
                tid = rows[p - 1]['id']
                mut_stmts.append(("DELETE FROM audit_log WHERE id = ?", (tid,)))
                mutation_meta[sid] = {"pos": p, "target_id": tid}
            elif cond == "duplicate_row":
                p = rng.randint(2, 18)
                dup = rows[p - 1]
                mut_stmts.append(("INSERT INTO audit_log(session_id, timestamp, event_type, payload, sensitive_action_flag, prev_hash, hash) VALUES(?,?,?,?,?,?,?)",
                                  (sid, dup['ts'] + 0.001, dup['type'], dup['pld'], dup['flag'], dup['prev'], dup['hash'])))
                mutation_meta[sid] = {"pos": p, "target_id": dup['id']}
            elif cond == "reordered_rows":
                p = rng.randint(2, 18)
                r1 = rows[p - 1]
                r2 = rows[p]
                mut_stmts.append(("UPDATE audit_log SET timestamp = ?, payload = ?, sensitive_action_flag = ? WHERE id = ?", (r2['ts'], r2['pld'], r2['flag'], r1['id'])))
                mut_stmts.append(("UPDATE audit_log SET timestamp = ?, payload = ?, sensitive_action_flag = ? WHERE id = ?", (r1['ts'], r1['pld'], r1['flag'], r2['id'])))
                mutation_meta[sid] = {"pos": p, "target_id": r1['id']}
            elif cond in trunc_map:
                n = trunc_map[cond]
                # Delete last N rows
                del_ids = [rows[idx]['id'] for idx in range(20 - n, 20)]
                for did in del_ids:
                    mut_stmts.append(("DELETE FROM audit_log WHERE id = ?", (did,)))
                mutation_meta[sid] = {"trunc_n": n, "target_ids": del_ids}

    # Execute mutations
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
    log(f"Applied {len(mut_stmts)} mutations across Part A and new classes.")

    # 4. Verification and Evaluation
    results_records = []
    class_stats = {}

    all_test_sessions = [("Clean_Control", sid) for sid in clean_sids]
    for cond in ORIGINAL_CONDITIONS:
        for sid in orig_sessions[cond]:
            all_test_sessions.append((cond, sid))
    for cond in NEW_CLASSES:
        for sid in new_sessions[cond]:
            all_test_sessions.append((cond, sid))

    for cond, sid in all_test_sessions:
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

        # Detection without anchor: internal hash chain broken OR sequence broken
        detected_without_anchor = (not chain_intact) or (not seq_complete)
        # Detection with anchor: either detected without anchor OR anchor_status != 'verified'
        detected_with_anchor = detected_without_anchor or (anchor_status != 'verified')

        rec = {
            "session_id": sid,
            "condition": cond,
            "chain_intact": chain_intact,
            "sequence_complete": seq_complete,
            "anchor_status": anchor_status,
            "detected_without_anchor": detected_without_anchor,
            "detected_with_anchor": detected_with_anchor,
            "checks_fired": ";".join(checks_fired),
            "missing_events_total": v.get("missing_events_total", 0),
            "duplicate_seq": ";".join(map(str, v.get("duplicate_seq", []))),
            "out_of_order_seq": ";".join(map(str, v.get("out_of_order_seq", []))),
            "unanchored_tail_events": v.get("unanchored_tail_events", 0)
        }
        results_records.append(rec)

        if cond not in class_stats:
            class_stats[cond] = {"total": 0, "detected_without_anchor": 0, "detected_with_anchor": 0}
        class_stats[cond]["total"] += 1
        if detected_without_anchor:
            class_stats[cond]["detected_without_anchor"] += 1
        if detected_with_anchor:
            class_stats[cond]["detected_with_anchor"] += 1

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

    log("\n================ RESULTS SUMMARY ================")
    log(f"{'Condition':<32} {'Total':<8} {'No Anchor Det':<16} {'With Anchor Det':<16}")
    log("-" * 75)
    for cond, st in class_stats.items():
        log(f"{cond:<32} {st['total']:<8} {st['detected_without_anchor']:<16} {st['detected_with_anchor']:<16}")

    log(f"\nRaw CSV saved to {csv_path}")
    log(f"Summary JSON saved to {summary_path}")

if __name__ == "__main__":
    run_v2_tamper_suite()
