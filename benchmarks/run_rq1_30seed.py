"""RQ1 Tamper, Truncation, and Rewrite Detection Evaluation Over 30 Seeds.
Evaluates on the CURRENT AegisTrace code (schema_version 2, client_seq, anchor_service, ANCHOR_EVERY=10).

Reproduces Table II composition across 30 seeds (seed 1337 + 2001..2029):
Total per seed: 350 sessions x 25 events = 8,750 events.
30 seeds x 350 sessions = 10,500 sessions (262,500 total events).

All events ingested LIVE through audit_service /ingest.
Outputs saved to results/raw_v2/rq1_30seed/.
"""

try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import argparse
import concurrent.futures
import csv
import hashlib
import json
import math
import os
import random
import subprocess
import sys
import time
import urllib.request
from typing import Any, Dict, List, Tuple

EVENT_TYPES = ['state_transition', 'tool_start', 'retrieval', 'tool_end']

ORIGINAL_EDIT_CLASSES = [
    "A1_single_event_payload",
    "A2_timestamp_modification",
    "A3_prev_hash_modification",
    "A4_envelope_tamper_session",
    "A5_envelope_tamper_event_type",
    "A6_envelope_tamper_flag"
]

STRUCTURAL_CLASSES = [
    "mid_chain_row_deletion",
    "duplicate_row",
    "reordered_rows"
]

TRUNC_DEPTHS = [1, 2, 3, 4, 5, 6, 7, 10, 15]
TRUNC_CLASSES = [f"suffix_truncation_N{d}" for d in TRUNC_DEPTHS]

def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)

def entry_hash(timestamp, payload_str, prev_hash):
    return hashlib.sha256((str(float(timestamp)) + payload_str + prev_hash).encode("utf-8")).hexdigest()

def wilson_interval(k: int, n: int, confidence: float = 0.95) -> Tuple[float, float]:
    """Calculate the Wilson score confidence interval for a binomial proportion."""
    if n == 0:
        return (0.0, 0.0)
    z = 1.959963984540054  # 95%
    p = k / n
    denom = 1 + (z ** 2) / n
    center = (p + (z ** 2) / (2 * n)) / denom
    spread = (z * math.sqrt((p * (1 - p)) / n + (z ** 2) / (4 * n ** 2))) / denom
    lower = max(0.0, center - spread)
    upper = min(1.0, center + spread)
    return (round(lower * 100, 2), round(upper * 100, 2))

def reset_ledger_and_restart():
    """Reset SQLite DB and anchor log, restart containers, wait for health."""
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    sql = """
import sqlite3
conn = sqlite3.connect('/data/audit.db', isolation_level=None)
conn.execute('DELETE FROM audit_log')
conn.execute('VACUUM')
conn.close()
"""
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(sql), text=True, check=True)
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "aegistrace-anchor_service-1", "python", "-c",
                    guarded_python("open('/anchor_data/anchors.jsonl', 'w').close()")], check=True)
    subprocess.run(
        ["docker", "restart", "aegistrace-audit_service-1", "aegistrace-reconstruction_service-1", "aegistrace-agent_service-1"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    for _ in range(40):
        try:
            req = urllib.request.Request("http://127.0.0.1:8002/health")
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    break
        except Exception:
            time.sleep(0.5)
    else:
        raise RuntimeError("Reconstruction service failed to become healthy after restart")

def run_seed(seed: int, log_fn) -> List[Dict[str, Any]]:
    """Runs 350 sessions for a given seed and returns records."""
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    t0_seed = time.perf_counter()
    rng = random.Random(seed)
    
    # Session composition: 350 sessions total
    # Clean: 30
    clean_sids = [f"rq1s{seed}-clean-{i:03d}" for i in range(30)]
    # Six edit classes: 6 x 30 = 180
    edit_sids = {cond: [f"rq1s{seed}-{cond}-{i:03d}" for i in range(30)] for cond in ORIGINAL_EDIT_CLASSES}
    # Structural: 3 x 10 = 30
    struct_sids = {cond: [f"rq1s{seed}-{cond}-{i:03d}" for i in range(10)] for cond in STRUCTURAL_CLASSES}
    # Truncation: 9 x 10 = 90
    trunc_sids = {cond: [f"rq1s{seed}-{cond}-{i:03d}" for i in range(10)] for cond in TRUNC_CLASSES}
    # Full history rewrite: 10
    fhr_sids = [f"rq1s{seed}-full_history_rewrite-{i:03d}" for i in range(10)]
    # Tail rewrite: 10
    tr_sids = [f"rq1s{seed}-tail_rewrite-{i:03d}" for i in range(10)]

    all_sessions_plan = []
    for sid in clean_sids:
        all_sessions_plan.append(("Clean_Control", sid))
    for cond in ORIGINAL_EDIT_CLASSES:
        for sid in edit_sids[cond]:
            all_sessions_plan.append((cond, sid))
    for cond in STRUCTURAL_CLASSES:
        for sid in struct_sids[cond]:
            all_sessions_plan.append((cond, sid))
    for cond in TRUNC_CLASSES:
        for sid in trunc_sids[cond]:
            all_sessions_plan.append((cond, sid))
    for sid in fhr_sids:
        all_sessions_plan.append(("full_history_rewrite", sid))
    for sid in tr_sids:
        all_sessions_plan.append(("tail_rewrite", sid))

    assert len(all_sessions_plan) == 350, f"Expected 350 sessions, got {len(all_sessions_plan)}"

    # 1. Reset state
    reset_ledger_and_restart()

    # 2. Ingest 350 sessions (8,750 events) concurrently inside agent container
    session_id_list = [item[1] for item in all_sessions_plan]
    ingest_script = f"""
import concurrent.futures, json, time, os, httpx

EVENT_TYPES = ['state_transition', 'tool_start', 'retrieval', 'tool_end']
audit_url = "http://audit_service:8001/ingest"
require_destructive(audit_url)
token = require_token()
headers = {{"Authorization": f"Bearer {{token}}", "Content-Type": "application/json"}}
sessions = {repr(session_id_list)}

def ingest_session(sid):
    client = httpx.Client(timeout=20.0, trust_env=False)
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
            raise RuntimeError(f"Ingest failed for {{sid}} seq {{i}}: status {{resp.status_code}} {{resp.text}}")
    client.close()
    return sid

t0 = time.perf_counter()
with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
    done = list(ex.map(ingest_session, sessions))
dur = time.perf_counter() - t0
print(f"INGESTED: {{len(done)}} sessions in {{dur:.2f}}s ({{len(done)*25/dur:.1f}} eps)")
"""
    proc = subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-agent_service-1", "python", "-"],
                          input=guarded_python(ingest_script), text=True, capture_output=True, check=True)
    ingest_stat_line = proc.stdout.strip().splitlines()[-1]

    # Wait for anchor dispatch threads
    time.sleep(1.0)

    # 3. Retrieve row data from SQLite
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
    proc_q = subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"],
                            input=guarded_python(query_sql), text=True, capture_output=True, check=True)
    all_db_rows = json.loads(proc_q.stdout.strip())

    # 4. Plan and apply mutations
    mut_stmts = []
    metadata_tracking = {}  # sid -> {"mutated_row": ..., "depth": ...}

    # A. Clean: no modification
    for sid in clean_sids:
        metadata_tracking[sid] = {"mutated_row": "none"}

    # B. Six edit classes (180 sessions)
    for cond in ORIGINAL_EDIT_CLASSES:
        for sid in edit_sids[cond]:
            rows = all_db_rows[sid]
            p = rng.randint(2, 24)  # position 2..24
            target = rows[p - 1]
            tid = target['id']
            metadata_tracking[sid] = {"mutated_row": p}

            if cond == "A1_single_event_payload":
                pld = json.loads(target['pld'])
                pld['message'] = f"Tampered message payload seed {seed}"
                mut_stmts.append(("UPDATE audit_log SET payload = ? WHERE id = ?", (canonical_json(pld), tid)))
            elif cond == "A2_timestamp_modification":
                mut_stmts.append(("UPDATE audit_log SET timestamp = ? WHERE id = ?", (target['ts'] + 10.0, tid)))
            elif cond == "A3_prev_hash_modification":
                mut_stmts.append(("UPDATE audit_log SET prev_hash = ? WHERE id = ?", ("c" * 64, tid)))
            elif cond == "A4_envelope_tamper_session":
                mut_stmts.append(("UPDATE audit_log SET session_id = ? WHERE id = ?", (f"forged-sid-s{seed}", tid)))
            elif cond == "A5_envelope_tamper_event_type":
                alt = "retrieval" if target['type'] == "state_transition" else "state_transition"
                mut_stmts.append(("UPDATE audit_log SET event_type = ? WHERE id = ?", (alt, tid)))
            elif cond == "A6_envelope_tamper_flag":
                mut_stmts.append(("UPDATE audit_log SET sensitive_action_flag = ? WHERE id = ?", (1 - target['flag'], tid)))

    # C. Structural classes (30 sessions)
    for cond in STRUCTURAL_CLASSES:
        for sid in struct_sids[cond]:
            rows = all_db_rows[sid]
            if cond == "mid_chain_row_deletion":
                p = rng.randint(2, 24)
                metadata_tracking[sid] = {"mutated_row": p}
                tid = rows[p - 1]['id']
                mut_stmts.append(("DELETE FROM audit_log WHERE id = ?", (tid,)))
            elif cond == "duplicate_row":
                p = rng.randint(2, 23)
                metadata_tracking[sid] = {"mutated_row": p}
                dup = rows[p - 1]
                mut_stmts.append(("INSERT INTO audit_log(session_id, timestamp, event_type, payload, sensitive_action_flag, prev_hash, hash) VALUES(?,?,?,?,?,?,?)",
                                  (sid, dup['ts'] + 0.001, dup['type'], dup['pld'], dup['flag'], dup['prev'], dup['hash'])))
            elif cond == "reordered_rows":
                p = rng.randint(2, 23)
                metadata_tracking[sid] = {"mutated_row": f"{p},{p+1}"}
                r1 = rows[p - 1]
                r2 = rows[p]
                mut_stmts.append(("UPDATE audit_log SET timestamp = ?, payload = ?, sensitive_action_flag = ? WHERE id = ?", (r2['ts'], r2['pld'], r2['flag'], r1['id'])))
                mut_stmts.append(("UPDATE audit_log SET timestamp = ?, payload = ?, sensitive_action_flag = ? WHERE id = ?", (r1['ts'], r1['pld'], r1['flag'], r2['id'])))

    # D. Suffix truncation (90 sessions)
    for depth in TRUNC_DEPTHS:
        cond_name = f"suffix_truncation_N{depth}"
        for sid in trunc_sids[cond_name]:
            rows = all_db_rows[sid]
            metadata_tracking[sid] = {"mutated_row": depth}
            del_ids = [rows[idx]['id'] for idx in range(25 - depth, 25)]
            for did in del_ids:
                mut_stmts.append(("DELETE FROM audit_log WHERE id = ?", (did,)))

    # E. Full-history rewrite (10 sessions, rows 2..14 altered, valid recomputed hashes)
    for sid in fhr_sids:
        rows = all_db_rows[sid]
        p = rng.randint(2, 14)  # strictly rows 2..14
        metadata_tracking[sid] = {"mutated_row": p}
        curr_prev = rows[p - 2]['hash']
        for idx in range(p - 1, 25):
            r = rows[idx]
            if idx == p - 1:
                pld = json.loads(r['pld'])
                pld['rewritten'] = f"full_history_rewrite_s{seed}"
                ser = canonical_json(pld)
            else:
                ser = r['pld']
            h = entry_hash(r['ts'], ser, curr_prev)
            mut_stmts.append(("UPDATE audit_log SET payload = ?, prev_hash = ?, hash = ? WHERE id = ?", (ser, curr_prev, h, r['id'])))
            curr_prev = h

    # F. Tail rewrite (10 sessions, rows 21..25 altered, valid recomputed hashes)
    for sid in tr_sids:
        rows = all_db_rows[sid]
        p = rng.randint(21, 23)  # strictly rows 21..23
        metadata_tracking[sid] = {"mutated_row": p}
        curr_prev = rows[p - 2]['hash']
        for idx in range(p - 1, 25):
            r = rows[idx]
            if idx == p - 1:
                pld = json.loads(r['pld'])
                pld['rewritten'] = f"tail_rewrite_s{seed}"
                ser = canonical_json(pld)
            else:
                ser = r['pld']
            h = entry_hash(r['ts'], ser, curr_prev)
            mut_stmts.append(("UPDATE audit_log SET payload = ?, prev_hash = ?, hash = ? WHERE id = ?", (ser, curr_prev, h, r['id'])))
            curr_prev = h

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
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"],
                   input=guarded_python(apply_sql), text=True, check=True)

    # 5. Query verifier for all 350 sessions
    reconstruction_url = "http://127.0.0.1:8002"
    require_destructive(reconstruction_url)
    records = []

    for cond, sid in all_sessions_plan:
        url = f"{reconstruction_url}/api/session/{sid}/verify"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                v = json.loads(resp.read().decode())
        except Exception as e:
            v = {"chain_intact": False, "sequence_complete": False, "anchor_status": "error", "firstBroken": None, "errors": [{"reason": str(e)}]}

        chain_intact = v.get("chain_intact", False)
        seq_complete = v.get("sequence_complete", False)
        anchor_status = v.get("anchor_status", "no_anchor")
        first_broken = v.get("firstBroken")
        mutated_val = metadata_tracking[sid]["mutated_row"]

        # Definitions:
        # no_anchor_detected = chain_intact == False OR sequence_complete == False
        no_anchor_detected = (chain_intact is False) or (seq_complete is False)
        # with_anchor_detected = no_anchor_detected OR anchor check reports mismatch
        anchor_mismatch = (anchor_status not in ("verified", "no_anchor"))
        with_anchor_detected = no_anchor_detected or anchor_mismatch

        # Exact localization for single-row edit classes
        if cond in ORIGINAL_EDIT_CLASSES:
            localized_exactly = (first_broken == mutated_val)
        else:
            localized_exactly = "N/A"

        records.append({
            "seed": seed,
            "class": cond,
            "session_id": sid,
            "mutated_row": str(mutated_val),
            "no_anchor_detected": no_anchor_detected,
            "with_anchor_detected": with_anchor_detected,
            "chain_intact": chain_intact,
            "sequence_complete": seq_complete,
            "anchor_check_result": anchor_status,
            "first_broken_entry_id": first_broken if first_broken is not None else "none",
            "localized_exactly": localized_exactly
        })

    dur_seed = time.perf_counter() - t0_seed
    log_fn(f"Seed {seed} finished in {dur_seed:.1f}s ({ingest_stat_line})")
    return records, dur_seed

def check_seed_matches_sanity(records: List[Dict[str, Any]]) -> Tuple[bool, str]:
    """Verify if a seed matches the expected deterministic Table II pattern."""
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for r in records:
        groups.setdefault(r["class"], []).append(r)

    # 1. Clean controls: 30 sessions, 0/30 no anchor, 0/30 with anchor
    clean_no = sum(1 for r in groups["Clean_Control"] if r["no_anchor_detected"])
    clean_with = sum(1 for r in groups["Clean_Control"] if r["with_anchor_detected"])
    if clean_no != 0 or clean_with != 0:
        return False, f"Clean controls false positive: no_anchor={clean_no}/30, with_anchor={clean_with}/30"

    # 2. Six edit classes: 180 sessions, 180/180 no anchor, 180/180 with anchor
    for cond in ORIGINAL_EDIT_CLASSES:
        c_no = sum(1 for r in groups[cond] if r["no_anchor_detected"])
        c_with = sum(1 for r in groups[cond] if r["with_anchor_detected"])
        if c_no != 30 or c_with != 30:
            return False, f"Edit class {cond} failed: no_anchor={c_no}/30, with_anchor={c_with}/30"

    # 3. Structural classes: 30 sessions, 30/30 no anchor, 30/30 with anchor
    for cond in STRUCTURAL_CLASSES:
        s_no = sum(1 for r in groups[cond] if r["no_anchor_detected"])
        s_with = sum(1 for r in groups[cond] if r["with_anchor_detected"])
        if s_no != 10 or s_with != 10:
            return False, f"Structural class {cond} failed: no_anchor={s_no}/10, with_anchor={s_with}/10"

    # 4. Truncation 1 to 5: 50 sessions, 0/50 no anchor, 0/50 with anchor
    for d in [1, 2, 3, 4, 5]:
        cname = f"suffix_truncation_N{d}"
        t_no = sum(1 for r in groups[cname] if r["no_anchor_detected"])
        t_with = sum(1 for r in groups[cname] if r["with_anchor_detected"])
        if t_no != 0 or t_with != 0:
            return False, f"Truncation N={d} failed: no_anchor={t_no}/10, with_anchor={t_with}/10 (expected 0/10)"

    # 5. Truncation 6, 7, 10, 15: 40 sessions, 0/40 no anchor, 40/40 with anchor
    for d in [6, 7, 10, 15]:
        cname = f"suffix_truncation_N{d}"
        t_no = sum(1 for r in groups[cname] if r["no_anchor_detected"])
        t_with = sum(1 for r in groups[cname] if r["with_anchor_detected"])
        if t_no != 0 or t_with != 10:
            return False, f"Truncation N={d} failed: no_anchor={t_no}/10, with_anchor={t_with}/10 (expected 0/10, 10/10)"

    # 6. Full history rewrite (rows 2..14): 10 sessions, 0/10 no anchor, 10/10 with anchor
    fhr_no = sum(1 for r in groups["full_history_rewrite"] if r["no_anchor_detected"])
    fhr_with = sum(1 for r in groups["full_history_rewrite"] if r["with_anchor_detected"])
    if fhr_no != 0 or fhr_with != 10:
        return False, f"Full history rewrite failed: no_anchor={fhr_no}/10, with_anchor={fhr_with}/10"

    # 7. Tail rewrite (rows 21..25): 10 sessions, 0/10 no anchor, 0/10 with anchor
    tr_no = sum(1 for r in groups["tail_rewrite"] if r["no_anchor_detected"])
    tr_with = sum(1 for r in groups["tail_rewrite"] if r["with_anchor_detected"])
    if tr_no != 0 or tr_with != 0:
        return False, f"Tail rewrite failed: no_anchor={tr_no}/10, with_anchor={tr_with}/10 (expected 0/10)"

    return True, "All classes match deterministic Table II pattern exactly"

def aggregate_and_write_reports(all_records: List[Dict[str, Any]], output_dir: str, wall_time_s: float):
    """Generate summary_by_class.csv, summary_by_seed.csv, and print final report."""
    require_destructive()
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Write sessions.csv
    sessions_path = os.path.join(output_dir, "sessions.csv")
    fieldnames = [
        "seed", "class", "session_id", "mutated_row", "no_anchor_detected",
        "with_anchor_detected", "chain_intact", "sequence_complete",
        "anchor_check_result", "first_broken_entry_id", "localized_exactly"
    ]
    with open(sessions_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(all_records)
    print(f"\nWritten {len(all_records)} session records to {sessions_path}")

    # 2. summary_by_seed.csv
    seeds = sorted(list(dict.fromkeys(r["seed"] for r in all_records)))
    seed_summaries = []
    for s in seeds:
        s_recs = [r for r in all_records if r["seed"] == s]
        s_groups: Dict[str, List[Dict[str, Any]]] = {}
        for r in s_recs:
            s_groups.setdefault(r["class"], []).append(r)

        clean_fp = sum(1 for r in s_groups["Clean_Control"] if r["with_anchor_detected"])
        edit_det = sum(sum(1 for r in s_groups[c] if r["with_anchor_detected"]) for c in ORIGINAL_EDIT_CLASSES)
        struct_det = sum(sum(1 for r in s_groups[c] if r["with_anchor_detected"]) for c in STRUCTURAL_CLASSES)
        trunc_1_5_det = sum(sum(1 for r in s_groups[f"suffix_truncation_N{d}"] if r["with_anchor_detected"]) for d in [1, 2, 3, 4, 5])
        trunc_6_15_det = sum(sum(1 for r in s_groups[f"suffix_truncation_N{d}"] if r["with_anchor_detected"]) for d in [6, 7, 10, 15])
        fhr_det = sum(1 for r in s_groups["full_history_rewrite"] if r["with_anchor_detected"])
        tr_det = sum(1 for r in s_groups["tail_rewrite"] if r["with_anchor_detected"])

        matches_pat, _ = check_seed_matches_sanity(s_recs)
        seed_summaries.append({
            "seed": s,
            "total_sessions": len(s_recs),
            "clean_fp": clean_fp,
            "edit_detected": edit_det,
            "structural_detected": struct_det,
            "trunc_1_5_detected": trunc_1_5_det,
            "trunc_6_15_detected": trunc_6_15_det,
            "fhr_detected": fhr_det,
            "tail_rewrite_detected": tr_det,
            "matches_expected_pattern": matches_pat
        })

    summary_by_seed_path = os.path.join(output_dir, "summary_by_seed.csv")
    with open(summary_by_seed_path, "w", newline="", encoding="utf-8") as f:
        sw = csv.DictWriter(f, fieldnames=list(seed_summaries[0].keys()))
        sw.writeheader()
        sw.writerows(seed_summaries)
    print(f"Written summary by seed to {summary_by_seed_path}")

    # 3. summary_by_class.csv
    # Group classes logically
    class_order = [
        ("Clean controls", ["Clean_Control"]),
        ("Payload edit (A1)", ["A1_single_event_payload"]),
        ("Timestamp edit (A2)", ["A2_timestamp_modification"]),
        ("Prev-hash edit (A3)", ["A3_prev_hash_modification"]),
        ("Metadata session edit (A4)", ["A4_envelope_tamper_session"]),
        ("Metadata event_type edit (A5)", ["A5_envelope_tamper_event_type"]),
        ("Metadata flag edit (A6)", ["A6_envelope_tamper_flag"]),
        ("Mid-chain deletion", ["mid_chain_row_deletion"]),
        ("Duplication", ["duplicate_row"]),
        ("Reordering", ["reordered_rows"]),
        ("Suffix truncation, 1 to 5 events", [f"suffix_truncation_N{d}" for d in [1, 2, 3, 4, 5]]),
        ("Suffix truncation, 6, 7, 10, 15 events", [f"suffix_truncation_N{d}" for d in [6, 7, 10, 15]]),
        ("Full-history rewrite (rows 2..14)", ["full_history_rewrite"]),
        ("Tail rewrite (rows 21..25)", ["tail_rewrite"])
    ]

    class_summaries = []
    print("\n" + "=" * 120)
    print(f"{'Class':<42} {'Sessions':<10} {'No Anchor (n/N)':<18} {'No Anchor 95% CI':<20} {'With Anchor (n/N)':<20} {'With Anchor 95% CI':<20}")
    print("-" * 120)

    for label, c_names in class_order:
        c_recs = [r for r in all_records if r["class"] in c_names]
        n_total = len(c_recs)
        no_det = sum(1 for r in c_recs if r["no_anchor_detected"])
        with_det = sum(1 for r in c_recs if r["with_anchor_detected"])

        no_pct = round(no_det / n_total * 100, 2)
        with_pct = round(with_det / n_total * 100, 2)
        no_ci = wilson_interval(no_det, n_total)
        with_ci = wilson_interval(with_det, n_total)

        class_summaries.append({
            "class_group": label,
            "sessions": n_total,
            "no_anchor_detected_n": no_det,
            "no_anchor_detected_pct": f"{no_pct:.2f}%",
            "no_anchor_ci_lower": f"{no_ci[0]:.2f}%",
            "no_anchor_ci_upper": f"{no_ci[1]:.2f}%",
            "with_anchor_detected_n": with_det,
            "with_anchor_detected_pct": f"{with_pct:.2f}%",
            "with_anchor_ci_lower": f"{with_ci[0]:.2f}%",
            "with_anchor_ci_upper": f"{with_ci[1]:.2f}%"
        })

        no_str = f"{no_det}/{n_total} ({no_pct:.2f}%)"
        no_ci_str = f"[{no_ci[0]:.2f}%, {no_ci[1]:.2f}%]"
        with_str = f"{with_det}/{n_total} ({with_pct:.2f}%)"
        with_ci_str = f"[{with_ci[0]:.2f}%, {with_ci[1]:.2f}%]"
        print(f"{label:<42} {n_total:<10} {no_str:<18} {no_ci_str:<20} {with_str:<20} {with_ci_str:<20}")

    print("=" * 120)

    summary_by_class_path = os.path.join(output_dir, "summary_by_class.csv")
    with open(summary_by_class_path, "w", newline="", encoding="utf-8") as f:
        cw = csv.DictWriter(f, fieldnames=list(class_summaries[0].keys()))
        cw.writeheader()
        cw.writerows(class_summaries)
    print(f"Written summary by class to {summary_by_class_path}")

    # 4. Combined lines and localization rates
    # Edit + Structural combined: 180 x 30 + 30 x 30 = 5,400 + 900 = 6,300
    combined_classes = ORIGINAL_EDIT_CLASSES + STRUCTURAL_CLASSES
    comb_recs = [r for r in all_records if r["class"] in combined_classes]
    comb_n = len(comb_recs)
    comb_det = sum(1 for r in comb_recs if r["with_anchor_detected"])
    comb_ci = wilson_interval(comb_det, comb_n)

    # Clean controls: 30 x 30 = 900
    clean_recs = [r for r in all_records if r["class"] == "Clean_Control"]
    clean_n = len(clean_recs)
    clean_fp = sum(1 for r in clean_recs if r["with_anchor_detected"])
    clean_ci = wilson_interval(clean_fp, clean_n)

    # Exact localization for edit classes: 5,400 sessions
    edit_recs = [r for r in all_records if r["class"] in ORIGINAL_EDIT_CLASSES]
    edit_n = len(edit_recs)
    exact_loc = sum(1 for r in edit_recs if r["localized_exactly"] is True)
    exact_loc_ci = wilson_interval(exact_loc, edit_n)

    print("\n--- COMBINED BENCHMARK SUMMARY ---")
    print(f"1. Six Edit + Three Structural Classes (N={comb_n}): Detected = {comb_det}/{comb_n} ({comb_det/comb_n*100:.2f}%, 95% Wilson CI: [{comb_ci[0]:.2f}%, {comb_ci[1]:.2f}%])")
    print(f"2. Clean Controls False Positives (N={clean_n}): FP = {clean_fp}/{clean_n} ({clean_fp/clean_n*100:.2f}%, 95% Wilson CI: [{clean_ci[0]:.2f}%, {clean_ci[1]:.2f}%])")
    print(f"3. Exact Localization Rate for Edit Classes (N={edit_n}): Exact = {exact_loc}/{edit_n} ({exact_loc/edit_n*100:.2f}%, 95% Wilson CI: [{exact_loc_ci[0]:.2f}%, {exact_loc_ci[1]:.2f}%])")
    print(f"4. Total Wall Time: {wall_time_s:.1f} seconds ({wall_time_s/60:.2f} minutes)")
    print("---------------------------------\n")

def main():
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    parser = argparse.ArgumentParser(description="RQ1 30-Seed Tamper & Truncation Benchmark")
    parser.add_argument("--sanity-only", action="store_true", help="Run only seed 1337 and perform sanity gate check")
    parser.add_argument("--resume", action="store_true", help="Resume unfinished seeds if sessions.csv exists")
    args = parser.parse_args()

    output_dir = "results/raw_v2/rq1_30seed"
    os.makedirs(output_dir, exist_ok=True)
    log_file_path = os.path.join(output_dir, "run.log")
    log_f = open(log_file_path, "a", encoding="utf-8")

    def log(msg):
        print(msg)
        log_f.write(msg + "\n")
        log_f.flush()

    seeds = [1337] + list(range(2001, 2030))
    log("=" * 80)
    log(f"Starting RQ1 30-Seed Evaluation Harness | Seeds ({len(seeds)}): {seeds}")
    log("=" * 80)

    # Sanity Gate: run seed 1337 first
    log("\n[SANITY GATE] Running Seed 1337 first...")
    t0_sanity = time.perf_counter()
    s1337_records, s1337_dur = run_seed(1337, log)
    dur_sanity = time.perf_counter() - t0_sanity

    matches_sanity, sanity_reason = check_seed_matches_sanity(s1337_records)
    log(f"[SANITY GATE RESULT] Match: {matches_sanity} | Reason: {sanity_reason}")
    log(f"[SANITY GATE TIMING] Seed 1337 completed in {dur_sanity:.1f}s.")
    projected_total_s = dur_sanity * 30
    log(f"[PROJECTED 30-SEED TIME] {projected_total_s:.1f}s ({projected_total_s/60:.2f} minutes) for 30 seeds (262,500 events)")

    if not matches_sanity:
        log("\nFATAL: Seed 1337 failed sanity gate check! Halting execution.")
        sys.exit(1)

    if args.sanity_only:
        log("Sanity-only flag passed. Halting after successful seed 1337 gate.")
        return

    # Check for existing completed seeds if resuming
    completed_seeds = set()
    all_records = []
    sessions_path = os.path.join(output_dir, "sessions.csv")
    if args.resume and os.path.exists(sessions_path):
        with open(sessions_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                s = int(row["seed"])
                completed_seeds.add(s)
                # Parse boolean fields
                row["seed"] = s
                row["no_anchor_detected"] = (row["no_anchor_detected"].lower() == "true")
                row["with_anchor_detected"] = (row["with_anchor_detected"].lower() == "true")
                row["chain_intact"] = (row["chain_intact"].lower() == "true")
                row["sequence_complete"] = (row["sequence_complete"].lower() == "true")
                if row["localized_exactly"] in ("True", "False"):
                    row["localized_exactly"] = (row["localized_exactly"] == "True")
                all_records.append(row)
        log(f"Resuming: found {len(completed_seeds)} already completed seeds in {sessions_path}")

    if 1337 not in completed_seeds:
        all_records.extend(s1337_records)
        completed_seeds.add(1337)
        # Flush initial sessions.csv
        fieldnames = [
            "seed", "class", "session_id", "mutated_row", "no_anchor_detected",
            "with_anchor_detected", "chain_intact", "sequence_complete",
            "anchor_check_result", "first_broken_entry_id", "localized_exactly"
        ]
        with open(sessions_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(all_records)

    # Run remaining seeds
    remaining_seeds = [s for s in seeds if s not in completed_seeds]
    t_start_all = time.perf_counter()

    for idx, s in enumerate(remaining_seeds, 1):
        log(f"\n[{idx}/{len(remaining_seeds)}] Executing Seed {s}...")
        s_recs, s_dur = run_seed(s, log)
        all_records.extend(s_recs)

        # Append to sessions.csv incrementally
        with open(sessions_path, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writerows(s_recs)

    total_wall_time = time.perf_counter() - t_start_all + dur_sanity
    log("\nAll 30 seeds completed. Generating aggregate reports...")
    aggregate_and_write_reports(all_records, output_dir, total_wall_time)
    log_f.close()

if __name__ == "__main__":
    main()
