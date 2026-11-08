"""Harness for Q1: True Mid-Chain Insertion and Duplication.
Tests 30 seeds x 10 sessions per class (600 sessions total):
- true_middle_row_insertion: inserts forged row at position p+1 in SQLite id order.
- true_duplicated_row: inserts duplicate of row p at position p+1 in SQLite id order.
Records verification outcome, checks fired, first_broken_seq, expected_first_seq, and localization rate.
"""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import csv
import json
import os
import sqlite3
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from benchmarks.eval_common import reset_ledger_and_restart_services
from benchmarks.run_extended_e1_tamper import canonical_json, entry_hash, generate_session_events, map_reasons_to_checks

def run_true_midchain_evaluation():
    require_destructive("http://127.0.0.1:8002", docker=True)
    os.makedirs("results/raw", exist_ok=True)
    os.makedirs("results/logs", exist_ok=True)
    log_file = open("results/logs/q1_true_midchain.log", "w", encoding="utf-8")

    def log(msg):
        print(msg)
        log_file.write(msg + "\n")
        log_file.flush()

    log("=== Starting Q1: True Mid-Chain Insertion and Duplication Evaluation ===")

    # Read original Part B CSV to get exact session IDs, seeds, and p selections
    with open("results/raw/e1_part_b_extended_mutations.csv", "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        orig_records = list(reader)

    orig_ins = [r for r in orig_records if r["condition"] == "ext_middle_row_insertion"]
    orig_dup = [r for r in orig_records if r["condition"] == "ext_duplicated_row"]

    seeds = [1337] + list(range(1, 30))
    reconstruction_url = "http://127.0.0.1:8002"
    require_destructive(reconstruction_url)

    results = []

    for seed_idx, seed in enumerate(seeds, 1):
        log(f"\n--- [Seed {seed_idx}/30: seed={seed}] Resetting DB & Restarting Services ---")
        reset_ledger_and_restart_services()

        seed_ins = [r for r in orig_ins if int(r["seed"]) == seed]
        seed_dup = [r for r in orig_dup if int(r["seed"]) == seed]

        all_tuples = []
        expected_meta = {}

        # 1. True Mid-Chain Insertion
        for r in seed_ins:
            sid = f"q1-s{seed}-true_ins-{r['session_id'].split('-')[-1]}"
            orig_exp_fb = int(r["expected_first_seq"]) # in orig test, expected_first_seq = p + 1
            p = orig_exp_fb - 1 # 1-based index of row p (2 <= p <= 18)
            
            clean_events = generate_session_events(sid, count=20)
            rows = clean_events
            prev_h = rows[p - 1]['hash']
            forged_ts = rows[p - 1]['timestamp'] + 0.5
            forged_pld = {
                "step": 999,
                "forged": True,
                "_aegis": {
                    "schema_version": 1,
                    "session_id": sid,
                    "event_type": "state_transition",
                    "sensitive_action_flag": False
                }
            }
            forged_ser = canonical_json(forged_pld)
            forged_hash = entry_hash(forged_ts, forged_ser, prev_h)
            forged_row = (sid, forged_ts, "state_transition", forged_ser, 0, prev_h, forged_hash)

            # Build 21 rows with true middle placement:
            # 1..p (original), p+1 (forged), p+2..21 (original p+1..20)
            session_tuples = []
            for ev in clean_events[:p]:
                session_tuples.append((sid, ev['timestamp'], ev['event_type'], ev['serialized'], ev['sensitive'], ev['prev_hash'], ev['hash']))
            session_tuples.append(forged_row)
            for ev in clean_events[p:]:
                session_tuples.append((sid, ev['timestamp'], ev['event_type'], ev['serialized'], ev['sensitive'], ev['prev_hash'], ev['hash']))

            all_tuples.extend(session_tuples)
            # The inserted forged row itself has valid prev_hash to p.
            # But the subsequent row (original row p+1, now at seq p+2) expects prev_hash of p,
            # whereas preceding row in table is forged_row. Thus seq p+2 has LinkBreak!
            expected_meta[sid] = {
                "seed": seed,
                "orig_session_id": r["session_id"],
                "condition": "true_middle_row_insertion",
                "p": p,
                "inserted_at_seq": p + 1,
                "expected_first_seq": p + 2, # first broken link
                "expected_detected": True
            }

        # 2. True Duplicated Row
        for r in seed_dup:
            sid = f"q1-s{seed}-true_dup-{r['session_id'].split('-')[-1]}"
            orig_exp_fb = int(r["expected_first_seq"]) # in orig test, expected_first_seq = p
            p = orig_exp_fb # 1-based index of row p (2 <= p <= 18)

            clean_events = generate_session_events(sid, count=20)
            dup = clean_events[p - 1]
            dup_row = (sid, dup['timestamp'] + 0.001, dup['event_type'], dup['serialized'], dup['sensitive'], dup['prev_hash'], dup['hash'])

            # Build 21 rows with true middle placement:
            # 1..p (original), p+1 (duplicate of row p), p+2..21 (original p+1..20)
            session_tuples = []
            for ev in clean_events[:p]:
                session_tuples.append((sid, ev['timestamp'], ev['event_type'], ev['serialized'], ev['sensitive'], ev['prev_hash'], ev['hash']))
            session_tuples.append(dup_row)
            for ev in clean_events[p:]:
                session_tuples.append((sid, ev['timestamp'], ev['event_type'], ev['serialized'], ev['sensitive'], ev['prev_hash'], ev['hash']))

            all_tuples.extend(session_tuples)
            # The duplicate row at seq p+1 has prev_hash = row p-1 hash, but prior row in table is row p.
            # Thus seq p+1 has LinkBreak + TamperDetected!
            expected_meta[sid] = {
                "seed": seed,
                "orig_session_id": r["session_id"],
                "condition": "true_duplicated_row",
                "p": p,
                "inserted_at_seq": p + 1,
                "expected_first_seq": p + 1, # first broken row
                "expected_detected": True
            }

        # Bulk insert into audit.db
        ins_sql = f"""
import sqlite3
conn = sqlite3.connect('/data/audit.db', isolation_level=None)
cur = conn.cursor()
cur.execute('BEGIN IMMEDIATE')
cur.executemany("INSERT INTO audit_log(session_id, timestamp, event_type, payload, sensitive_action_flag, prev_hash, hash) VALUES(?,?,?,?,?,?,?)", {repr(all_tuples)})
cur.execute('COMMIT')
conn.close()
"""
        subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(ins_sql), text=True, check=True)

        # Query verifier for each session
        for sid, meta in expected_meta.items():
            url = f"{reconstruction_url}/api/session/{sid}/verify"
            with urllib.request.urlopen(url) as resp:
                data = json.loads(resp.read().decode())

            intact = data.get("chain_intact", False)
            broken = data.get("broken_entry_ids", [])
            errors = data.get("errors", [])
            is_detected = (not intact) or (len(broken) > 0)
            checks = map_reasons_to_checks(errors)

            fb_seq = data.get("firstBroken")
            if fb_seq is None and errors:
                fb_seq = errors[0].get("seq")
            elif fb_seq is None and broken:
                try:
                    fb_seq = int(broken[0].split("-")[-1])
                except Exception:
                    fb_seq = None

            exp_fb = meta["expected_first_seq"]
            loc_exact = (fb_seq == exp_fb)
            loc_inserted_pos = (fb_seq == meta["inserted_at_seq"])

            results.append({
                "seed": seed,
                "session_id": sid,
                "orig_session_id": meta["orig_session_id"],
                "condition": meta["condition"],
                "p": meta["p"],
                "inserted_at_seq": meta["inserted_at_seq"],
                "detected": is_detected,
                "checks_fired": checks,
                "first_broken_seq": fb_seq,
                "expected_first_broken_seq": exp_fb,
                "localization_exact_match": loc_exact,
                "localization_matches_inserted_pos": loc_inserted_pos
            })

        ins_det = sum(1 for r in results if r["seed"] == seed and r["condition"] == "true_middle_row_insertion" and r["detected"])
        dup_det = sum(1 for r in results if r["seed"] == seed and r["condition"] == "true_duplicated_row" and r["detected"])
        log(f"Seed {seed} complete: True Insertion Detected = {ins_det}/10, True Duplication Detected = {dup_det}/10")

    # Save CSV
    csv_path = "results/raw/q1_true_midchain_records.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader()
        w.writerows(results)

    # Summaries
    ins_results = [r for r in results if r["condition"] == "true_middle_row_insertion"]
    dup_results = [r for r in results if r["condition"] == "true_duplicated_row"]

    summary = {
        "true_middle_row_insertion": {
            "total_tested": len(ins_results),
            "detected_count": sum(1 for r in ins_results if r["detected"]),
            "detection_rate_pct": sum(1 for r in ins_results if r["detected"]) / len(ins_results) * 100,
            "checks_distribution": {},
            "localization_exact_match_count": sum(1 for r in ins_results if r["localization_exact_match"]),
            "localization_exact_rate_pct": sum(1 for r in ins_results if r["localization_exact_match"]) / len(ins_results) * 100,
            "localization_matches_inserted_pos_count": sum(1 for r in ins_results if r["localization_matches_inserted_pos"]),
            "first_broken_seq_equals_p_plus_2_count": sum(1 for r in ins_results if r["first_broken_seq"] == r["p"] + 2)
        },
        "true_duplicated_row": {
            "total_tested": len(dup_results),
            "detected_count": sum(1 for r in dup_results if r["detected"]),
            "detection_rate_pct": sum(1 for r in dup_results if r["detected"]) / len(dup_results) * 100,
            "checks_distribution": {},
            "localization_exact_match_count": sum(1 for r in dup_results if r["localization_exact_match"]),
            "localization_exact_rate_pct": sum(1 for r in dup_results if r["localization_exact_match"]) / len(dup_results) * 100,
            "first_broken_seq_equals_p_plus_1_count": sum(1 for r in dup_results if r["first_broken_seq"] == r["p"] + 1)
        }
    }

    for r in ins_results:
        summary["true_middle_row_insertion"]["checks_distribution"][r["checks_fired"]] = summary["true_middle_row_insertion"]["checks_distribution"].get(r["checks_fired"], 0) + 1
    for r in dup_results:
        summary["true_duplicated_row"]["checks_distribution"][r["checks_fired"]] = summary["true_duplicated_row"]["checks_distribution"].get(r["checks_fired"], 0) + 1

    with open("results/raw/q1_true_midchain_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    log("\n=== Q1 True Mid-Chain Evaluation Complete ===")
    log_file.close()

if __name__ == "__main__":
    run_true_midchain_evaluation()
