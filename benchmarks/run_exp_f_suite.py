"""Host runner for Experiment F: Malformed Event and Sequence Validation.
Executes test_exp_f_malformed.py inside aegistrace-agent_service-1,
verifies that invalid payloads never enter audit.db,
saves CSV, JSON summary, and raw logs.
"""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import csv
import json
import os
import subprocess
import time

def run_exp_f_suite():
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    print("=== Executing Experiment F Suite ===")
    
    # 1. Clean old exp-f records
    clean_sql = """
import sqlite3
conn = sqlite3.connect('/data/audit.db')
conn.execute("DELETE FROM audit_log WHERE session_id LIKE 'exp-f-%'")
conn.commit()
conn.close()
"""
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(clean_sql), text=True, check=True)

    # 2. Run test_exp_f_malformed.py inside agent_service container
    with open("benchmarks/test_exp_f_malformed.py", "r", encoding="utf-8") as f:
        agent_script = f.read()
    
    proc = subprocess.run(
        ["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-agent_service-1", "python", "-"],
        input=guarded_python(agent_script),
        text=True,
        capture_output=True,
        check=True
    )
    
    output = proc.stdout.strip()
    json_start = output.find("[")
    if json_start == -1:
        print("Raw output:", output)
        print("Raw stderr:", proc.stderr)
        raise RuntimeError("Could not find JSON array in output")
    
    cases = json.loads(output[json_start:])
    
    # 3. Verify SQLite DB contents for exp-f sessions
    check_sql = """
import sqlite3, json
conn = sqlite3.connect('/data/audit.db')
rows = conn.execute("SELECT session_id, event_type, payload FROM audit_log WHERE session_id LIKE 'exp-f-%'").fetchall()
conn.close()
print(json.dumps([{"session_id": r[0], "event_type": r[1]} for r in rows]))
"""
    check_proc = subprocess.run(
        ["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"],
        input=guarded_python(check_sql),
        text=True,
        capture_output=True,
        check=True
    )
    db_stored = json.loads(check_proc.stdout.strip())
    
    # Write raw log
    os.makedirs("evaluation_results/raw_logs", exist_ok=True)
    with open("evaluation_results/raw_logs/exp_f.log", "w", encoding="utf-8") as f:
        f.write("=== STDOUT ===\n")
        f.write(proc.stdout)
        f.write("\n=== STDERR ===\n")
        f.write(proc.stderr)
        f.write(f"\n=== DB VERIFICATION ===\nStored records: {len(db_stored)}\n")
        f.write(json.dumps(db_stored, indent=2))
        
    # Write CSV
    csv_file = "evaluation_results/exp_f_malformed.csv"
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "test_id", "category", "description", "expected_status", "actual_status", "passed", "response_excerpt"
        ])
        writer.writeheader()
        for c in cases:
            writer.writerow(c)
            
    # Summary
    total = len(cases)
    passed = sum(1 for c in cases if c["passed"])
    rejected_invalid = sum(1 for c in cases if c["expected_status"] != 200 and c["actual_status"] == c["expected_status"])
    control_accepted = sum(1 for c in cases if c["expected_status"] == 200 and c["actual_status"] == 200)
    
    # Check that ONLY the control session entered the DB
    stored_sessions = [r["session_id"] for r in db_stored]
    only_control_stored = (len(stored_sessions) == 1 and stored_sessions[0] == "exp-f-session-ctrl")
    
    summary = {
        "total_test_cases": total,
        "passed_test_cases": passed,
        "failed_test_cases": total - passed,
        "control_accepted": control_accepted,
        "rejected_invalid_payloads": rejected_invalid,
        "rejection_accuracy_pct": (rejected_invalid / (total - 1)) * 100 if total > 1 else 0,
        "db_stored_records_count": len(db_stored),
        "zero_malformed_records_in_db": only_control_stored,
        "timestamp_unix": time.time()
    }
    
    summary_file = "evaluation_results/exp_f_summary.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        
    # 4. Clean up exp-f records from DB to maintain clean slate
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(clean_sql), text=True, check=True)
    
    print(f"Experiment F complete: {passed}/{total} passed. Rejection rate: {summary['rejection_accuracy_pct']:.1f}%. Zero malformed records stored: {only_control_stored}.")

if __name__ == "__main__":
    run_exp_f_suite()
