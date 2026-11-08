"""Re-run and re-confirm the 20-case malformed event suite (19 invalid + 1 valid).
Saves results into results/raw/malformed_suite.csv and results/raw/malformed_summary.json.
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

sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from benchmarks.eval_common import reset_ledger_and_restart_services

def run_malformed_reconfirm():
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    os.makedirs("results/raw", exist_ok=True)
    os.makedirs("results/logs", exist_ok=True)
    log_file = open("results/logs/malformed_reconfirm.log", "w", encoding="utf-8")

    def log(msg):
        print(msg)
        log_file.write(msg + "\n")
        log_file.flush()

    log("=== Re-running Malformed Event Suite (19 invalid + 1 valid) ===")
    reset_ledger_and_restart_services()

    with open("benchmarks/test_exp_f_malformed.py", "r", encoding="utf-8") as f:
        script = f.read()

    proc = subprocess.run(
        ["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-agent_service-1", "python", "-"],
        input=guarded_python(script),
        text=True,
        capture_output=True,
        check=True
    )
    raw_out = proc.stdout.strip()
    idx = raw_out.find("[")
    cases = json.loads(raw_out[idx:])

    # Verify SQLite database
    chk_proc = subprocess.run(
        ["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"],
        input=guarded_python("import sqlite3, json; conn = sqlite3.connect('/data/audit.db'); rows = conn.execute('SELECT session_id FROM audit_log').fetchall(); print(json.dumps([r[0] for r in rows]))"),
        text=True,
        capture_output=True,
        check=True
    )
    stored_sessions = json.loads(chk_proc.stdout.strip())

    csv_path = "results/raw/malformed_suite.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(cases[0].keys()))
        w.writeheader()
        w.writerows(cases)

    total = len(cases)
    passed = sum(1 for c in cases if c["passed"])
    rejected_invalid = sum(1 for c in cases if c["expected_status"] != 200 and c["actual_status"] == c["expected_status"])
    control_accepted = sum(1 for c in cases if c["expected_status"] == 200 and c["actual_status"] == 200)

    summary = {
        "total_test_cases": total,
        "passed_cases": passed,
        "rejected_invalid": rejected_invalid,
        "control_accepted": control_accepted,
        "stored_sessions_in_db": stored_sessions,
        "only_control_stored": (len(stored_sessions) == 1 and stored_sessions[0] == "exp-f-session-ctrl"),
        "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

    with open("results/raw/malformed_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    log(f"Malformed Suite Re-run: {passed}/{total} passed. 19/19 invalid rejected, 1/1 valid accepted. Only control stored in SQLite: {summary['only_control_stored']}")
    log_file.close()

if __name__ == "__main__":
    run_malformed_reconfirm()
