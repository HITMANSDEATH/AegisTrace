"""Host runner for Experiment C: executes concurrency load generator inside agent container, verifies all sessions, and exports metrics."""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import csv
import json
import subprocess
import time
import urllib.request

def run_exp_c_suite():
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    print("=== Executing Experiment C Suite ===")
    
    # 1. Clean old exp-c records
    clean_sql = """
import sqlite3
conn = sqlite3.connect('/data/audit.db')
conn.execute("DELETE FROM audit_log WHERE session_id LIKE 'exp-c-%'")
conn.commit()
conn.close()
print("Cleaned old exp-c records")
"""
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(clean_sql), text=True, check=True)

    # 2. Run test_exp_c_concurrency.py inside agent_service container
    with open("benchmarks/test_exp_c_concurrency.py", "r") as f:
        agent_script = f.read()
        
    proc = subprocess.run(
        ["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-agent_service-1", "python", "-"],
        input=guarded_python(agent_script),
        text=True,
        capture_output=True,
        check=True
    )
    
    output = proc.stdout.strip()
    idx_start = output.find("__JSON_START__")
    idx_end = output.find("__JSON_END__")
    if idx_start == -1 or idx_end == -1:
        print("Raw output:", output)
        raise RuntimeError("Could not find JSON markers in output")
        
    raw_payload = json.loads(output[idx_start + len("__JSON_START__"):idx_end].strip())
    summaries = raw_payload["summaries"]
    records = raw_payload["records"]
    
    # 3. Post-hoc verification of all sessions
    reconstruction_url = "http://127.0.0.1:8002"
    require_destructive(reconstruction_url)
    unique_sessions = sorted(list(set(r["session_id"] for r in records)))
    print(f"\nVerifying {len(unique_sessions)} generated sessions via /verify endpoint...")
    
    session_verification_results = {}
    total_verified = 0
    total_intact = 0
    verification_errors = []
    
    for sid in unique_sessions:
        url = f"{reconstruction_url}/api/session/{sid}/verify"
        try:
            with urllib.request.urlopen(url) as resp:
                data = json.loads(resp.read().decode())
                intact = data.get("chain_intact", False)
                count = data.get("entry_count", 0)
                total_verified += 1
                if intact:
                    total_intact += 1
                else:
                    verification_errors.append((sid, "Tampered/Broken", data.get("broken_entry_ids")))
                session_verification_results[sid] = {
                    "entry_count": count,
                    "chain_intact": intact,
                    "broken_entry_ids": data.get("broken_entry_ids", [])
                }
        except urllib.error.HTTPError as e:
            verification_errors.append((sid, f"HTTP_{e.code}", []))
            session_verification_results[sid] = {"error": f"HTTP_{e.code}"}
            
    print(f"Verification completed: {total_intact}/{total_verified} sessions intact.")
    
    # Update summaries with verification statistics
    for key, s in summaries.items():
        c_level = s["concurrency_level"]
        c_prefix = f"exp-c-c{c_level}-"
        c_sessions = [v for k, v in session_verification_results.items() if k.startswith(c_prefix)]
        s["sessions_count"] = len(c_sessions)
        s["sessions_verified_intact"] = sum(1 for cs in c_sessions if cs.get("chain_intact") is True)
        s["sessions_with_verification_failure"] = len(c_sessions) - s["sessions_verified_intact"]
        s["actual_entries_stored_total"] = sum(cs.get("entry_count", 0) for cs in c_sessions)
        s["missing_entries"] = s["accepted_count"] - s["actual_entries_stored_total"]

    # 4. Write CSV file of all request records
    csv_file = "evaluation_results/exp_c_concurrency_requests.csv"
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(records[0].keys()))
        writer.writeheader()
        writer.writerows(records)
    print(f"Saved request records CSV to {csv_file}")
    
    # 5. Write summary JSON
    final_output = {
        "concurrency_summaries": summaries,
        "verification_summary": {
            "total_sessions_tested": len(unique_sessions),
            "sessions_intact": total_intact,
            "verification_errors": verification_errors
        }
    }
    with open("evaluation_results/exp_c_summary.json", "w") as f:
        json.dump(final_output, f, indent=2)
        
    # 6. Clean up test records
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(clean_sql), text=True, check=True)
    
    print("Experiment C completed successfully.")
    return final_output

if __name__ == "__main__":
    run_exp_c_suite()
