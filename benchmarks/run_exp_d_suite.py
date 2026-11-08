"""Host runner for Experiment D queue pressure."""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import csv
import json
import subprocess
import urllib.request

def run_exp_d_suite():
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    print("=== Executing Experiment D Suite ===")
    
    # 1. Clean old exp-d records
    clean_sql = """
import sqlite3
conn = sqlite3.connect('/data/audit.db')
conn.execute("DELETE FROM audit_log WHERE session_id LIKE 'exp-d-%'")
conn.commit()
conn.close()
print("Cleaned old exp-d records")
"""
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(clean_sql), text=True, check=True)

    # 2. Run inside agent_service
    with open("benchmarks/test_exp_d_queue_pressure.py", "r") as f:
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
        
    summary = json.loads(output[idx_start + len("__JSON_START__"):idx_end].strip())
    
    # 3. Check verification on Part 1 sessions
    reconstruction_url = "http://127.0.0.1:8002"
    require_destructive(reconstruction_url)
    for r in summary["part1_normal_sink"]:
        sid = f"exp-d-norm-{r['burst_size']}"
        url = f"{reconstruction_url}/api/session/{sid}/verify"
        try:
            with urllib.request.urlopen(url) as resp:
                data = json.loads(resp.read().decode())
                r["actual_db_entries"] = data.get("entry_count", 0)
                r["chain_intact"] = data.get("chain_intact", False)
        except Exception as e:
            r["actual_db_entries"] = 0
            r["chain_intact"] = False
            r["error"] = str(e)

    # Export CSV for Part 1 & Part 2
    with open("evaluation_results/exp_d_queue_normal.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(summary["part1_normal_sink"][0].keys()))
        writer.writeheader()
        writer.writerows(summary["part1_normal_sink"])

    with open("evaluation_results/exp_d_queue_paused.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(summary["part2_paused_sink"][0].keys()))
        writer.writeheader()
        writer.writerows(summary["part2_paused_sink"])

    with open("evaluation_results/exp_d_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    # Clean up test records
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(clean_sql), text=True, check=True)
    
    print("Experiment D completed successfully.")
    return summary

if __name__ == "__main__":
    run_exp_d_suite()
