"""V2 Latency & Overhead Benchmark: 5 trials x 1000 turns with 100 warm-up.
Runs inside aegistrace-agent_service-1 by streaming benchmarks/run_audit_overhead.py.
Evaluates:
- DISABLED: Audit capture middleware disabled (FakeLLM baseline)
- ENABLED: Audit capture middleware enabled with schema v2 client_seq and real ingest
Records per-event latency, median, p95, p99, mean.
Saves to results/raw_v2/latency_v2.json and results/logs_v2/latency_v2.log.
"""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import json
import os
import subprocess
import sys

def run_v2_latency_suite():
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    os.makedirs("results/raw_v2", exist_ok=True)
    os.makedirs("results/logs_v2", exist_ok=True)
    
    with open("benchmarks/run_audit_overhead.py", "r", encoding="utf-8") as f:
        script_code = f.read()

    print("Running 5 trials x 1000 turns (100 warm-up) inside agent container...")
    proc = subprocess.run(
        ["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-agent_service-1", "python", "-"],
        input=guarded_python(script_code), text=True, capture_output=True, check=True
    )
    
    out = proc.stdout
    with open("results/logs_v2/latency_v2.log", "w", encoding="utf-8") as f:
        f.write(out)
        if proc.stderr:
            f.write("\nSTDERR:\n" + proc.stderr)

    s_idx = out.find("__JSON_START__")
    e_idx = out.find("__JSON_END__")
    if s_idx == -1 or e_idx == -1:
        print("Error: Could not find JSON markers in output:\n", out)
        sys.exit(1)

    json_str = out[s_idx + len("__JSON_START__"):e_idx].strip()
    data = json.loads(json_str)

    with open("results/raw_v2/latency_v2.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print("\n" + out[out.find("========================================================"):s_idx].strip())
    print("\nResults saved to results/raw_v2/latency_v2.json and results/logs_v2/latency_v2.log")

if __name__ == "__main__":
    run_v2_latency_suite()
