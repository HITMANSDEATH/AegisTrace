"""Benchmark 4: Verification Scaling Evaluation for AegisTrace.
Generates sessions at sizes 10, 100, 1,000, and 10,000 entries.
Measures how long /verify takes to run at each size.
"""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import hashlib
import json
import subprocess
import time
import urllib.request

def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)

def entry_hash(timestamp, payload_str, prev_hash):
    return hashlib.sha256((str(float(timestamp)) + payload_str + prev_hash).encode("utf-8")).hexdigest()

EVENT_TYPES = ['state_transition', 'tool_start', 'retrieval', 'tool_end']

def generate_session_tuples(session_id, count, base_time=1700000000.0):
    events = []
    prev_hash = '0' * 64
    for i in range(1, count + 1):
        ts = base_time + i * 1.0
        event_type = EVENT_TYPES[(i - 1) % len(EVENT_TYPES)]
        sensitive = (i % 10 == 0)
        payload = {
            "step": i,
            "label": f"Step {i} execution",
            "message": f"Deterministic synthetic scaling event {i} for session {session_id}",
            "tool": "mock_tool" if "tool" in event_type else None,
            "_aegis": {
                "schema_version": 1,
                "session_id": session_id,
                "event_type": event_type,
                "sensitive_action_flag": sensitive
            }
        }
        serialized = canonical_json(payload)
        digest = entry_hash(ts, serialized, prev_hash)
        events.append((session_id, ts, event_type, serialized, int(sensitive), prev_hash, digest))
        prev_hash = digest
    return events

def run_scaling_benchmark():
    require_destructive("http://127.0.0.1:8002", docker=True)
    sizes = [10, 100, 1000, 10000]
    reconstruction_url = "http://127.0.0.1:8002"
    require_destructive(reconstruction_url)

    print("Cleaning any old scaling sessions...")
    clean_sql = """
import sqlite3
conn = sqlite3.connect('/data/audit.db')
conn.execute("DELETE FROM audit_log WHERE session_id LIKE 'eval-scale-%'")
conn.commit()
conn.close()
print("Cleaned scale sessions")
"""
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(clean_sql), text=True, check=True)

    results = []

    for count in sizes:
        sid = f"eval-scale-{count}"
        print(f"\nGenerating {count} entries for session {sid}...")
        events = generate_session_tuples(sid, count)

        # Batch insert into audit_service SQLite
        # Use chunks to avoid passing huge strings to docker exec if count == 10000
        chunk_size = 2500
        for chunk_idx in range(0, len(events), chunk_size):
            chunk = events[chunk_idx:chunk_idx + chunk_size]
            insert_script = f"""
import sqlite3
conn = sqlite3.connect('/data/audit.db')
cursor = conn.cursor()
events = {repr(chunk)}
cursor.executemany("INSERT INTO audit_log(session_id, timestamp, event_type, payload, sensitive_action_flag, prev_hash, hash) VALUES(?,?,?,?,?,?,?)", events)
conn.commit()
conn.close()
"""
            subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(insert_script), text=True, check=True)

        print(f"Inserted {count} entries into database. Now verifying...")

        # Warm-up call
        warmup_req = urllib.request.Request(f"{reconstruction_url}/api/session/{sid}/verify")
        with urllib.request.urlopen(warmup_req) as resp:
            data = json.loads(resp.read().decode())
            assert data["chain_intact"] is True
            assert data["entry_count"] == count

        # Measure /verify runtime (take 3 runs and average, or single clean run)
        measurements_http = []
        measurements_server = []
        for trial in range(3):
            t0 = time.perf_counter()
            req = urllib.request.Request(f"{reconstruction_url}/api/session/{sid}/verify")
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode())
                dt_http = (time.perf_counter() - t0) * 1000
                assert data["chain_intact"] is True
                assert data["entry_count"] == count
                server_ms = data.get("durationMs", dt_http)
                measurements_http.append(dt_http)
                measurements_server.append(server_ms)

        avg_http = sum(measurements_http) / len(measurements_http)
        avg_server = sum(measurements_server) / len(measurements_server)

        print(f"Session {sid} ({count} entries):")
        print(f"  Server verification durationMs: {avg_server:.2f} ms")
        print(f"  Total HTTP round-trip: {avg_http:.2f} ms")

        results.append({
            "entry_count": count,
            "server_duration_ms": round(avg_server, 2),
            "http_roundtrip_ms": round(avg_http, 2)
        })

    print("\n--- RESULTS FOR METRIC 4 ---")
    print(f"{'Entry Count':<15} | {'Verification Time (ms)':<25}")
    print("-" * 45)
    for r in results:
        print(f"{r['entry_count']:<15} | {r['server_duration_ms']:<25}")

    with open("benchmarks/verification_scaling_results.json", "w") as f:
        json.dump(results, f, indent=2)

    # Cleanup scale sessions
    print("\nCleaning up scaling sessions...")
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(clean_sql), text=True, check=True)

if __name__ == "__main__":
    run_scaling_benchmark()
