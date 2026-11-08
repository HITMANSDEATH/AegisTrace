"""Benchmark 1: Tamper Detection Evaluation for AegisTrace.
Generates 100 clean sessions (20 events each) and 100 tampered sessions (20 events each),
measures detection rate, false positive rate, and localization accuracy via /verify.
"""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import json
import random
import sys
import time
import urllib.request
import sqlite3
import hashlib

def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)

def entry_hash(timestamp, payload_str, prev_hash):
    return hashlib.sha256((str(float(timestamp)) + payload_str + prev_hash).encode("utf-8")).hexdigest()

EVENT_TYPES = ['state_transition', 'tool_start', 'retrieval', 'tool_end']

def generate_session_events(session_id, count=20, base_time=1700000000.0):
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
        events.append((session_id, ts, event_type, serialized, int(sensitive), prev_hash, digest))
        prev_hash = digest
    return events

def run_benchmark():
    require_destructive("http://127.0.0.1:8002", docker=True)
    rng = random.Random(42)
    reconstruction_url = "http://127.0.0.1:8002"
    require_destructive(reconstruction_url)

    # We will execute database operations inside audit_service container using docker exec
    import subprocess

    print("Step 1: Preparing database and cleaning old evaluation sessions...")
    clean_sql = """
import sqlite3
conn = sqlite3.connect('/data/audit.db')
conn.execute("DELETE FROM audit_log WHERE session_id LIKE 'eval-clean-%' OR session_id LIKE 'eval-tamper-%'")
conn.commit()
conn.close()
print("Cleaned")
"""
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(clean_sql), text=True, check=True)

    print("Step 2: Generating 100 clean sessions (~20 events each)...")
    clean_sessions = [f"eval-clean-{i:03d}" for i in range(100)]
    all_clean_events = []
    for sid in clean_sessions:
        all_clean_events.extend(generate_session_events(sid, count=20))

    # Insert all clean events in batches
    insert_script = f"""
import sqlite3
conn = sqlite3.connect('/data/audit.db')
cursor = conn.cursor()
events = {repr(all_clean_events)}
cursor.executemany("INSERT INTO audit_log(session_id, timestamp, event_type, payload, sensitive_action_flag, prev_hash, hash) VALUES(?,?,?,?,?,?,?)", events)
conn.commit()
conn.close()
print("Inserted clean events: " + str(len(events)))
"""
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(insert_script), text=True, check=True)

    print("Step 3: Running /verify on 100 clean sessions...")
    false_positives = 0
    clean_results = []
    for sid in clean_sessions:
        url = f"{reconstruction_url}/api/session/{sid}/verify"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            intact = data.get("chain_intact", False)
            broken = data.get("broken_entry_ids", [])
            clean_results.append((sid, intact, broken))
            if not intact or len(broken) > 0:
                false_positives += 1

    print(f"Clean sessions tested: {len(clean_sessions)}")
    print(f"False positives: {false_positives}/100")

    print("Step 4: Generating 100 sessions with exactly 1 tampered entry...")
    tamper_sessions = [f"eval-tamper-{i:03d}" for i in range(100)]
    all_tamper_events = []
    for sid in tamper_sessions:
        all_tamper_events.extend(generate_session_events(sid, count=20))

    insert_tamper_script = f"""
import sqlite3
conn = sqlite3.connect('/data/audit.db')
cursor = conn.cursor()
events = {repr(all_tamper_events)}
cursor.executemany("INSERT INTO audit_log(session_id, timestamp, event_type, payload, sensitive_action_flag, prev_hash, hash) VALUES(?,?,?,?,?,?,?)", events)
conn.commit()
conn.close()
print("Inserted tamper base events: " + str(len(events)))
"""
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(insert_tamper_script), text=True, check=True)

    # Now tamper exactly one entry per session at a random position (1 to 20)
    tamper_targets = {}  # sid -> (pos, db_id)
    # We query the row IDs for each tamper session
    query_script = """
import sqlite3, json
conn = sqlite3.connect('/data/audit.db')
cursor = conn.cursor()
rows = cursor.execute("SELECT id, session_id FROM audit_log WHERE session_id LIKE 'eval-tamper-%' ORDER BY id").fetchall()
conn.close()
mapping = {}
for r in rows:
    mapping.setdefault(r[1], []).append(r[0])
print(json.dumps(mapping))
"""
    proc = subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(query_script), text=True, capture_output=True, check=True)
    mapping = json.loads(proc.stdout.strip())

    tamper_updates = []
    for sid in tamper_sessions:
        row_ids = mapping[sid]
        pos = rng.randint(1, 20)  # 1-indexed
        target_id = row_ids[pos - 1]
        tamper_targets[sid] = (pos, target_id)
        # We craft a tampered payload
        tampered_payload = {
            "step": pos,
            "label": f"Step {pos} execution [MODIFIED]",
            "message": "UNAUTHORIZED TAMPERED PAYLOAD VALUE",
            "tool": "tampered_tool",
            "_aegis": {
                "schema_version": 1,
                "session_id": sid,
                "event_type": EVENT_TYPES[(pos - 1) % len(EVENT_TYPES)],
                "sensitive_action_flag": (pos % 7 == 0)
            }
        }
        tamper_updates.append((canonical_json(tampered_payload), target_id))

    execute_tamper_script = f"""
import sqlite3
conn = sqlite3.connect('/data/audit.db')
cursor = conn.cursor()
updates = {repr(tamper_updates)}
cursor.executemany("UPDATE audit_log SET payload = ? WHERE id = ?", updates)
conn.commit()
conn.close()
print("Tampered " + str(len(updates)) + " entries")
"""
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(execute_tamper_script), text=True, check=True)

    print("Step 5: Running /verify on 100 tampered sessions...")
    detected_count = 0
    localized_count = 0

    for sid in tamper_sessions:
        expected_pos, expected_id = tamper_targets[sid]
        url = f"{reconstruction_url}/api/session/{sid}/verify"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            intact = data.get("chain_intact", True)
            broken = data.get("broken_entry_ids", [])
            first_broken = data.get("firstBroken")

            if not intact:
                detected_count += 1

            # Check if reported broken matches actual tampered entry
            if (expected_id in broken) and (first_broken == expected_pos):
                localized_count += 1
            else:
                print(f"FAILED LOCALIZATION for {sid}: expected_pos={expected_pos}, expected_id={expected_id}, got broken={broken}, firstBroken={first_broken}")

    print("\n--- RESULTS FOR METRIC 1 ---")
    print(f"Clean sessions tested: 100")
    print(f"False Positives: {false_positives}/100 (False Positive Rate: {false_positives/100:.1%})")
    print(f"Tampered sessions tested: 100")
    print(f"Detection Rate: {detected_count}/100 ({detected_count/100:.1%})")
    print(f"Localization Accuracy: {localized_count}/100 ({localized_count/100:.1%})")

    results = {
        "clean_sessions_count": 100,
        "false_positive_count": false_positives,
        "false_positive_rate": f"{false_positives}/100",
        "tampered_sessions_count": 100,
        "detection_count": detected_count,
        "detection_rate": f"{detected_count}/100",
        "localization_count": localized_count,
        "localization_accuracy": f"{localized_count}/100",
    }
    with open("benchmarks/tamper_detection_results.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    run_benchmark()
