"""Benchmark ingest throughput for 3 variants:
1. Current code: executes SELECT COUNT(*) FROM audit_log WHERE session_id=? on every insert
2. COUNT(*) only when needed: executes COUNT(*) only when client_seq % ANCHOR_EVERY == 0
3. No anchor logic: skips COUNT(*) and anchor logic completely
Measures at C=1 and C=50 (3 trials each, 100 requests per worker).
"""
try:
    from benchmarks.benchmark_safety import require_destructive
except ModuleNotFoundError:
    from benchmark_safety import require_destructive

import concurrent.futures
import hashlib
import json
import os
import sqlite3
import tempfile
import time

SCHEMA = '''
CREATE TABLE IF NOT EXISTS audit_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 session_id TEXT NOT NULL,
 timestamp REAL NOT NULL,
 event_type TEXT NOT NULL,
 payload TEXT NOT NULL,
 sensitive_action_flag BOOLEAN NOT NULL DEFAULT 0,
 prev_hash TEXT NOT NULL,
 hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_session_id ON audit_log(session_id,id);
'''

def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)

def entry_hash(timestamp, payload_str, prev_hash):
    return hashlib.sha256((str(float(timestamp)) + payload_str + prev_hash).encode("utf-8")).hexdigest()

def run_variant_trial(variant, c, trial, events_per_worker=100):
    require_destructive()
    with tempfile.TemporaryDirectory() as td:
        db_path = os.path.join(td, "bench.db")
        conn = sqlite3.connect(db_path, timeout=5, isolation_level=None)
        conn.execute('PRAGMA journal_mode=DELETE')
        conn.execute('PRAGMA busy_timeout=5000')
        conn.executescript(SCHEMA)
        conn.close()

        def worker_task(wid):
            sid = f"bench-c{c}-t{trial}-w{wid:03d}"
            local_conn = sqlite3.connect(db_path, timeout=5, isolation_level=None)
            local_conn.execute('PRAGMA busy_timeout=5000')
            accepted = 0
            locked = 0
            anchor_every = 10
            for i in range(1, events_per_worker + 1):
                pld = {"step": i, "_aegis": {"schema_version": 2, "session_id": sid, "event_type": "state_transition", "sensitive_action_flag": False, "client_seq": i}}
                ser = canonical_json(pld)
                ts = 1710000000.0 + i
                try:
                    local_conn.execute('BEGIN IMMEDIATE')
                    prev = local_conn.execute('SELECT hash FROM audit_log WHERE session_id=? ORDER BY id DESC LIMIT 1', (sid,)).fetchone()
                    prev_h = prev[0] if prev else '0'*64
                    h = entry_hash(ts, ser, prev_h)
                    local_conn.execute('INSERT INTO audit_log(session_id,timestamp,event_type,payload,sensitive_action_flag,prev_hash,hash) VALUES(?,?,?,?,?,?,?)',
                                       (sid, ts, "state_transition", ser, 0, prev_h, h))
                    
                    if variant == "current":
                        cnt = local_conn.execute('SELECT COUNT(*) FROM audit_log WHERE session_id=?', (sid,)).fetchone()[0]
                        if cnt % anchor_every == 0:
                            pass
                    elif variant == "count_when_needed":
                        if i % anchor_every == 0:
                            cnt = local_conn.execute('SELECT COUNT(*) FROM audit_log WHERE session_id=?', (sid,)).fetchone()[0]
                            if cnt % anchor_every == 0:
                                pass
                    elif variant == "no_anchor":
                        pass
                    
                    local_conn.commit()
                    accepted += 1
                except sqlite3.OperationalError as e:
                    try:
                        local_conn.execute('ROLLBACK')
                    except Exception:
                        pass
                    locked += 1
            local_conn.close()
            return accepted, locked

        t0 = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=c) as ex:
            futs = [ex.submit(worker_task, wid) for wid in range(c)]
            results = [f.result() for f in futs]
        dur = time.perf_counter() - t0
        total_acc = sum(r[0] for r in results)
        total_lock = sum(r[1] for r in results)
        eps = total_acc / dur if dur > 0 else 0.0
        return eps, total_acc, total_lock, dur

def main():
    require_destructive()
    variants = ["current", "count_when_needed", "no_anchor"]
    results = {}
    print(f"{'Variant':<20} {'C':<5} {'Trial 1 (eps)':<15} {'Trial 2 (eps)':<15} {'Trial 3 (eps)':<15} {'Mean eps':<12}")
    print("-" * 85)
    for v in variants:
        results[v] = {}
        for c in [1, 50]:
            trials = []
            for t in range(1, 4):
                eps, acc, lck, dur = run_variant_trial(v, c, t)
                trials.append(eps)
            mean_eps = sum(trials) / len(trials)
            results[v][c] = {"trials": trials, "mean": mean_eps}
            print(f"{v:<20} {c:<5} {trials[0]:<15.1f} {trials[1]:<15.1f} {trials[2]:<15.1f} {mean_eps:<12.1f}")

    os.makedirs("results/raw_v2", exist_ok=True)
    with open("results/raw_v2/ingest_variant_benchmarks.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
