"""Container Ingest Variant Benchmark.
Evaluates 3 variants of SQLite transaction logic:
1. current: SELECT COUNT(*) on every event
2. count_when_needed: SELECT COUNT(*) only when client_seq % 10 == 0
3. no_anchor: no COUNT(*) and no anchor logic
Measures at C=1 and C=50 (3 trials each, 100 events/worker).
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

def run_variant(variant, c, run_idx, events_per_worker=100):
    require_destructive()
    with tempfile.NamedTemporaryFile() as tf:
        db_path = tf.name
        conn = sqlite3.connect(db_path, timeout=5, isolation_level=None)
        conn.execute('PRAGMA journal_mode=DELETE')
        conn.execute('PRAGMA busy_timeout=5000')
        conn.executescript(SCHEMA)
        conn.close()

        anchor_every = 10

        def worker(wid):
            sid = f"bench-c{c}-r{run_idx}-w{wid:03d}"
            local_conn = sqlite3.connect(db_path, timeout=5, isolation_level=None)
            local_conn.execute('PRAGMA busy_timeout=5000')
            accepted = 0
            locked = 0
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
                except sqlite3.OperationalError:
                    try: local_conn.execute('ROLLBACK')
                    except Exception: pass
                    locked += 1
            local_conn.close()
            return accepted, locked

        t0 = time.perf_counter()
        if c == 1:
            acc, lck = worker(0)
            total_acc = acc
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=c) as ex:
                futs = [ex.submit(worker, wid) for wid in range(c)]
                total_acc = sum(f.result()[0] for f in futs)
        dur = time.perf_counter() - t0
        eps = total_acc / dur if dur > 0 else 0.0
        return eps, total_acc, dur

def main():
    require_destructive()
    variants = ["current", "count_when_needed", "no_anchor"]
    results = {}
    print(f"{'Variant':<20} {'C':<5} {'Trial 1':<12} {'Trial 2':<12} {'Trial 3':<12} {'Mean eps':<12}", flush=True)
    print("-" * 75, flush=True)
    for v in variants:
        results[v] = {}
        for c in [1, 50]:
            trials = []
            for r in range(1, 4):
                eps, acc, dur = run_variant(v, c, r, events_per_worker=100)
                trials.append(round(eps, 1))
            mean_eps = round(sum(trials) / len(trials), 1)
            results[v][str(c)] = {"trials": trials, "mean": mean_eps}
            print(f"{v:<20} {c:<5} {trials[0]:<12.1f} {trials[1]:<12.1f} {trials[2]:<12.1f} {mean_eps:<12.1f}", flush=True)

    print("__JSON_START__")
    print(json.dumps(results, indent=2))
    print("__JSON_END__")

if __name__ == "__main__":
    main()
