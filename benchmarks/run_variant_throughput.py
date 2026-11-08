"""Benchmark 3 ingest variants at C=1 and C=50 (3 trials each, 100 events per worker).
Variant 1: Current code (COUNT(*) on every event)
Variant 2: COUNT(*) executed only when needed (when client_seq % ANCHOR_EVERY == 0)
Variant 3: No anchor logic (skips COUNT(*) and anchor dispatch)
Runs inside container or against local app to compare throughput.
"""
try:
    from benchmarks.benchmark_safety import require_destructive
except ModuleNotFoundError:
    from benchmark_safety import require_destructive

import concurrent.futures
import json
import os
import sqlite3
import tempfile
import time
from types import SimpleNamespace
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field, ConfigDict
from typing import Literal
import sys
sys.path.insert(0, os.path.abspath("aegistrace-complete/aegistrace"))
from common.hash import canonical_json, entry_hash

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

class IngestEvent(BaseModel):
    model_config = ConfigDict(allow_inf_nan=False, extra='forbid')
    client_seq: int = Field(strict=True, ge=1)
    event_type: Literal['retrieval','state_transition','tool_start','tool_end']
    session_id: str = Field(pattern=r'^[A-Za-z0-9_-]{1,96}$')
    payload: dict
    sensitive_action_flag: bool = False
    timestamp: float

def build_app(db_path, variant):
    require_destructive()
    from fastapi import FastAPI, HTTPException
    app = FastAPI()
    
    @app.post('/ingest')
    def ingest(body: IngestEvent):
        payload = dict(body.payload)
        payload['_aegis'] = dict(schema_version=2, session_id=body.session_id,
                                 event_type=body.event_type, sensitive_action_flag=body.sensitive_action_flag,
                                 client_seq=body.client_seq)
        serialized = canonical_json(payload)
        conn = None
        anchor_job = None
        anchor_every = 10
        try:
            conn = sqlite3.connect(db_path, timeout=5, isolation_level=None)
            conn.execute('PRAGMA busy_timeout=5000')
            conn.execute('BEGIN IMMEDIATE')
            previous = conn.execute('SELECT hash FROM audit_log WHERE session_id=? ORDER BY id DESC LIMIT 1', (body.session_id,)).fetchone()
            prev_hash = previous[0] if previous else '0'*64
            digest = entry_hash(body.timestamp, serialized, prev_hash)
            conn.execute('INSERT INTO audit_log(session_id,timestamp,event_type,payload,sensitive_action_flag,prev_hash,hash) VALUES(?,?,?,?,?,?,?)',
                         (body.session_id, body.timestamp, body.event_type, serialized, int(body.sensitive_action_flag), prev_hash, digest))
            
            if variant == "current":
                session_count = conn.execute('SELECT COUNT(*) FROM audit_log WHERE session_id=?', (body.session_id,)).fetchone()[0]
                if session_count % anchor_every == 0:
                    anchor_job = dict(session_id=body.session_id, count=session_count, head_hash=digest, last_client_seq=body.client_seq)
            elif variant == "count_when_needed":
                if body.client_seq % anchor_every == 0:
                    session_count = conn.execute('SELECT COUNT(*) FROM audit_log WHERE session_id=?', (body.session_id,)).fetchone()[0]
                    if session_count % anchor_every == 0:
                        anchor_job = dict(session_id=body.session_id, count=session_count, head_hash=digest, last_client_seq=body.client_seq)
            elif variant == "no_anchor":
                pass
                
            conn.commit()
        except sqlite3.Error:
            if conn:
                try: conn.rollback()
                except Exception: pass
            raise HTTPException(503, 'audit sink unavailable')
        finally:
            if conn: conn.close()
        return {'status': 'recorded'}
    return app

def run_test(variant, c, run_idx, events_per_worker=100):
    require_destructive()
    with tempfile.TemporaryDirectory() as td:
        db_path = os.path.join(td, "audit.db")
        conn = sqlite3.connect(db_path)
        conn.execute('PRAGMA journal_mode=DELETE')
        conn.executescript(SCHEMA)
        conn.close()
        
        app = build_app(db_path, variant)
        client = TestClient(app)
        
        def worker(wid):
            sid = f"v-{variant}-c{c}-r{run_idx}-w{wid:03d}"
            acc = 0
            for i in range(1, events_per_worker + 1):
                body = {
                    "session_id": sid,
                    "client_seq": i,
                    "event_type": "state_transition",
                    "payload": {"step": i},
                    "timestamp": 1710000000.0 + i,
                    "sensitive_action_flag": False
                }
                r = client.post('/ingest', json=body)
                if r.status_code == 200:
                    acc += 1
            return acc

        t0 = time.perf_counter()
        if c == 1:
            total_acc = worker(0)
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=c) as ex:
                futs = [ex.submit(worker, wid) for wid in range(c)]
                total_acc = sum(f.result() for f in futs)
        dur = time.perf_counter() - t0
        throughput = total_acc / dur if dur > 0 else 0.0
        return throughput, total_acc, dur

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
            for r in range(1, 4):
                eps, acc, dur = run_test(v, c, r, events_per_worker=100)
                trials.append(round(eps, 1))
            mean_eps = round(sum(trials) / len(trials), 1)
            results[v][str(c)] = {"trials": trials, "mean": mean_eps}
            print(f"{v:<20} {c:<5} {trials[0]:<15.1f} {trials[1]:<15.1f} {trials[2]:<15.1f} {mean_eps:<12.1f}")
            
    os.makedirs("results/raw_v2", exist_ok=True)
    with open("results/raw_v2/ingest_variant_benchmarks.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
