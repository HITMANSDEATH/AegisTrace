"""Benchmark Runner for Naive-Logging Baseline (Condition B).
Runs inside agent_service container context.
Matches the exact methodology of the audit layer overhead benchmark:
- 100 warm-up events (discarded)
- 1,000 synthetic tool-call events per run across 5 independent runs
- Measures per-turn latency, calculating median and p95
"""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import json
import os
import statistics
import time
from types import SimpleNamespace
from fastapi.testclient import TestClient
from agent.main import create_app

# Inline naive logger in case module is piped over stdin to docker exec
class NaiveLoggingStub:
    def __init__(self, db_path="/tmp/naive_audit_log.db"):
        require_destructive()
        self.db_path = db_path
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass
        import sqlite3
        self.sqlite3 = sqlite3
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS naive_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp REAL NOT NULL,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                sensitive_action_flag INTEGER NOT NULL
            )
        """)
        self.conn.commit()

    def capture(
        self,
        *,
        session_id: str,
        event_type: str,
        payload: dict,
        sensitive_action_flag: bool = False,
        timestamp: float | None = None,
    ) -> bool:
        ts = float(time.time() if timestamp is None else timestamp)
        payload_str = json.dumps(payload)
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO naive_audit_log (session_id, timestamp, event_type, payload, sensitive_action_flag)
            VALUES (?, ?, ?, ?, ?)
            """,
            (session_id, ts, event_type, payload_str, int(sensitive_action_flag))
        )
        self.conn.commit()
        return True

    def start(self):
        pass

    def close(self, **kwargs):
        try:
            self.conn.close()
        except Exception:
            pass

class FakeLLM:
    async def ainvoke(self, messages):
        return SimpleNamespace(content="Deterministic mock response for tool execution.")
    def invoke(self, messages):
        return SimpleNamespace(content="Deterministic mock response for tool execution.")

def percentile(data, p):
    sorted_data = sorted(data)
    idx = int(len(sorted_data) * p / 100.0)
    return sorted_data[min(idx, len(sorted_data) - 1)]

def run_condition_b(runs=5, count_per_run=1000, warmup_count=100):
    require_destructive()
    all_latencies = []
    run_stats = []

    print("\n--- Running Condition B: Naive Synchronous Logging ---")
    
    # Warm-up (100 events, discarded)
    print(f"Executing {warmup_count} warm-up events (discarded)...")
    logger = NaiveLoggingStub()
    app = create_app(llm=FakeLLM(), capture=logger)
    with TestClient(app) as client:
        for i in range(warmup_count):
            resp = client.post("/chat", json={
                "session_id": "warmup-naive",
                "message": f"Investigate account access warmup {i}"
            })
            assert resp.status_code == 200, resp.text
    logger.close()

    # 5 runs x 1,000 events
    for run_idx in range(1, runs + 1):
        logger = NaiveLoggingStub(f"/tmp/naive_run_{run_idx}.db")
        app = create_app(llm=FakeLLM(), capture=logger)
        latencies = []
        sid = f"overhead-naive-run{run_idx}"
        print(f"Run {run_idx}/{runs}: executing {count_per_run} events...")
        
        with TestClient(app) as client:
            for i in range(count_per_run):
                t0 = time.perf_counter()
                resp = client.post("/chat", json={
                    "session_id": sid,
                    "message": f"Investigate account access event {i}"
                })
                dt_ms = (time.perf_counter() - t0) * 1000.0
                assert resp.status_code == 200, resp.text
                latencies.append(dt_ms)
                
        logger.close()

        med = statistics.median(latencies)
        p95 = percentile(latencies, 95)
        mean = statistics.mean(latencies)
        run_stats.append({
            "run": run_idx,
            "median_ms": round(med, 3),
            "p95_ms": round(p95, 3),
            "mean_ms": round(mean, 3)
        })
        all_latencies.extend(latencies)
        print(f"  Run {run_idx} complete: median = {med:.3f} ms, p95 = {p95:.3f} ms")

    overall_med = statistics.median(all_latencies)
    overall_p95 = percentile(all_latencies, 95)
    overall_mean = statistics.mean(all_latencies)

    results = {
        "condition": "B - Naive synchronous logging",
        "runs": run_stats,
        "total_events": len(all_latencies),
        "median_ms": round(overall_med, 3),
        "p95_ms": round(overall_p95, 3),
        "mean_ms": round(overall_mean, 3)
    }

    print("\n========================================================")
    print("CONDITION B RESULTS SUMMARY")
    print("========================================================")
    print(f"Total events measured: {len(all_latencies)}")
    print(f"Overall Median: {overall_med:.3f} ms")
    print(f"Overall p95:    {overall_p95:.3f} ms")
    print("========================================================")
    print("__JSON_START__")
    print(json.dumps(results, indent=2))
    print("__JSON_END__")

if __name__ == "__main__":
    run_condition_b()
