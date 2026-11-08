"""Experiment C: Concurrent Ingestion and Load Testing for AegisTrace.
Executes from inside agent_service container to test real audit_service concurrency and SQLite locking.
Tests concurrency levels: 1, 5, 10, 25, 50 workers.
Each worker runs on a distinct session ID, submitting 100 events.
Records per-request start, end, latency (ns), HTTP status, response, and errors.
"""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import concurrent.futures
import csv
import json
import os
import sys
import time
import httpx

EVENT_TYPES = ['state_transition', 'tool_start', 'retrieval', 'tool_end']

def worker_task(worker_id, concurrency_level, events_per_worker, audit_url, token):
    require_destructive(audit_url)
    session_id = f"exp-c-c{concurrency_level}-w{worker_id:02d}"
    client = httpx.Client(timeout=10.0, trust_env=False)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    records = []
    base_time = 1710200000.0 + worker_id * 1000.0
    
    for i in range(1, events_per_worker + 1):
        ts = base_time + i * 1.0
        event_type = EVENT_TYPES[(i - 1) % len(EVENT_TYPES)]
        sensitive = (i % 10 == 0)
        body = {
            "session_id": session_id,
            "client_seq": i,
            "timestamp": ts,
            "event_type": event_type,
            "payload": {"step": i, "worker": worker_id, "load_test": True},
            "sensitive_action_flag": sensitive
        }
        
        t0_ns = time.perf_counter_ns()
        status_code = None
        response_text = ""
        error_type = None
        
        try:
            resp = client.post(audit_url, json=body, headers=headers)
            t1_ns = time.perf_counter_ns()
            status_code = resp.status_code
            response_text = resp.text
            if status_code != 200:
                error_type = f"HTTP_{status_code}"
        except httpx.TimeoutException:
            t1_ns = time.perf_counter_ns()
            error_type = "TimeoutException"
        except Exception as e:
            t1_ns = time.perf_counter_ns()
            error_type = type(e).__name__
            
        elapsed_ms = (t1_ns - t0_ns) / 1_000_000.0
        records.append({
            "concurrency": concurrency_level,
            "worker_id": worker_id,
            "session_id": session_id,
            "event_seq": i,
            "start_ns": t0_ns,
            "end_ns": t1_ns,
            "elapsed_ms": elapsed_ms,
            "status_code": status_code,
            "error_type": error_type,
            "response_text": response_text[:100]
        })
        
    client.close()
    return records

def run_experiment_c(concurrency_levels=[1, 5, 10, 25, 50], events_per_worker=100):
    require_destructive(os.environ.get("AUDIT_SINK_URL", "http://audit_service:8001/ingest"))
    token = require_token()
    if not token:
        print("ERROR: AUDIT_WRITE_TOKEN missing")
        sys.exit(1)
        
    audit_url = os.environ.get("AUDIT_SINK_URL", "http://audit_service:8001/ingest")
    require_destructive(audit_url)
    print(f"=== Starting Experiment C: Concurrent Ingestion & Load (Levels: {concurrency_levels}) ===")
    
    all_request_records = []
    level_summaries = {}
    
    for c in concurrency_levels:
        total_requested = c * events_per_worker
        print(f"\n[Concurrency {c}] Launching {c} workers x {events_per_worker} events = {total_requested} requests...")
        
        t_start_suite = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=c) as executor:
            futures = [
                executor.submit(worker_task, w_id, c, events_per_worker, audit_url, token)
                for w_id in range(c)
            ]
            level_records = []
            for f in concurrent.futures.as_completed(futures):
                level_records.extend(f.result())
        t_end_suite = time.perf_counter()
        
        total_suite_duration = t_end_suite - t_start_suite
        all_request_records.extend(level_records)
        
        # Calculate statistics for this concurrency level
        latencies = [r["elapsed_ms"] for r in level_records]
        latencies_sorted = sorted(latencies)
        accepted = sum(1 for r in level_records if r["status_code"] == 200)
        rejected = sum(1 for r in level_records if r["status_code"] in [400, 403, 422])
        db_locked = sum(1 for r in level_records if r["status_code"] == 503)
        timeouts = sum(1 for r in level_records if r["error_type"] == "TimeoutException")
        other_errors = sum(1 for r in level_records if r["status_code"] not in [200, 400, 403, 422, 503] and r["error_type"] != "TimeoutException" and r["error_type"] is not None)
        
        p50 = latencies_sorted[int(len(latencies_sorted) * 0.50)]
        p95 = latencies_sorted[min(int(len(latencies_sorted) * 0.95), len(latencies_sorted) - 1)]
        p99 = latencies_sorted[min(int(len(latencies_sorted) * 0.99), len(latencies_sorted) - 1)]
        mean = sum(latencies) / len(latencies)
        throughput = accepted / total_suite_duration if total_suite_duration > 0 else 0
        
        level_summaries[f"c_{c}"] = {
            "concurrency_level": c,
            "workers": c,
            "events_per_worker": events_per_worker,
            "total_requested": total_requested,
            "accepted_count": accepted,
            "rejected_count": rejected,
            "db_locked_count (503)": db_locked,
            "timeouts_count": timeouts,
            "other_errors_count": other_errors,
            "total_duration_sec": round(total_suite_duration, 3),
            "throughput_events_per_sec": round(throughput, 2),
            "latency_p50_ms": round(p50, 3),
            "latency_p95_ms": round(p95, 3),
            "latency_p99_ms": round(p99, 3),
            "latency_mean_ms": round(mean, 3)
        }
        
        print(f"  Level {c}: {accepted}/{total_requested} accepted, {db_locked} db_locked (503), {timeouts} timeouts.")
        print(f"  Latency: p50={p50:.2f}ms, p95={p95:.2f}ms, p99={p99:.2f}ms. Throughput={throughput:.1f} ev/s")
        
    print("__JSON_START__")
    print(json.dumps({"summaries": level_summaries, "records": all_request_records}))
    print("__JSON_END__")

if __name__ == "__main__":
    run_experiment_c()
