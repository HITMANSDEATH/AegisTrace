"""Benchmark 3: Audit Layer Overhead Evaluation for AegisTrace.
Runs 1,000 synthetic tool-call events through the agent with audit capture middleware DISABLED vs ENABLED.
Warms up with 100 events first (discarded).
Repeats full 1,000-event run 5 times for each condition.
Records per-event latency, reports median and p95 for both conditions and the difference.
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
from agent.capture import AuditCapture

class FakeLLM:
    async def ainvoke(self, messages):
        return SimpleNamespace(content="Deterministic mock response for tool execution.")
    def invoke(self, messages):
        return SimpleNamespace(content="Deterministic mock response for tool execution.")

class DisabledCapture:
    def capture(self, **kwargs):
        return False
    def start(self):
        pass
    def close(self, **kwargs):
        pass

def percentile(data, p):
    sorted_data = sorted(data)
    idx = int(len(sorted_data) * p / 100.0)
    return sorted_data[min(idx, len(sorted_data) - 1)]

def run_trials(app_factory, condition_name, runs=5, count_per_run=1000, warmup_count=100):
    require_destructive(os.environ.get("AUDIT_SINK_URL", "http://audit_service:8001/ingest"))
    all_latencies = []
    run_stats = []

    print(f"\n--- Running Condition: {condition_name} ---")
    
    # 1. Warm-up
    print(f"Executing {warmup_count} warm-up events (discarded)...")
    app, capture_obj = app_factory()
    capture_url = getattr(capture_obj, "audit_url", None)
    if capture_url:
        validate_target(capture_url)
    with TestClient(app) as client:
        for i in range(warmup_count):
            resp = client.post("/chat", json={
                "session_id": f"warmup-{condition_name}",
                "message": f"Investigate account access warmup {i}"
            })
            assert resp.status_code == 200, resp.text
    if capture_obj and hasattr(capture_obj, "close"):
        capture_obj.close(drain=True)

    # 2. 5 Benchmark Runs of 1000 events each
    for run_idx in range(1, runs + 1):
        app, capture_obj = app_factory()
        capture_url = getattr(capture_obj, "audit_url", None)
        if capture_url:
            validate_target(capture_url)
        latencies = []
        sid = f"overhead-{condition_name}-run{run_idx}"
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
                
        if capture_obj and hasattr(capture_obj, "close"):
            capture_obj.close(drain=True)

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
    overall_p99 = percentile(all_latencies, 99)

    return {
        "condition": condition_name,
        "runs": run_stats,
        "total_events": len(all_latencies),
        "median_ms": round(overall_med, 3),
        "p95_ms": round(overall_p95, 3),
        "p99_ms": round(overall_p99, 3),
        "mean_ms": round(overall_mean, 3),
        "all_latencies": all_latencies
    }

def main():
    require_destructive(os.environ.get("AUDIT_SINK_URL", "http://audit_service:8001/ingest"))
    print("Starting Audit Layer Overhead Evaluation (Deterministic Synthetic LLM)...")

    # Condition 1: Audit Capture Middleware DISABLED
    def make_disabled():
        cap = DisabledCapture()
        app = create_app(llm=FakeLLM(), capture=cap)
        return app, cap

    disabled_results = run_trials(make_disabled, "DISABLED", runs=5, count_per_run=1000, warmup_count=100)

    # Condition 2: Audit Capture Middleware ENABLED (Normal Operation)
    def make_enabled():
        cap = AuditCapture(
            audit_url=os.getenv("AUDIT_SINK_URL", "http://audit_service:8001/ingest"),
            token=os.getenv("AUDIT_WRITE_TOKEN"),
            autostart=True
        )
        app = create_app(llm=FakeLLM(), capture=cap)
        return app, cap

    enabled_results = run_trials(make_enabled, "ENABLED", runs=5, count_per_run=1000, warmup_count=100)

    # Calculate overhead difference
    diff_median = enabled_results["median_ms"] - disabled_results["median_ms"]
    diff_p95 = enabled_results["p95_ms"] - disabled_results["p95_ms"]
    diff_mean = enabled_results["mean_ms"] - disabled_results["mean_ms"]

    summary = {
        "disabled": {
            "median_ms": disabled_results["median_ms"],
            "p95_ms": disabled_results["p95_ms"],
            "mean_ms": disabled_results["mean_ms"],
            "runs": disabled_results["runs"]
        },
        "enabled": {
            "median_ms": enabled_results["median_ms"],
            "p95_ms": enabled_results["p95_ms"],
            "mean_ms": enabled_results["mean_ms"],
            "runs": enabled_results["runs"]
        },
        "difference": {
            "median_delta_ms": round(diff_median, 3),
            "p95_delta_ms": round(diff_p95, 3),
            "mean_delta_ms": round(diff_mean, 3)
        }
    }

    print("\n========================================================")
    print("AUDIT LAYER OVERHEAD RESULTS SUMMARY")
    print("========================================================")
    print(f"Condition: DISABLED (5x1000 events)")
    print(f"  Median: {disabled_results['median_ms']:.3f} ms | p95: {disabled_results['p95_ms']:.3f} ms")
    print(f"Condition: ENABLED (5x1000 events)")
    print(f"  Median: {enabled_results['median_ms']:.3f} ms | p95: {enabled_results['p95_ms']:.3f} ms")
    print(f"Difference (Audit Cost):")
    print(f"  Median Cost: {diff_median:+.3f} ms")
    print(f"  p95 Cost:    {diff_p95:+.3f} ms")
    print("========================================================")

    # Print pure JSON output markers for extraction
    print("__JSON_START__")
    print(json.dumps(summary, indent=2))
    print("__JSON_END__")

if __name__ == "__main__":
    main()
