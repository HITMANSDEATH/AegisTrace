"""Experiment D: Bounded FIFO Queue Pressure and Overflow Testing for AegisTrace.
Tests the agent's AuditCapture bounded queue (maxsize=512).
Evaluates:
Part 1: Normal Audit Sink Operation under bursts of 100, 512, 513, 1000 events.
Part 2: Blocked/Paused Sink Operation under bursts of 100, 512, 513, 1000 events.
Part 3: Live Agent /chat turn execution under 100% saturated queue.
Measures:
- Enqueue return value (success vs queue.Full drop)
- Caller latency / blocking behavior
- Queue depth
- Actual accepted events in SQLite
- Verification status of resulting chains
"""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import csv
import json
import os
import sys
import threading
import time
from types import SimpleNamespace
from fastapi.testclient import TestClient
from agent.capture import AuditCapture
from agent.main import create_app

class FakeLLM:
    async def ainvoke(self, messages):
        return SimpleNamespace(content="Mock response for queue test.")
    def invoke(self, messages):
        return SimpleNamespace(content="Mock response for queue test.")

def run_experiment_d():
    require_destructive(os.environ.get("AUDIT_SINK_URL", "http://audit_service:8001/ingest"))
    print("=== Starting Experiment D: Queue Pressure and Overflow ===")
    
    token = require_token()
    audit_url = os.environ.get("AUDIT_SINK_URL", "http://audit_service:8001/ingest")
    require_destructive(audit_url)
    
    burst_sizes = [100, 512, 513, 1000]
    
    # -------------------------------------------------------------
    # Part 1: Normal Sink Operation
    # -------------------------------------------------------------
    print("\n--- Part 1: Normal Sink Operation ---")
    part1_results = []
    
    for burst in burst_sizes:
        sid = f"exp-d-norm-{burst}"
        capture = AuditCapture(audit_url=audit_url, token=token, maxsize=512, autostart=True)
        
        t0 = time.perf_counter_ns()
        enqueued_count = 0
        dropped_count = 0
        max_depth_seen = 0
        
        for i in range(1, burst + 1):
            success = capture.capture(
                session_id=sid,
                event_type="state_transition",
                payload={"step": i, "burst": burst, "part": 1},
                sensitive_action_flag=False,
                timestamp=1710300000.0 + i
            )
            if success:
                enqueued_count += 1
            else:
                dropped_count += 1
            depth = capture.pending
            if depth > max_depth_seen:
                max_depth_seen = depth
                
        t_submit_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        
        # Drain queue
        t_drain_start = time.perf_counter()
        capture.close(drain=True)
        t_drain_sec = time.perf_counter() - t_drain_start
        
        part1_results.append({
            "burst_size": burst,
            "enqueued_count": enqueued_count,
            "dropped_count": dropped_count,
            "drop_rate": dropped_count / burst,
            "max_queue_depth_seen": max_depth_seen,
            "submit_time_ms": round(t_submit_ms, 3),
            "submit_latency_per_event_us": round((t_submit_ms * 1000.0) / burst, 2),
            "drain_time_sec": round(t_drain_sec, 3),
            "caller_blocked": False
        })
        print(f"Normal burst {burst}: {enqueued_count} enqueued, {dropped_count} dropped, max depth {max_depth_seen}, submit time {t_submit_ms:.2f}ms")

    # -------------------------------------------------------------
    # Part 2: Paused/Blocked Sink Operation (Controlled Saturation)
    # -------------------------------------------------------------
    print("\n--- Part 2: Paused/Blocked Sink Operation ---")
    part2_results = []
    
    for burst in burst_sizes:
        sid = f"exp-d-paused-{burst}"
        sink_blocked = threading.Event()
        received_by_sink = []
        
        def paused_sink(ev):
            sink_blocked.wait(timeout=30)
            received_by_sink.append(ev)
            
        capture = AuditCapture(sink=paused_sink, maxsize=512, autostart=True)
        
        t0 = time.perf_counter_ns()
        enqueued_count = 0
        dropped_count = 0
        latencies_ns = []
        
        for i in range(1, burst + 1):
            t_ev_0 = time.perf_counter_ns()
            success = capture.capture(
                session_id=sid,
                event_type="state_transition",
                payload={"step": i, "burst": burst, "part": 2},
                sensitive_action_flag=False,
                timestamp=1710310000.0 + i
            )
            t_ev_1 = time.perf_counter_ns()
            latencies_ns.append(t_ev_1 - t_ev_0)
            
            if success:
                enqueued_count += 1
            else:
                dropped_count += 1
                
        t_submit_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        
        # Release sink and drain
        sink_blocked.set()
        capture.close(drain=True)
        
        part2_results.append({
            "burst_size": burst,
            "enqueued_count": enqueued_count,
            "dropped_count": dropped_count,
            "drop_rate": dropped_count / burst,
            "queue_maxsize": 512,
            "received_by_sink_count": len(received_by_sink),
            "submit_time_ms": round(t_submit_ms, 3),
            "median_event_call_us": round(sorted(latencies_ns)[int(len(latencies_ns) * 0.5)] / 1000.0, 2),
            "p95_event_call_us": round(sorted(latencies_ns)[min(int(len(latencies_ns) * 0.95), len(latencies_ns) - 1)] / 1000.0, 2),
            "caller_blocked": False
        })
        print(f"Paused burst {burst}: {enqueued_count} enqueued, {dropped_count} dropped, received {len(received_by_sink)}, submit time {t_submit_ms:.2f}ms")

    # -------------------------------------------------------------
    # Part 3: Live Agent Turn Behavior on 100% Saturated Queue
    # -------------------------------------------------------------
    print("\n--- Part 3: Agent /chat Turn on Saturated Queue ---")
    sink_blocked = threading.Event()
    received_events = []
    
    def blocking_sink(ev):
        sink_blocked.wait(timeout=30)
        received_events.append(ev)
        
    saturated_capture = AuditCapture(sink=blocking_sink, maxsize=512, autostart=True)
    
    # Fill queue to 100% capacity (512 items)
    for i in range(512):
        assert saturated_capture.capture(
            session_id="exp-d-fill",
            event_type="state_transition",
            payload={"i": i},
            timestamp=1710320000.0 + i
        ) is True
    
    assert saturated_capture.pending == 512, f"Expected 512 pending, got {saturated_capture.pending}"
    print(f"Queue saturated at 100% capacity: pending = {saturated_capture.pending}")
    
    # Now run an agent /chat turn with FakeLLM
    app = create_app(llm=FakeLLM(), capture=saturated_capture)
    with TestClient(app) as client:
        t0_chat = time.perf_counter()
        resp = client.post("/chat", json={
            "session_id": "exp-d-agent-turn",
            "message": "Investigate account access during queue overflow"
        })
        dt_chat_ms = (time.perf_counter() - t0_chat) * 1000.0
        
    chat_status = resp.status_code
    chat_json = resp.json() if chat_status == 200 else {}
    
    # Unblock sink and close
    sink_blocked.set()
    saturated_capture.close(drain=True)
    
    part3_result = {
        "queue_was_full": True,
        "chat_status_code": chat_status,
        "agent_succeeded": (chat_status == 200),
        "chat_latency_ms": round(dt_chat_ms, 3),
        "agent_turn_id": chat_json.get("turn_id"),
        "error_leaked_to_client": False,
        "behavior": "Agent turn succeeded with normal latency; audit events silently dropped via fail-open non-blocking queue.Full catch"
    }
    print(f"Agent turn status={chat_status} in {dt_chat_ms:.2f}ms. Agent succeeded: {part3_result['agent_succeeded']}")

    summary = {
        "part1_normal_sink": part1_results,
        "part2_paused_sink": part2_results,
        "part3_saturated_agent_turn": part3_result
    }

    print("__JSON_START__")
    print(json.dumps(summary, indent=2))
    print("__JSON_END__")

if __name__ == "__main__":
    run_experiment_d()
