"""V2 Concurrency Scaling Benchmark: C in {1, 5, 10, 25, 50, 100, 200}, 3 trials each.
Evaluates:
- High concurrency load against audit_service /ingest with schema v2 client_seq.
- Records requests, accepted, HTTP status counts (200, 503, timeouts, errors).
- Verifies per-session missing_events_total via reconstruction /api/session/{sid}/verify.
- Checks whether sum(missing_events_total) == failed_requests.
Saves to results/raw_v2/ and results/logs_v2/.
"""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import concurrent.futures
import csv
import json
import math
import os
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from benchmarks.eval_common import reset_ledger_and_restart_services

TIER_RUNNER_TEMPLATE = """
import concurrent.futures
import json
import os
import time
import httpx

EVENT_TYPES = ['state_transition', 'tool_start', 'retrieval', 'tool_end']

def run_worker_task(worker_id, c, run_idx, events_per_worker, audit_url, token):
    session_id = f"v2-c{c}-r{run_idx}-w{worker_id:03d}"
    client = httpx.Client(timeout=25.0, trust_env=False)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    req_records = []
    base_time = 1710500000.0 + worker_id * 100.0
    
    for i in range(1, events_per_worker + 1):
        ts = base_time + i * 1.0
        etype = EVENT_TYPES[(i - 1) % len(EVENT_TYPES)]
        body = {
            "session_id": session_id,
            "client_seq": i,
            "timestamp": ts,
            "event_type": etype,
            "payload": {"step": i, "worker": worker_id, "load_test": True},
            "sensitive_action_flag": (i % 10 == 0)
        }
        t0 = time.perf_counter_ns()
        status = None
        err = None
        try:
            resp = client.post(audit_url, json=body, headers=headers)
            t1 = time.perf_counter_ns()
            status = resp.status_code
            if status != 200:
                err = f"HTTP_{status}"
        except httpx.TimeoutException:
            t1 = time.perf_counter_ns()
            err = "TimeoutException"
        except Exception as e:
            t1 = time.perf_counter_ns()
            err = type(e).__name__
        
        elapsed_ms = (t1 - t0) / 1_000_000.0
        req_records.append({
            "concurrency": c,
            "run": run_idx,
            "worker_id": worker_id,
            "session_id": session_id,
            "step": i,
            "status_code": status,
            "error_type": err,
            "latency_ms": elapsed_ms
        })
    client.close()
    return req_records

def main():
    c = __CONCURRENCY__
    run_idx = __RUN_IDX__
    events_per_worker = 100
    token = require_token()
    audit_url = os.environ.get("AUDIT_SINK_URL", "http://audit_service:8001/ingest")
    require_destructive(audit_url)

    t_start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=c) as executor:
        futures = [executor.submit(run_worker_task, wid, c, run_idx, events_per_worker, audit_url, token) for wid in range(c)]
        records = []
        for f in concurrent.futures.as_completed(futures):
            records.extend(f.result())
    duration_s = time.perf_counter() - t_start

    print("__RESULT_START__")
    print(json.dumps({"records": records, "duration": duration_s}))
    print("__RESULT_END__")

if __name__ == "__main__":
    main()
"""

def run_v2_concurrency_suite():
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    os.makedirs("results/raw_v2", exist_ok=True)
    os.makedirs("results/logs_v2", exist_ok=True)
    log_file = open("results/logs_v2/e3_concurrency.log", "w", encoding="utf-8")

    def log(msg):
        print(msg)
        log_file.write(msg + "\n")
        log_file.flush()

    log("=== Starting V2 Concurrency Scaling Benchmark (C in {1, 5, 10, 25, 50, 100, 200}, 3 trials each) ===")

    tiers = [1, 5, 10, 25, 50, 100, 200]
    runs_per_tier = 3
    reconstruction_url = "http://127.0.0.1:8002"
    require_destructive(reconstruction_url)

    all_run_summaries = []
    all_session_reconciliations = []

    req_csv_path = "results/raw_v2/e3_concurrency_requests.csv"
    req_csv_file = open(req_csv_path, "w", newline="", encoding="utf-8")
    req_writer = None

    for c in tiers:
        log(f"\n========================================================")
        log(f"--- Tier C={c} Workers ({c * 100} reqs/run x {runs_per_tier} runs = {c * 100 * runs_per_tier} total) ---")
        log(f"========================================================")

        for r in range(1, runs_per_tier + 1):
            log(f"\n[Tier C={c}, Run {r}/{runs_per_tier}] Resetting DB & Restarting Services...")
            reset_ledger_and_restart_services()

            runner_code = TIER_RUNNER_TEMPLATE.replace("__CONCURRENCY__", str(c)).replace("__RUN_IDX__", str(r))

            proc = subprocess.run(
                ["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-agent_service-1", "python", "-"],
                input=guarded_python(runner_code),
                text=True,
                capture_output=True,
                check=True
            )
            raw_out = proc.stdout.strip()
            s_idx = raw_out.find("__RESULT_START__")
            e_idx = raw_out.find("__RESULT_END__")
            if s_idx == -1 or e_idx == -1:
                log(f"Error in runner output: {raw_out}\nStderr: {proc.stderr}")
                raise RuntimeError("Failed to parse runner output")

            payload = json.loads(raw_out[s_idx + len("__RESULT_START__"):e_idx].strip())
            records = payload["records"]
            duration_s = payload["duration"]

            if req_writer is None:
                req_writer = csv.DictWriter(req_csv_file, fieldnames=list(records[0].keys()))
                req_writer.writeheader()
            req_writer.writerows(records)
            req_csv_file.flush()

            total_sent = len(records)
            accepted = sum(1 for rec in records if rec["status_code"] == 200)
            db_locked_503 = sum(1 for rec in records if rec["status_code"] == 503)
            other_errs = total_sent - accepted - db_locked_503

            latencies = sorted(rec["latency_ms"] for rec in records)
            p50 = latencies[int(len(latencies) * 0.50)]
            p95 = latencies[min(int(len(latencies) * 0.95), len(latencies) - 1)]
            p99 = latencies[min(int(len(latencies) * 0.99), len(latencies) - 1)]
            throughput = accepted / duration_s if duration_s > 0 else 0.0

            # Session-level reconciliation: check actual SQLite count per session
            chk_proc = subprocess.run(
                ["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"],
                input=guarded_python("""
import sqlite3, json
conn = sqlite3.connect('/data/audit.db')
rows = conn.execute("SELECT session_id, count(id) FROM audit_log GROUP BY session_id").fetchall()
conn.close()
print(json.dumps(dict(rows)))
"""),
                text=True,
                capture_output=True,
                check=True
            )
            stored_counts_by_session = json.loads(chk_proc.stdout.strip())
            actual_total_stored = sum(stored_counts_by_session.values())

            unique_sids = sorted(list(set(rec["session_id"] for rec in records)))
            sessions_verified_intact = 0
            sessions_verified_failed = 0
            run_missing_events_total = 0

            for sid in unique_sids:
                s_recs = [rec for rec in records if rec["session_id"] == sid]
                s_submitted = len(s_recs)
                s_accepted = sum(1 for rec in s_recs if rec["status_code"] == 200)
                s_503 = sum(1 for rec in s_recs if rec["status_code"] == 503)
                s_stored = stored_counts_by_session.get(sid, 0)

                url = f"{reconstruction_url}/api/session/{sid}/verify"
                try:
                    with urllib.request.urlopen(url) as resp:
                        vdata = json.loads(resp.read().decode())
                        is_intact = vdata.get("chain_intact", False)
                        s_missing = vdata.get("missing_events_total", 0)
                        s_seq_complete = vdata.get("sequence_complete", False)
                except Exception:
                    is_intact = False
                    s_missing = 0
                    s_seq_complete = False

                if is_intact:
                    sessions_verified_intact += 1
                else:
                    sessions_verified_failed += 1

                run_missing_events_total += s_missing

                all_session_reconciliations.append({
                    "concurrency": c,
                    "run": r,
                    "session_id": sid,
                    "submitted": s_submitted,
                    "accepted_200": s_accepted,
                    "rejected_503": s_503,
                    "stored_in_sqlite": s_stored,
                    "missing_events_total": s_missing,
                    "sequence_complete": s_seq_complete,
                    "chain_intact": is_intact
                })

            failed_requests = total_sent - accepted
            sum_matches_failed = (run_missing_events_total == failed_requests)

            run_summary = {
                "concurrency": c,
                "run": r,
                "duration_s": duration_s,
                "total_sent": total_sent,
                "accepted_200": accepted,
                "db_locked_503": db_locked_503,
                "other_errors": other_errs,
                "failed_requests": failed_requests,
                "actual_total_stored": actual_total_stored,
                "run_missing_events_total": run_missing_events_total,
                "missing_equals_failed": sum_matches_failed,
                "sessions_verified_intact": sessions_verified_intact,
                "sessions_verified_failed": sessions_verified_failed,
                "throughput_eps": throughput,
                "p50_latency_ms": p50,
                "p95_latency_ms": p95,
                "p99_latency_ms": p99
            }
            all_run_summaries.append(run_summary)
            log(f"Run {r} Result: Sent={total_sent}, Accepted={accepted}, 503={db_locked_503}, Stored={actual_total_stored}, "
                f"MissingTotal={run_missing_events_total}, Missing==Failed: {sum_matches_failed}, "
                f"Throughput={throughput:.1f} eps, p50={p50:.1f}ms, p95={p95:.1f}ms, VerifiedIntact={sessions_verified_intact}/{c}")

    req_csv_file.close()

    # Write Run Summaries CSV
    runs_csv_path = "results/raw_v2/e3_concurrency_runs.csv"
    with open(runs_csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(all_run_summaries[0].keys()))
        w.writeheader()
        w.writerows(all_run_summaries)

    # Write Session Reconciliation CSV
    recon_csv_path = "results/raw_v2/e3_session_reconciliation.csv"
    with open(recon_csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(all_session_reconciliations[0].keys()))
        w.writeheader()
        w.writerows(all_session_reconciliations)

    # Compute Tier Summaries & JSON
    tier_aggregates = {}
    for c in tiers:
        c_runs = [r for r in all_run_summaries if r["concurrency"] == c]
        tier_aggregates[str(c)] = {
            "workers": c,
            "runs": len(c_runs),
            "total_sent": sum(r["total_sent"] for r in c_runs),
            "accepted_200": sum(r["accepted_200"] for r in c_runs),
            "db_locked_503": sum(r["db_locked_503"] for r in c_runs),
            "other_errors": sum(r["other_errors"] for r in c_runs),
            "failed_requests": sum(r["failed_requests"] for r in c_runs),
            "missing_events_total": sum(r["run_missing_events_total"] for r in c_runs),
            "missing_equals_failed_all_runs": all(r["missing_equals_failed"] for r in c_runs),
            "mean_throughput": sum(r["throughput_eps"] for r in c_runs) / len(c_runs),
            "mean_p50_latency_ms": sum(r["p50_latency_ms"] for r in c_runs) / len(c_runs),
            "mean_p95_latency_ms": sum(r["p95_latency_ms"] for r in c_runs) / len(c_runs)
        }

    summary_json_path = "results/raw_v2/e3_summary.json"
    with open(summary_json_path, "w", encoding="utf-8") as f:
        json.dump(tier_aggregates, f, indent=2)

    log("\n================ CONCURRENCY RESULTS SUMMARY ================")
    log(f"{'Tier C':<8} {'Sent':<8} {'Accepted':<10} {'503 Lock':<10} {'MissingTot':<12} {'Missing==Fail':<14} {'Mean Throughput':<16} {'Mean p50 (ms)':<14}")
    log("-" * 88)
    for c_str, agg in tier_aggregates.items():
        log(f"{agg['workers']:<8} {agg['total_sent']:<8} {agg['accepted_200']:<10} {agg['db_locked_503']:<10} "
            f"{agg['missing_events_total']:<12} {str(agg['missing_equals_failed_all_runs']):<14} "
            f"{agg['mean_throughput']:<16.1f} {agg['mean_p50_latency_ms']:<14.1f}")

    log(f"\nAll files saved in results/raw_v2/:")
    log(f"  {req_csv_path}")
    log(f"  {runs_csv_path}")
    log(f"  {recon_csv_path}")
    log(f"  {summary_json_path}")

if __name__ == "__main__":
    run_v2_concurrency_suite()
