"""Extended E3: Concurrency Scaling, Contention Analysis, and Ledger Reconciliation.
Evaluates:
- Tiers C in {1, 5, 10, 25, 50, 100, 200}
- 100 events per worker to a dedicated session, single attempt (no retries)
- 10 runs per tier, resetting database and restarting services between runs
- Records: requests sent, HTTP 200, HTTP 503, other errors, stored entries, throughput, p50/p95/p99 latency
- Reconciles every session: verifies accepted == stored, no 503 stored, session chain_intact
"""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import csv
import json
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
    session_id = f"e3-c{c}-r{run_idx}-w{worker_id:03d}"
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

def run_e3_suite():
    require_destructive("http://127.0.0.1:8002", docker=True, agent=True)
    os.makedirs("results/raw", exist_ok=True)
    os.makedirs("results/logs", exist_ok=True)
    log_file = open("results/logs/e3_concurrency.log", "w", encoding="utf-8")

    def log(msg):
        print(msg)
        log_file.write(msg + "\n")
        log_file.flush()

    log("=== Starting Extended Experiment E3: RQ3a Concurrency Scaling (1 to 200 workers) ===")

    tiers = [1, 5, 10, 25, 50, 100, 200]
    runs_per_tier = 10
    reconstruction_url = "http://127.0.0.1:8002"
    require_destructive(reconstruction_url)

    all_run_summaries = []
    all_session_reconciliations = []

    req_csv_path = "results/raw/e3_concurrency_requests.csv"
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
            accepted_not_stored_count = 0
            locked_was_stored_count = 0

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
                except Exception:
                    is_intact = False

                if is_intact:
                    sessions_verified_intact += 1
                else:
                    sessions_verified_failed += 1

                discrepancy = s_accepted - s_stored
                if discrepancy > 0:
                    accepted_not_stored_count += discrepancy
                elif discrepancy < 0:
                    locked_was_stored_count += abs(discrepancy)

                all_session_reconciliations.append({
                    "concurrency": c,
                    "run": r,
                    "session_id": sid,
                    "submitted": s_submitted,
                    "accepted": s_accepted,
                    "db_locked_503": s_503,
                    "stored": s_stored,
                    "discrepancy": discrepancy,
                    "chain_intact": is_intact
                })

            run_summary = {
                "concurrency": c,
                "run": r,
                "workers": c,
                "requests_sent": total_sent,
                "http_200_count": accepted,
                "http_503_count": db_locked_503,
                "other_errors_count": other_errs,
                "stored_entries": actual_total_stored,
                "duration_sec": round(duration_s, 3),
                "throughput_ev_per_s": round(throughput, 2),
                "p50_ms": round(p50, 3),
                "p95_ms": round(p95, 3),
                "p99_ms": round(p99, 3),
                "sessions_total": len(unique_sids),
                "sessions_intact": sessions_verified_intact,
                "sessions_failed": sessions_verified_failed,
                "accepted_not_stored": accepted_not_stored_count,
                "locked_stored": locked_was_stored_count
            }
            all_run_summaries.append(run_summary)
            log(f"  [Run {r}] Sent={total_sent}, 200={accepted}, 503={db_locked_503}, Stored={actual_total_stored}, Dur={duration_s:.2f}s, Tput={throughput:.1f} ev/s, p50={p50:.2f}ms, p95={p95:.2f}ms, Intact={sessions_verified_intact}/{len(unique_sids)}")

    req_csv_file.close()

    # Save summaries
    summary_csv_path = "results/raw/e3_concurrency_runs.csv"
    with open(summary_csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(all_run_summaries[0].keys()))
        w.writeheader()
        w.writerows(all_run_summaries)

    recon_csv_path = "results/raw/e3_session_reconciliation.csv"
    with open(recon_csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(all_session_reconciliations[0].keys()))
        w.writeheader()
        w.writerows(all_session_reconciliations)

    tier_aggregates = {}
    for c in tiers:
        runs = [s for s in all_run_summaries if s["concurrency"] == c]
        total_reqs = sum(s["requests_sent"] for s in runs)
        total_200 = sum(s["http_200_count"] for s in runs)
        total_503 = sum(s["http_503_count"] for s in runs)
        total_stored = sum(s["stored_entries"] for s in runs)
        avg_tput = sum(s["throughput_ev_per_s"] for s in runs) / len(runs)
        avg_p50 = sum(s["p50_ms"] for s in runs) / len(runs)
        avg_p95 = sum(s["p95_ms"] for s in runs) / len(runs)
        avg_p99 = sum(s["p99_ms"] for s in runs) / len(runs)
        tot_sessions = sum(s["sessions_total"] for s in runs)
        tot_intact = sum(s["sessions_intact"] for s in runs)
        tot_discrepancy = sum(s["accepted_not_stored"] + s["locked_stored"] for s in runs)

        tier_aggregates[f"C_{c}"] = {
            "concurrency": c,
            "runs": len(runs),
            "total_requests": total_reqs,
            "total_accepted_200": total_200,
            "total_locked_503": total_503,
            "failure_rate_pct": (total_503 / total_reqs) * 100 if total_reqs > 0 else 0.0,
            "total_stored_entries": total_stored,
            "reconciliation_discrepancy": tot_discrepancy,
            "avg_throughput_ev_s": round(avg_tput, 2),
            "mean_p50_ms": round(avg_p50, 3),
            "mean_p95_ms": round(avg_p95, 3),
            "mean_p99_ms": round(avg_p99, 3),
            "total_sessions": tot_sessions,
            "sessions_verified_intact": tot_intact,
            "verification_intact_pct": (tot_intact / tot_sessions) * 100 if tot_sessions > 0 else 0.0
        }

    final_e3_summary = {
        "configured_busy_timeout_ms": 5000,
        "journal_mode": "DELETE",
        "serialization_mechanism": "BEGIN IMMEDIATE in audit/main.py",
        "optional_extension_busy_timeout_configurable": False,
        "note_on_extension": "busy_timeout is hardcoded at 5000ms in audit/main.py:37; not configurable via env vars. Skipped per Rule 1.",
        "tier_aggregates": tier_aggregates
    }

    with open("results/raw/e3_summary.json", "w", encoding="utf-8") as f:
        json.dump(final_e3_summary, f, indent=2)

    log("\n=== Extended Experiment E3 Complete ===")
    log_file.close()

if __name__ == "__main__":
    run_e3_suite()
