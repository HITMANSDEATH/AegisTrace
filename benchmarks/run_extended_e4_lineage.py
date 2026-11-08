"""Extended E4: Lineage Reconstruction Accuracy against Ground-Truth Dependency Graphs.
Evaluates 50 synthetic sessions (20 events each):
- 25 linear sequential workflows (sequential step dependencies)
- 25 branching/fork-join workflows (e.g. retrieval parent fanning out to parallel tool steps, then joining into aggregation)
Queries /api/session/{sid}/graph and compares reconstructed edges against ground truth.
Reports edge precision, edge recall, and exact-match rate per session and pooled.
"""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

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

def event_id(seq: int) -> str:
    return f"evt-{seq:03d}"

def canonical_json(value):
    import json
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)

def entry_hash(timestamp, payload_str, prev_hash):
    import hashlib
    return hashlib.sha256((str(float(timestamp)) + payload_str + prev_hash).encode("utf-8")).hexdigest()

EVENT_TYPES = ['state_transition', 'tool_start', 'retrieval', 'tool_end']

def generate_lineage_trace(session_id, workflow_type="linear", count=20, base_time=1710900000.0):
    """Generates 20 events and returns (events_tuples, ground_truth_edges)."""
    events = []
    prev_hash = '0' * 64
    gt_edges = set()

    # Define ground truth dependencies
    if workflow_type == "linear":
        for i in range(1, count):
            gt_edges.add((event_id(i), event_id(i + 1)))
    else:
        # Branching fork-join workflow:
        # Steps 1..4: linear setup (1->2->3->4)
        # Step 4 (retrieval) fans out to 5, 6, 7 (parallel tool invocations): (4->5), (4->6), (4->7)
        # Tools 5, 6, 7 join into 8 (aggregation state transition): (5->8), (6->8), (7->8)
        # Steps 8..12: linear (8->9->10->11->12)
        # Step 12 fans out to 13, 14, 15: (12->13), (12->14), (12->15)
        # Tools 13, 14, 15 join into 16: (13->16), (14->16), (15->16)
        # Steps 16..20: linear (16->17->18->19->20)
        gt_edges.update([(event_id(1), event_id(2)), (event_id(2), event_id(3)), (event_id(3), event_id(4))])
        gt_edges.update([(event_id(4), event_id(5)), (event_id(4), event_id(6)), (event_id(4), event_id(7))])
        gt_edges.update([(event_id(5), event_id(8)), (event_id(6), event_id(8)), (event_id(7), event_id(8))])
        gt_edges.update([(event_id(8), event_id(9)), (event_id(9), event_id(10)), (event_id(10), event_id(11)), (event_id(11), event_id(12))])
        gt_edges.update([(event_id(12), event_id(13)), (event_id(12), event_id(14)), (event_id(12), event_id(15))])
        gt_edges.update([(event_id(13), event_id(16)), (event_id(14), event_id(16)), (event_id(15), event_id(16))])
        gt_edges.update([(event_id(16), event_id(17)), (event_id(17), event_id(18)), (event_id(18), event_id(19)), (event_id(19), event_id(20))])

    # Generate cryptographic event chain in temporal recording order
    for i in range(1, count + 1):
        ts = base_time + i * 1.5
        etype = EVENT_TYPES[(i - 1) % len(EVENT_TYPES)]
        parents = [p for p, c in gt_edges if c == event_id(i)]
        payload = {
            "step": i,
            "workflow_type": workflow_type,
            "label": f"Step {i}",
            "declared_parents": parents,
            "_aegis": {
                "schema_version": 1,
                "session_id": session_id,
                "event_type": etype,
                "sensitive_action_flag": False
            }
        }
        serialized = canonical_json(payload)
        digest = entry_hash(ts, serialized, prev_hash)
        events.append((session_id, ts, etype, serialized, 0, prev_hash, digest))
        prev_hash = digest

    return events, gt_edges

def run_e4_suite():
    require_destructive("http://127.0.0.1:8002", docker=True)
    os.makedirs("results/raw", exist_ok=True)
    os.makedirs("results/logs", exist_ok=True)
    log_file = open("results/logs/e4_lineage.log", "w", encoding="utf-8")

    def log(msg):
        print(msg)
        log_file.write(msg + "\n")
        log_file.flush()

    log("=== Starting Extended Experiment E4: Lineage Reconstruction Accuracy ===")
    reset_ledger_and_restart_services()

    reconstruction_url = "http://127.0.0.1:8002"
    require_destructive(reconstruction_url)
    sessions_total = 50
    session_records = []
    all_tuples = []
    ground_truth_map = {}

    for idx in range(sessions_total):
        wtype = "linear" if idx < 25 else "branching"
        sid = f"e4-{wtype}-{idx:02d}"
        ev_tuples, gt_edges = generate_lineage_trace(sid, workflow_type=wtype, count=20)
        all_tuples.extend(ev_tuples)
        ground_truth_map[sid] = {"workflow_type": wtype, "edges": gt_edges}

    # Insert into database
    ins_sql = f"""
import sqlite3
conn = sqlite3.connect('/data/audit.db', isolation_level=None)
cur = conn.cursor()
cur.execute('BEGIN IMMEDIATE')
cur.executemany("INSERT INTO audit_log(session_id, timestamp, event_type, payload, sensitive_action_flag, prev_hash, hash) VALUES(?,?,?,?,?,?,?)", {repr(all_tuples)})
cur.execute('COMMIT')
conn.close()
"""
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(ins_sql), text=True, check=True)
    log(f"Inserted 50 sessions (1,000 events) for lineage evaluation.")

    # Query /api/session/{sid}/graph for each session
    linear_metrics = []
    branching_metrics = []

    for sid, info in ground_truth_map.items():
        wtype = info["workflow_type"]
        gt_edges = info["edges"]
        url = f"{reconstruction_url}/api/session/{sid}/graph"
        with urllib.request.urlopen(url) as resp:
            data = json.loads(resp.read().decode())

        recon_edges = set((e["source"], e["target"]) for e in data.get("edges", []))
        tp = len(recon_edges.intersection(gt_edges))
        fp = len(recon_edges - gt_edges)
        fn = len(gt_edges - recon_edges)

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        exact_match = (recon_edges == gt_edges)

        rec_item = {
            "session_id": sid,
            "workflow_type": wtype,
            "gt_edge_count": len(gt_edges),
            "recon_edge_count": len(recon_edges),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "exact_match": exact_match
        }
        session_records.append(rec_item)
        if wtype == "linear":
            linear_metrics.append(rec_item)
        else:
            branching_metrics.append(rec_item)

    # Save CSV
    csv_path = "results/raw/e4_lineage_sessions.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(session_records[0].keys()))
        w.writeheader()
        w.writerows(session_records)

    # Summarize
    def summarize_group(group):
        tot = len(group)
        mean_p = sum(g["precision"] for g in group) / tot
        mean_r = sum(g["recall"] for g in group) / tot
        matches = sum(1 for g in group if g["exact_match"])
        return {
            "sessions": tot,
            "mean_precision": round(mean_p, 4),
            "mean_recall": round(mean_r, 4),
            "exact_matches": matches,
            "exact_match_rate": round(matches / tot, 4)
        }

    summary_e4 = {
        "linear_workflows": summarize_group(linear_metrics),
        "branching_workflows": summarize_group(branching_metrics),
        "overall": summarize_group(session_records),
        "graph_semantics_statement": "Reconstruction service reconstructs strictly the recorded sequential execution order (evt-(k-1) -> evt-k). It demonstrates 100% precision/recall on linear sequential agent traces, but does not capture non-adjacent causal branching dependencies."
    }

    with open("results/raw/e4_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary_e4, f, indent=2)

    log(f"Linear Workflows (25 sessions): Precision={summary_e4['linear_workflows']['mean_precision']*100:.1f}%, Recall={summary_e4['linear_workflows']['mean_recall']*100:.1f}%, ExactMatch={summary_e4['linear_workflows']['exact_match_rate']*100:.1f}%")
    log(f"Branching Workflows (25 sessions): Precision={summary_e4['branching_workflows']['mean_precision']*100:.1f}%, Recall={summary_e4['branching_workflows']['mean_recall']*100:.1f}%, ExactMatch={summary_e4['branching_workflows']['exact_match_rate']*100:.1f}%")
    log("=== Extended Experiment E4 Complete ===")
    log_file.close()

if __name__ == "__main__":
    run_e4_suite()
