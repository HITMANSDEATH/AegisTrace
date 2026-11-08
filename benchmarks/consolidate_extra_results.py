"""Consolidate all extra evaluation results into extra_evaluation_results.json."""
try:
    from benchmarks.benchmark_safety import require_destructive
except ModuleNotFoundError:
    from benchmark_safety import require_destructive

import json
import os
import time

def main():
    require_destructive()
    exp_a = json.load(open("evaluation_results/exp_a_summary.json", encoding="utf-8"))
    exp_b = json.load(open("evaluation_results/exp_b_summary.json", encoding="utf-8"))
    exp_c = json.load(open("evaluation_results/exp_c_summary.json", encoding="utf-8"))
    exp_d = json.load(open("evaluation_results/exp_d_summary.json", encoding="utf-8"))
    exp_e = json.load(open("evaluation_results/exp_e_summary.json", encoding="utf-8"))
    exp_f = json.load(open("evaluation_results/exp_f_summary.json", encoding="utf-8"))

    consolidated = {
        "metadata": {
            "title": "AegisTrace Additional Empirical Systems and Security Evaluation",
            "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "environment": {
                "os": "Windows 11 Pro (WSL2 Debian 12 containers)",
                "docker_version": "29.8.0, build 88096ef",
                "python_host": "3.13.7",
                "python_container": "3.12",
                "services": [
                    "aegistrace-agent_service-1",
                    "aegistrace-audit_service-1",
                    "aegistrace-reconstruction_service-1",
                    "aegistrace-frontend-1",
                    "aegistrace-groq_proxy-1"
                ]
            }
        },
        "experiment_a_multi_entry_tamper_detection": exp_a,
        "experiment_b_bearer_token_compromise_and_forgery": exp_b,
        "experiment_c_concurrent_ingestion_and_load": exp_c,
        "experiment_d_bounded_queue_pressure_and_overflow": exp_d,
        "experiment_e_audit_sink_downtime_and_recovery": exp_e,
        "experiment_f_malformed_event_and_schema_validation": exp_f
    }

    with open("evaluation_results/extra_evaluation_results.json", "w", encoding="utf-8") as f:
        json.dump(consolidated, f, indent=2)

    print("Saved evaluation_results/extra_evaluation_results.json successfully.")

if __name__ == "__main__":
    main()
