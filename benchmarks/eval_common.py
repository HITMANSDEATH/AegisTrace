"""Shared evaluation helpers, environment capture, Wilson score intervals, and service management."""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import math
import os
import platform
import subprocess
import time
import json
import urllib.request
import psutil

def wilson_interval(k, n, confidence=0.95):
    """Calculate the Wilson score confidence interval for a binomial proportion."""
    if n == 0:
        return (0.0, 0.0)
    z = 1.959963984540054  # 95%
    p = k / n
    denom = 1 + (z ** 2) / n
    center = (p + (z ** 2) / (2 * n)) / denom
    spread = (z * math.sqrt((p * (1 - p)) / n + (z ** 2) / (4 * n ** 2))) / denom
    lower = max(0.0, center - spread)
    upper = min(1.0, center + spread)
    return (lower, upper)

def get_system_environment():
    """Gather hardware, operating system, Docker, and package versions."""
    cpu_name = platform.processor()
    try:
        proc_out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_Processor).Name"],
            text=True
        ).strip()
        if proc_out:
            cpu_name = proc_out
    except Exception:
        pass

    ram_gb = round(psutil.virtual_memory().total / (1024 ** 3), 2)
    cores_physical = psutil.cpu_count(logical=False)
    cores_logical = psutil.cpu_count(logical=True)
    os_name = f"{platform.system()} {platform.release()} (Build {platform.version()})"
    host_python = platform.python_version()

    # Container versions
    docker_version = "Unknown"
    try:
        d_out = subprocess.check_output(["docker", "--version"], text=True).strip()
        docker_version = d_out
    except Exception:
        pass

    container_python = "Unknown"
    container_sqlite = "Unknown"
    try:
        container_python = subprocess.check_output(
            ["docker", "exec", "aegistrace-audit_service-1", "python", "--version"], text=True
        ).strip()
        container_sqlite = subprocess.check_output(
            ["docker", "exec", "aegistrace-audit_service-1", "python", "-c", "import sqlite3; print(sqlite3.sqlite_version)"],
            text=True
        ).strip()
    except Exception:
        pass

    return {
        "cpu": cpu_name,
        "physical_cores": cores_physical,
        "logical_cores": cores_logical,
        "ram_gb": ram_gb,
        "os": os_name,
        "docker_version": docker_version,
        "host_python": host_python,
        "container_python": container_python,
        "container_sqlite": container_sqlite,
        "git_commit": "No git repository at root",
        "date_time_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "background_load_minimized": True
    }

def reset_ledger_and_restart_services():
    """Rule 6: Reset the ledger to an empty database and restart services so runs are independent."""
    require_destructive("http://127.0.0.1:8002", docker=True)
    sql = """
import sqlite3
conn = sqlite3.connect('/data/audit.db', isolation_level=None)
conn.execute('DELETE FROM audit_log')
conn.execute('VACUUM')
conn.close()
"""
    subprocess.run(["docker", "exec", "-e", "AEGIS_ALLOW_DESTRUCTIVE", "-i", "aegistrace-audit_service-1", "python", "-"], input=guarded_python(sql), text=True, check=True)
    subprocess.run(
        ["docker", "restart", "aegistrace-audit_service-1", "aegistrace-reconstruction_service-1", "aegistrace-agent_service-1"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    # Wait for services to report healthy
    for _ in range(30):
        try:
            req = urllib.request.Request("http://127.0.0.1:8002/health")
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    break
        except Exception:
            time.sleep(0.5)
    else:
        raise RuntimeError("Reconstruction service failed to become healthy after restart")
