"""Bounded real-process /health smoke; no .env, providers, or live databases.

Run with the repository's .venv/Scripts/python.exe. Only stdlib is needed by
this runner; the child processes use the installed application requirements.
"""
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener

APP = Path(__file__).resolve().parents[1]
ROOT = APP.parents[1]
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
STARTUP_TIMEOUT = 30


def isolated_environment(scratch, database):
    # Allowlist OS plumbing, not inherited keys, tracing, proxies, or app config.
    allowed = {"SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC", "PATH", "PATHEXT"}
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    env.update({
        "TEMP": str(scratch), "TMP": str(scratch), "TMPDIR": str(scratch),
        "HOME": str(scratch), "USERPROFILE": str(scratch),
        "PYTHONPATH": str(APP), "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1",
        "DB_PATH": str(database), "ANCHOR_DATA_DIR": str(scratch / "anchors"),
        "FRONTEND_DIR": str(APP / "frontend"),
        "DEMO_MODE": "false", "LLM_PROVIDER": "groq", "AGENT_MAX_SESSIONS": "2",
        "AUDIT_SINK_URL": "http://127.0.0.1:1/ingest",
        "ANCHOR_SINK_URL": "http://127.0.0.1:1/anchor", "ANCHOR_EVERY": "0",
        "ALLOWED_ORIGINS": "http://127.0.0.1", "AEGIS_API_BASE": "",
    })
    return env


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    else:
        process.wait()


def remove_tree(path, timeout=10):
    # Windows can retain a terminated child's inherited log handle briefly.
    deadline = time.monotonic() + timeout
    while path.exists():
        try:
            shutil.rmtree(path)
        except PermissionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


def check_service(module, scratch, env):
    log_path = scratch / (module.split(".")[0] + ".log")
    # Port zero lets the OS allocate an unused loopback port without a bind race.
    command = [str(PYTHON), "-m", "uvicorn", module, "--host", "127.0.0.1",
               "--port", "0", "--lifespan", "on", "--log-level", "info",
               "--no-access-log", "--timeout-graceful-shutdown", "5"]
    opener = build_opener(ProxyHandler({}))
    with log_path.open("wb") as log:
        process = subprocess.Popen(command, cwd=scratch, env=env,
                                   stdin=subprocess.DEVNULL, stdout=log,
                                   stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + STARTUP_TIMEOUT
            last_error = "server has not announced its port"
            while time.monotonic() < deadline:
                output = log_path.read_text(encoding="utf-8", errors="replace")
                if process.poll() is not None:
                    raise AssertionError(f"{module} exited with {process.returncode}\n{output}")
                match = re.search(r"Uvicorn running on http://127\.0\.0\.1:(\d+)", output)
                if match:
                    url = f"http://127.0.0.1:{match.group(1)}/health"
                    try:
                        with opener.open(url, timeout=1) as response:
                            assert response.status == 200, response.status
                            assert response.headers.get_content_type() == "application/json"
                            body = json.load(response)
                            assert body == {"status": "ok"}, body
                        print(f"PASS {module} GET /health: 200 {body}", flush=True)
                        return
                    except (URLError, TimeoutError) as error:
                        last_error = str(error)
                # Bounded readiness polling, not a fixed startup delay.
                time.sleep(0.05)
            raise AssertionError(f"{module} health deadline exceeded: {last_error}\n{output}")
        finally:
            stop(process)


def main():
    if not PYTHON.is_file() or not os.path.samefile(sys.executable, PYTHON):
        raise SystemExit(f"Run this smoke with {PYTHON}")
    # Keep even temporary files inside the workspace; delete them on every exit.
    scratch = Path(tempfile.mkdtemp(prefix="aegis-health-", dir=APP / "tests"))
    try:
        database = scratch / "audit.db"
        # /health only selects id. No audit service or ingestion is needed.
        connection = sqlite3.connect(database)
        try:
            connection.execute("CREATE TABLE audit_log (id INTEGER PRIMARY KEY)")
            connection.commit()
        finally:
            connection.close()
        before = database.read_bytes()
        env = isolated_environment(scratch, database)
        for module in ("agent.main:app", "reconstruction.main:app"):
            check_service(module, scratch, env)
        assert database.read_bytes() == before, "health checks changed the database"
    finally:
        remove_tree(scratch)
    assert not scratch.exists(), "smoke temporary directory was not removed"
    print("PASS both processes stopped; temporary files removed; database unchanged")


if __name__ == "__main__":
    main()
