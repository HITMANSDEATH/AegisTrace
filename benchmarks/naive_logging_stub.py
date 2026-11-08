"""Naive Logging Stub (Baseline Comparison for AegisTrace Evaluation).

This module implements a naive, unhardened, in-process logging mechanism
representing a typical 'just log it' implementation:
- Synchronous write directly to a local SQLite table
- In-process execution blocking the agent request thread
- No cryptographic hash chaining
- No container / network isolation boundary
- No async background worker / FIFO queue
"""
try:
    from benchmarks.benchmark_safety import require_destructive, require_token, validate_target, guarded_python
except ModuleNotFoundError:  # Direct file execution or helper transported over Docker stdin.
    from benchmark_safety import require_destructive, require_token, validate_target, guarded_python

import json
import os
import sqlite3
import time

class NaiveLoggingStub:
    """Synchronous in-process SQLite logger with no isolation or hash chaining."""

    def __init__(self, db_path="/tmp/naive_audit_log.db"):
        require_destructive()
        self.db_path = db_path
        # Clean up any previous benchmark database file
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass
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
        """Synchronously persist the audit record into SQLite, blocking caller until commit completes."""
        ts = float(time.time() if timestamp is None else timestamp)
        # Serialize payload directly to JSON without canonical hashing
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

    def start(self) -> None:
        """No background thread to start; synchronous in-process logging."""
        pass

    def close(self, **kwargs) -> None:
        """Close database connection."""
        try:
            self.conn.close()
        except Exception:
            pass
