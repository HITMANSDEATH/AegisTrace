from __future__ import annotations

"""Best-effort, ordered audit capture for the agent.

The agent deliberately does not make ingestion part of the chat critical path.  A
single bounded worker drains this FIFO, which preserves event order without
creating one thread per event (or retrying an event and risking duplicates).
"""

import json
import os
import queue
import threading
import time
from typing import Any, Callable


class AuditCapture:
    """Non-blocking bounded FIFO audit sink.

    ``sink`` is injectable for tests and is called by the worker, never by
    :meth:`capture`.  When omitted, events are POSTed to the configured audit
    service.  Exceptions are intentionally swallowed: audit availability must
    not change the agent's response.
    """

    def __init__(
        self,
        sink: Callable[[dict[str, Any]], Any] | None = None,
        *,
        audit_url: str | None = None,
        token: str | None = None,
        maxsize: int = 512,
        timeout: float = 2.0,
        autostart: bool = False,
    ) -> None:
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=max(1, int(maxsize)))
        self._sink = sink
        self.audit_url = audit_url or os.getenv("AUDIT_SINK_URL", "http://audit_service:8001/ingest")
        self.token = token or os.getenv("AUDIT_WRITE_TOKEN")
        self.timeout = float(timeout)
        self._stop = threading.Event()
        self._closed = False
        self._thread: threading.Thread | None = None
        self._start_lock = threading.Lock()
        self._session_seq: dict[str, int] = {}
        self._seq_lock = threading.Lock()
        if autostart:
            self.start()

    def start(self) -> None:
        with self._start_lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name="aegis-audit-capture", daemon=True)
            self._thread.start()

    @property
    def pending(self) -> int:
        return self._queue.qsize()

    def capture(
        self,
        *,
        session_id: str,
        event_type: str,
        payload: dict[str, Any],
        sensitive_action_flag: bool = False,
        timestamp: float | None = None,
        client_seq: int | None = None,
    ) -> bool:
        """Queue an event without waiting for the sink.

        A false return means the bounded queue was full (or the capture was
        closed).  The caller should never retry it synchronously.
        """
        if self._closed:
            return False
        if self._thread is None:
            self.start()
        with self._seq_lock:
            if client_seq is not None:
                seq = int(client_seq)
                if seq > self._session_seq.get(session_id, 0):
                    self._session_seq[session_id] = seq
            else:
                self._session_seq[session_id] = self._session_seq.get(session_id, 0) + 1
                seq = self._session_seq[session_id]
        event = {
            "client_seq": seq,
            "event_type": event_type,
            "session_id": session_id,
            "payload": dict(payload),
            "sensitive_action_flag": bool(sensitive_action_flag),
            "timestamp": float(time.time() if timestamp is None else timestamp),
        }
        try:
            self._queue.put_nowait(event)
            return True
        except queue.Full:
            return False

    def _run(self) -> None:
        while not self._stop.is_set() or not self._queue.empty():
            try:
                event = self._queue.get(timeout=0.05)
            except queue.Empty:
                continue
            try:
                if self._sink is not None:
                    self._sink(event)
                else:
                    self._post(event)
            except Exception:
                # Best effort is explicit.  Do not leak network/serialization
                # failures into the request thread or log prompts/payloads.
                pass
            finally:
                self._queue.task_done()

    def _post(self, event: dict[str, Any]) -> None:
        # Import lazily so app import and unit tests have no network side effect.
        import httpx

        headers = {"content-type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        with httpx.Client(timeout=self.timeout, trust_env=False) as client:
            response = client.post(self.audit_url, json=event, headers=headers)
            response.raise_for_status()

    def close(self, *, drain: bool = False) -> None:
        self._closed = True
        if drain:
            try:
                self._queue.join()
            except Exception:
                pass
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=max(0.1, self.timeout + 0.2))

    def __enter__(self) -> "AuditCapture":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
