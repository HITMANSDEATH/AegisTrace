"""Write-only authenticated audit sink. This app intentionally has exactly one route."""
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
import hmac
import os
import sqlite3
import threading
import time

from fastapi import FastAPI, Header, HTTPException, Depends
from pydantic import BaseModel, Field, ConfigDict
from common.hash import canonical_json, entry_hash

SCHEMA = '''
CREATE TABLE IF NOT EXISTS audit_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 session_id TEXT NOT NULL,
 timestamp REAL NOT NULL,
 event_type TEXT NOT NULL,
 payload TEXT NOT NULL,
 sensitive_action_flag BOOLEAN NOT NULL DEFAULT 0,
 prev_hash TEXT NOT NULL,
 hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_session_id ON audit_log(session_id,id);
'''

class IngestEvent(BaseModel):
    model_config = ConfigDict(allow_inf_nan=False, extra='forbid')
    client_seq: int = Field(strict=True, ge=1)
    event_type: Literal['retrieval','state_transition','tool_start','tool_end']
    session_id: str = Field(pattern=r'^[A-Za-z0-9_-]{1,96}$')
    payload: dict
    sensitive_action_flag: bool = False
    timestamp: float

def connect(path):
    conn = sqlite3.connect(str(path), timeout=5, isolation_level=None)
    conn.execute('PRAGMA busy_timeout=5000')
    return conn

def initialize(path=None):
    path = Path(path or os.getenv('DB_PATH','/data/audit.db'))
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    try:
        conn.execute('PRAGMA journal_mode=DELETE')
        conn.executescript(SCHEMA)
    finally:
        conn.close()

def create_app(db_path=None):
    path = Path(db_path or os.getenv('DB_PATH','/data/audit.db'))
    @asynccontextmanager
    async def lifespan(app):
        if not os.getenv('AUDIT_WRITE_TOKEN'):
            raise RuntimeError('AUDIT_WRITE_TOKEN must be configured')
        initialize(path)
        yield
    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    def authorize(authorization: str | None = Header(default=None)):
        expected = os.getenv('AUDIT_WRITE_TOKEN','')
        if not expected or not authorization or not hmac.compare_digest(authorization.encode(), ('Bearer '+expected).encode()):
            raise HTTPException(403, 'forbidden')

    def dispatch_anchor(anchor_data):
        url = os.getenv('ANCHOR_SINK_URL', 'http://anchor_service:8003/anchor')
        token = os.getenv('ANCHOR_WRITE_TOKEN', '')
        def _send():
            try:
                import httpx
                headers = {'Content-Type': 'application/json'}
                if token:
                    headers['Authorization'] = f'Bearer {token}'
                with httpx.Client(timeout=0.5, trust_env=False) as client:
                    client.post(url, json=anchor_data, headers=headers)
            except Exception:
                pass
        threading.Thread(target=_send, daemon=True).start()

    @app.post('/ingest', dependencies=[Depends(authorize)])
    def ingest(body: IngestEvent):
        payload = dict(body.payload)
        payload['_aegis'] = dict(schema_version=2,session_id=body.session_id,
                                 event_type=body.event_type,sensitive_action_flag=body.sensitive_action_flag,
                                 client_seq=body.client_seq)
        try:
            serialized = canonical_json(payload)
            if len(serialized.encode()) > 131072:
                raise ValueError('too large')
        except (ValueError, TypeError, RecursionError):
            raise HTTPException(422, 'payload must be finite JSON under 128 KiB')
        conn = None
        anchor_job = None
        try:
            conn = connect(path)
            conn.execute('BEGIN IMMEDIATE')
            previous = conn.execute('SELECT hash FROM audit_log WHERE session_id=? ORDER BY id DESC LIMIT 1',(body.session_id,)).fetchone()
            prev_hash = previous[0] if previous else '0'*64
            timestamp = 0.0 if body.timestamp == 0 else body.timestamp  # SQLite normalizes negative zero.
            digest = entry_hash(timestamp,serialized,prev_hash)
            conn.execute('INSERT INTO audit_log(session_id,timestamp,event_type,payload,sensitive_action_flag,prev_hash,hash) VALUES(?,?,?,?,?,?,?)',
                         (body.session_id,timestamp,body.event_type,serialized,int(body.sensitive_action_flag),prev_hash,digest))
            session_count = conn.execute('SELECT COUNT(*) FROM audit_log WHERE session_id=?',(body.session_id,)).fetchone()[0]
            anchor_every = int(os.getenv('ANCHOR_EVERY','10'))
            if anchor_every > 0 and session_count % anchor_every == 0:
                anchor_job = dict(session_id=body.session_id,count=session_count,head_hash=digest,
                                  last_client_seq=body.client_seq,ts=float(time.time()))
            conn.commit()
        except sqlite3.Error:
            if conn: conn.rollback()
            raise HTTPException(503, 'audit sink unavailable')
        finally:
            if conn: conn.close()
        if anchor_job is not None:
            dispatch_anchor(anchor_job)
        return {'status':'recorded'}
    return app

app = create_app()
