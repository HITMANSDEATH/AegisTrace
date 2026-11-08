"""External Chain-Head Anchor Service.

Append-only tamper-evident anchor log for detecting suffix deletion and
full-history rewrites.
"""
from contextlib import asynccontextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import threading
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, Depends
from pydantic import BaseModel, Field, ConfigDict
from common.hash import canonical_json

class AnchorRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', allow_inf_nan=False)
    session_id: str = Field(pattern=r'^[A-Za-z0-9_-]{1,96}$')
    count: int = Field(ge=1)
    head_hash: str = Field(min_length=64, max_length=64)
    last_client_seq: int = Field(ge=1)
    ts: float

class FileLock:
    def __init__(self, lock_path: Path):
        self.lock_path = lock_path
        self.fd = None

    def __enter__(self):
        try:
            import fcntl
            self.lock_path.parent.mkdir(parents=True, exist_ok=True)
            self.fd = open(self.lock_path, 'a+')
            fcntl.flock(self.fd.fileno(), fcntl.LOCK_EX)
        except ImportError:
            pass
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.fd is not None:
            try:
                import fcntl
                fcntl.flock(self.fd.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            self.fd.close()

def get_last_anchor_hash(log_path: Path) -> str:
    if not log_path.exists() or log_path.stat().st_size == 0:
        return '0' * 64
    with open(log_path, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if line.strip()]
    if not lines:
        return '0' * 64
    last_record = json.loads(lines[-1])
    return str(last_record.get('anchor_hash', '0' * 64))

def create_app(data_dir=None):
    dir_path = Path(data_dir or os.getenv('ANCHOR_DATA_DIR', '/anchor_data'))
    log_path = dir_path / 'anchors.jsonl'
    lock_path = dir_path / 'anchors.lock'
    proc_lock = threading.Lock()

    @asynccontextmanager
    async def lifespan(app):
        if not os.getenv('ANCHOR_WRITE_TOKEN'):
            raise RuntimeError('ANCHOR_WRITE_TOKEN must be configured')
        dir_path.mkdir(parents=True, exist_ok=True)
        yield

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    def authorize(authorization: str | None = Header(default=None)):
        expected = os.getenv('ANCHOR_WRITE_TOKEN', '')
        if not expected or not authorization or not hmac.compare_digest(authorization.encode(), ('Bearer ' + expected).encode()):
            raise HTTPException(403, 'forbidden')

    @app.get('/health')
    def health():
        return {'status': 'ok'}

    @app.post('/anchor', dependencies=[Depends(authorize)])
    def record_anchor(body: AnchorRequest):
        with proc_lock:
            with FileLock(lock_path):
                prev_anchor_hash = get_last_anchor_hash(log_path)
                record = {
                    'count': body.count,
                    'head_hash': body.head_hash,
                    'last_client_seq': body.last_client_seq,
                    'prev_anchor_hash': prev_anchor_hash,
                    'session_id': body.session_id,
                    'ts': float(body.ts)
                }
                serialized = canonical_json(record)
                anchor_hash = hashlib.sha256(serialized.encode('utf-8')).hexdigest()
                record['anchor_hash'] = anchor_hash
                entry_line = canonical_json(record)
                with open(log_path, 'a', encoding='utf-8') as f:
                    f.write(entry_line + '\n')
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except OSError:
                        pass
        return {'status': 'anchored', 'anchor_hash': anchor_hash, 'count': body.count}

    return app

app = create_app()
