"""Canonical payload and audit-chain hashing helpers shared by services."""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    """Return the exact JSON representation used by the audit sink."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def entry_hash(timestamp: float, payload_str: str, prev_hash: str) -> str:
    """Hash the bytes specified by the audit contract (not a JSON envelope)."""
    return hashlib.sha256((str(float(timestamp)) + payload_str + prev_hash).encode("utf-8")).hexdigest()


def event_id(seq: int) -> str:
    return f"evt-{seq:03d}"
