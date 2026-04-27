"""Structured JSON logging to stdout for journald/Loki consumption."""

from __future__ import annotations

import datetime
import json
import sys
from typing import Any


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def emit(event: str, **fields: Any) -> None:
    """Emit one JSON line to stdout. Always includes ts + event."""
    record: dict[str, Any] = {"ts": _now(), "event": event}
    for k, v in fields.items():
        if v is None:
            continue
        record[k] = v
    sys.stdout.write(json.dumps(record, default=str) + "\n")
    sys.stdout.flush()


def warn(event: str, **fields: Any) -> None:
    emit(event, level="warn", **fields)


def error(event: str, **fields: Any) -> None:
    emit(event, level="error", **fields)
