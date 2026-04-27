"""Persistent state: per-source cursors for incremental log reading."""

from __future__ import annotations

import datetime
import json
from pathlib import Path

DEFAULT_STATE_FILE = Path("/var/lib/claude-fail2ban/state.json")


def load(path: Path = DEFAULT_STATE_FILE) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, ValueError):
            return {"file_offsets": {}}
    return {"file_offsets": {}}


def save(state: dict, path: Path = DEFAULT_STATE_FILE) -> None:
    state["last_run"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2))
