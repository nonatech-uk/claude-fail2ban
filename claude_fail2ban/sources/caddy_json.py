"""Caddy JSON access-log source.

Reads new lines appended to /docker/caddy/logs/*.log since the last run, parses
each line as JSON, applies a cheap suspicion pre-filter, and returns a list of
simplified entries.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..patterns import BAD_PATH_PATTERNS, SUSPICIOUS_METHODS, SUSPICIOUS_STATUSES
from .base import Source


class CaddyJsonSource(Source):
    name = "caddy"

    def __init__(self, log_dir: str):
        self.log_dir = Path(log_dir)

    def read_new_entries(self, state: dict) -> list[dict]:
        entries: list[dict] = []
        offsets = state.setdefault("file_offsets", {})
        new_offsets: dict[str, int] = {}

        for log_file in sorted(self.log_dir.glob("*.log")):
            fname = log_file.name
            file_size = log_file.stat().st_size
            last_offset = offsets.get(fname, 0)

            # Rotation: new file is shorter than the recorded offset → restart.
            # Also defensive against corrupt/negative offsets in state.
            if last_offset < 0 or file_size < last_offset:
                last_offset = 0

            if file_size <= last_offset:
                new_offsets[fname] = last_offset
                continue

            with open(log_file, "r") as f:
                f.seek(last_offset)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        entry["_source_file"] = fname
                        entries.append(entry)
                    except json.JSONDecodeError:
                        continue
                new_offsets[fname] = f.tell()

        state["file_offsets"] = new_offsets
        return entries

    def is_suspicious(self, entry: dict) -> bool:
        status = entry.get("status", 200)
        request = entry.get("request", {})
        method = request.get("method", "GET")
        uri = request.get("uri", "")
        headers = request.get("headers", {})
        ua_list = headers.get("User-Agent", headers.get("user-agent", []))
        user_agent = ua_list[0] if ua_list else ""

        if BAD_PATH_PATTERNS.search(uri):
            return True
        if status in SUSPICIOUS_STATUSES:
            return True
        if method.upper() in SUSPICIOUS_METHODS:
            return True
        if not user_agent and status != 200:
            return True
        return False

    def simplify(self, entry: dict) -> dict:
        request = entry.get("request", {})
        headers = request.get("headers", {})
        ua_list = headers.get("User-Agent", headers.get("user-agent", []))
        return {
            "ts": entry.get("ts", 0),
            "client_ip": _extract_client_ip(entry),
            "method": request.get("method", "?"),
            "host": request.get("host", "?"),
            "uri": request.get("uri", "?"),
            "status": entry.get("status", 0),
            "user_agent": ua_list[0] if ua_list else "",
        }


def _extract_client_ip(entry: dict) -> str:
    request = entry.get("request", {})
    return request.get("client_ip", request.get("remote_ip", "unknown"))
