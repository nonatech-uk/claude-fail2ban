"""mailcow nginx access-log source (combined log format).

Reads the nginx-mailcow container's access log and pre-filters for SOGo /
admin / API / ActiveSync auth failures and the shared bad-path scanner
signatures defined in `caddy_json.py`.

Internal mailcow bridge IPs (172.22.0.0/16) and the IPv6 ULA mailcow uses
(fd4d:6169:6c63:6f77::/64) are not filtered out here — they show up as
client_ip on rspamd / acme / watchdog health-check traffic, and the
whitelist file is the right place to ignore them. Keeping the source dumb
also means the LLM never sees the noise even if the whitelist drifts.

Simplified entries follow the gold-standard shape from `caddy_json.py`:
the legacy keys (`host`, `uri`, `method`, `status`, `user_agent`) plus the
new `target_site`, `target_path`, `target_proto`, `ua_family`. mailcow's
nginx combined log doesn't carry the Host header, so `target_site` is
best-effort from the Referer and may be absent (None) when no usable
Referer is present. `target_proto` is always `"http"` for this source.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ._docker_logs import read_lines
from .base import Source
from .caddy_json import BAD_PATH_PATTERNS, ua_family

# Combined log format:
#   <ip> - <user> [<time>] "<method> <uri> <proto>" <status> <size> "<ref>" "<ua>"
_COMBINED = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+'
    r'"(?P<method>[A-Z!-~]+)\s+(?P<uri>\S+)(?:\s+\S+)?"\s+'
    r'(?P<status>\d+)\s+\S+\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)

# Specific mailcow paths worth flagging on non-2xx responses.
_AUTH_PATH_PATTERNS = re.compile(
    r"(?i)"
    r"(/SOGo/so/|/SOGo/connect|/SOGo/Microsoft-Server-ActiveSync"
    r"|/Microsoft-Server-ActiveSync"
    r"|/admin(?:/|/dist/|/index\.php)?"
    r"|/api/v1/)"
)


class MailcowNginxSource(Source):
    name = "mailcow_nginx"

    def __init__(self, container: str):
        self.container = container

    def read_new_entries(self, state: dict) -> list[dict]:
        lines, _ = read_lines(self.container, state)
        out: list[dict] = []
        for ts, raw in lines:
            parsed = _parse_combined(raw)
            if parsed is None:
                # Mailcow's nginx also logs error.log entries to the same
                # stream; they don't match the combined format. Skip.
                continue
            parsed["ts"] = ts.isoformat()
            out.append(parsed)
        return out

    def is_suspicious(self, entry: dict) -> bool:
        uri = entry.get("uri", "")
        status = entry.get("status", 0)
        method = (entry.get("method") or "").upper()

        if BAD_PATH_PATTERNS.search(uri):
            return True
        # Mailcow auth surfaces (SOGo, admin, API, ActiveSync): any non-2xx.
        if _AUTH_PATH_PATTERNS.search(uri) and not 200 <= status < 300:
            return True
        # 404 with a recognisably scanner-y method is suspicious.
        if status == 404 and method in {"POST", "PUT", "DELETE", "PROPFIND"}:
            return True
        # Empty / placeholder UA on any non-2xx.
        ua = entry.get("user_agent", "")
        if (not ua or ua == "-") and not 200 <= status < 300:
            return True
        return False

    def simplify(self, entry: dict) -> dict:
        uri = entry.get("uri") or None
        method = (entry.get("method") or "?").upper()
        status = entry.get("status", 0)
        ua = entry.get("user_agent", "")
        referer_site = _host_from_referer(entry.get("referer", ""))
        return {
            "ts": entry.get("ts", ""),
            "client_ip": entry.get("ip", "unknown"),
            "method": method,
            # Legacy keys kept for parity with caddy_json's simplified shape.
            # mailcow nginx doesn't capture the Host header, so `host` falls
            # back to whatever the Referer indicates (same as target_site).
            "host": referer_site,
            "uri": uri,
            "target_site": referer_site,
            "target_path": uri[:200] if uri else None,
            "target_user": None,
            "target_proto": "http",
            "status": status,
            "user_agent": ua,
            "ua_family": ua_family(ua),
            "container": self.container,
        }


def _host_from_referer(referer: str) -> str | None:
    # Mailcow's nginx combined log doesn't capture the Host header, but the
    # Referer often points back at the same vhost the request was made to
    # (the panel making API calls, SOGo's own JS calls, etc.). Use it as a
    # best-effort indicator of which mailcow hostname was targeted. Returns
    # None when no usable Referer host is present so log.emit drops the
    # field from the JSON line (rather than emitting a literal "unknown").
    if not referer or referer == "-":
        return None
    try:
        host = urlparse(referer).hostname
    except ValueError:
        return None
    return host or None


def _parse_combined(raw: str) -> dict | None:
    m = _COMBINED.match(raw)
    if not m:
        return None
    try:
        status = int(m.group("status"))
    except ValueError:
        status = 0
    return {
        "ip": m.group("ip"),
        "method": m.group("method"),
        "uri": m.group("uri"),
        "status": status,
        "referer": m.group("referer"),
        "user_agent": m.group("ua"),
    }
