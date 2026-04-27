"""mailcow mail-flow log source (postfix / dovecot / rspamd).

Reads stdout+stderr of the named docker container via `docker logs --since`.
Per-flavour cheap pre-filter regexes flag entries worth sending to the LLM.

Why this is `mailcow_docker.py` and not `mailcow_journald.py`: the original
phase plan assumed mailcow's compose stack would ship logs to journald. On
mees-mail-server the docker daemon uses the default `json-file` driver, so
`journalctl _SYSTEMD_UNIT=…` is empty. We read with `docker logs` instead.
A future host using the `journald` log driver can add a sibling source.
"""

from __future__ import annotations

import datetime
import re

from .. import log
from ._docker_logs import read_lines
from .base import Source

# Postfix syslog-style prefix produced inside the container:
#   "<MMM dd HH:MM:SS> <host> postfix/<component>[<pid>]: <msg>"
# We don't care about parsing the prefix — only the body. The leading
# RFC3339 ts is already stripped by `_docker_logs.read_lines`.
# Postfix wraps IPs in `[…]:port`, but ALSO wraps PIDs in `[…]` with no
# port — `postfix/postscreen[57887]: DNSBL rank 21 for [80.94.95.242]:50468`.
# Match only bracket contents that look like a real IP (dotted-quad IPv4 or
# colon-bearing IPv6); PIDs are pure decimal so they don't match.
_BRACKET_IP = re.compile(
    r"\[("
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|[0-9a-fA-F:]*:[0-9a-fA-F:.]+"
    r")\]"
)
_RIP = re.compile(r"\brip=([0-9a-fA-F:.]+)")

_POSTFIX_INTERESTING = re.compile(
    r"(?:"
    r"SASL\s+\w+\s+authentication failed"
    r"|postscreen\[\d+\]:\s+(?:DNSBL|PREGREET|HANGUP|COMMAND COUNT|COMMAND TIME LIMIT)"
    r"|NOQUEUE:\s+reject:"
    r"|Relay access denied"
    r"|too many errors after"
    r"|disconnect from .* commands="
    r")",
    re.IGNORECASE,
)
# Successful postscreen passes (`PASS NEW`) or normal disconnects after a
# clean session aren't suspicious; the regex above is strict enough to
# leave them out without an explicit exclusion list.

# Dovecot lines for failed auth / brute force.
_DOVECOT_INTERESTING = re.compile(
    r"(?:"
    r"auth failed"
    r"|Disconnected:\s+(?:auth failed|Aborted login \(auth failed)"
    r"|Disconnected:\s+Connection closed.*auth failed"
    r"|disconnected:\s+rcvd"
    r"|too many invalid commands"
    r"|policy server: "
    r")",
    re.IGNORECASE,
)

# Rspamd: only the per-message log lines that ended with a reject action.
_RSPAMD_INTERESTING = re.compile(
    r"task;.*?\(default:\s+(?:T \(reject\)|R)\b",
    re.IGNORECASE,
)


_FLAVOURS = {
    "postfix":  (_POSTFIX_INTERESTING, _BRACKET_IP),
    "dovecot":  (_DOVECOT_INTERESTING, _RIP),
    "rspamd":   (_RSPAMD_INTERESTING, re.compile(r"\bip:\s*([0-9a-fA-F:.]+)")),
}


class MailcowDockerSource(Source):
    """One instance per (container, flavour) pair."""

    def __init__(self, container: str, flavour: str):
        if flavour not in _FLAVOURS:
            raise ValueError(
                f"unknown flavour {flavour!r}; "
                f"expected one of {sorted(_FLAVOURS)}"
            )
        self.container = container
        self.flavour = flavour
        self.name = f"mailcow_{flavour}"
        self._interesting, self._ip_re = _FLAVOURS[flavour]

    def read_new_entries(self, state: dict) -> list[dict]:
        lines, _ = read_lines(self.container, state)
        out: list[dict] = []
        for ts, raw in lines:
            out.append({
                "ts": ts.isoformat(),
                "container": self.container,
                "flavour": self.flavour,
                "raw": raw,
            })
        return out

    def is_suspicious(self, entry: dict) -> bool:
        raw = entry.get("raw", "")
        if not self._interesting.search(raw):
            return False
        # Don't burn LLM tokens on entries we can't even attribute to an IP.
        return self._ip_re.search(raw) is not None

    def simplify(self, entry: dict) -> dict:
        raw = entry.get("raw", "")
        ip = _extract_ip(raw, self._ip_re)
        # Trim the message to keep the LLM batch small. Take the body after
        # the syslog-style header so the model sees the action, not the
        # container hostname/pid noise.
        body = _trim_syslog_header(raw)
        return {
            "ts": entry.get("ts", ""),
            "client_ip": ip,
            "flavour": self.flavour,
            "container": self.container,
            "message": body[:400],
        }


def _extract_ip(raw: str, ip_re: re.Pattern[str]) -> str:
    m = ip_re.search(raw)
    if not m:
        return "unknown"
    return m.group(1)


def _trim_syslog_header(raw: str) -> str:
    """Drop the `MMM dd HH:MM:SS hostname program[pid]:` syslog prefix."""
    # Quick path: split on `: ` after the program tag if present.
    idx = raw.find("]: ")
    if idx != -1:
        return raw[idx + 3:].strip()
    # Fallback: drop the first 4 whitespace-separated tokens (the syslog
    # date, time, hostname, program). Cheap and good enough for the LLM.
    parts = raw.split(maxsplit=4)
    return parts[4].strip() if len(parts) == 5 else raw.strip()
