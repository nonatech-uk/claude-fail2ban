"""Helper: read new lines from a docker container since a given timestamp.

mailcow runs as docker-compose containers with the default `json-file` log
driver, so journald-based scraping does not work — we shell out to
`docker logs --timestamps --since=<rfc3339>` and parse the leading RFC3339
timestamp Docker prepends.

State key is `docker:<container>` and stores the last seen RFC3339
timestamp. Negative / corrupt / future-dated values clamp back to a sane
look-back window, mirroring the defensive offset handling in
`caddy_json.py`.
"""

from __future__ import annotations

import datetime
import subprocess

from .. import log

# How far back to look on the very first run for a container we've never
# seen, OR when the recorded cursor looks bogus. One timer cycle is 15
# minutes; pad to 16 to avoid a sliver of un-read logs at boundaries.
DEFAULT_LOOKBACK = datetime.timedelta(minutes=16)
# `docker logs` is fast for short windows, but on a busy nginx container a
# corrupt cursor that asks for years of logs would hang. Cap at ~24h.
MAX_LOOKBACK = datetime.timedelta(hours=24)


def read_lines(
    container: str,
    state: dict,
    *,
    timeout_seconds: int = 30,
) -> tuple[list[tuple[datetime.datetime, str]], str]:
    """Return [(ts, line)] since the cursor in state, plus the new cursor.

    Side-effects: emits `DOCKER_LOG_ERROR` on subprocess failure (returns
    empty list rather than raising — sources should never crash a run).
    """
    cursors: dict[str, str] = state.setdefault("docker_cursors", {})
    now = datetime.datetime.now(datetime.timezone.utc)

    since = _resolve_since(cursors.get(container), now)

    try:
        proc = subprocess.run(
            [
                "docker", "logs",
                "--timestamps",
                "--since", since.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                container,
            ],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log.warn(
            "DOCKER_LOG_ERROR",
            container=container,
            error=str(e),
        )
        return [], cursors.get(container, _format_ts(since))

    # docker logs sends container stdout to subprocess stdout and container
    # stderr to subprocess stderr. Postfix/dovecot/nginx all log to stderr
    # in the upstream images, so we MUST merge both streams.
    raw_lines: list[str] = []
    if proc.stdout:
        raw_lines.extend(proc.stdout.splitlines())
    if proc.stderr:
        # Docker's own diagnostic output goes here on real errors (e.g. "No
        # such container"). Distinguish: real log lines have a parseable
        # leading RFC3339 ts; diagnostics don't.
        raw_lines.extend(proc.stderr.splitlines())

    out: list[tuple[datetime.datetime, str]] = []
    last_ts = since
    for raw in raw_lines:
        if not raw:
            continue
        ts, msg = _split_ts(raw)
        if ts is None:
            # Diagnostic / non-timestamped line — skip silently.
            continue
        out.append((ts, msg))
        if ts > last_ts:
            last_ts = ts

    new_cursor = _format_ts(last_ts)
    cursors[container] = new_cursor
    return out, new_cursor


def _resolve_since(
    recorded: str | None,
    now: datetime.datetime,
) -> datetime.datetime:
    fallback = now - DEFAULT_LOOKBACK
    if not recorded:
        return fallback
    try:
        ts = datetime.datetime.fromisoformat(recorded.replace("Z", "+00:00"))
    except ValueError:
        return fallback
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=datetime.timezone.utc)
    if ts > now:
        return fallback
    if now - ts > MAX_LOOKBACK:
        return now - MAX_LOOKBACK
    return ts


def _split_ts(line: str) -> tuple[datetime.datetime | None, str]:
    # Docker --timestamps prepends e.g. `2026-04-27T15:00:00.123456789Z `.
    head, sep, rest = line.partition(" ")
    if not sep:
        return None, line
    try:
        # Trim nanoseconds (Python's fromisoformat tolerates microseconds
        # at most). Docker emits 9-digit fractional seconds.
        ts_str = head
        if "." in ts_str:
            base, _, frac_z = ts_str.partition(".")
            frac, _, tz = frac_z.partition("Z") if "Z" in frac_z else (frac_z, "", "")
            frac = frac[:6]  # microseconds
            ts_str = f"{base}.{frac}+00:00"
        else:
            ts_str = ts_str.replace("Z", "+00:00")
        ts = datetime.datetime.fromisoformat(ts_str)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None, line
    return ts, rest


def _format_ts(ts: datetime.datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
