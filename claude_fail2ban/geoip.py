"""GeoIP country lookup. Lazy-loaded; safely returns 'Unknown' if DB missing."""

from __future__ import annotations

from pathlib import Path

import geoip2.database
import geoip2.errors

DEFAULT_DB = Path("/var/lib/claude-fail2ban/GeoLite2-Country.mmdb")
_LEGACY_DB = Path("/opt/caddy-claude-analysis/data/GeoLite2-Country.mmdb")

_reader: geoip2.database.Reader | None = None
_db_path: Path | None = None


def _resolve_db() -> Path | None:
    if DEFAULT_DB.exists():
        return DEFAULT_DB
    if _LEGACY_DB.exists():
        return _LEGACY_DB
    return None


def _get_reader() -> geoip2.database.Reader | None:
    global _reader, _db_path
    if _reader is None:
        path = _resolve_db()
        if path is None:
            return None
        _reader = geoip2.database.Reader(str(path))
        _db_path = path
    return _reader


def lookup_country(ip: str) -> str:
    reader = _get_reader()
    if not reader:
        return "Unknown"
    try:
        return reader.country(ip).country.name or "Unknown"
    except (geoip2.errors.AddressNotFoundError, ValueError):
        return "Unknown"
