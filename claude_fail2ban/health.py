"""Healthchecks.io ping. Optional; no-op if HEALTHCHECK_URL unset."""

from __future__ import annotations

import os
import urllib.request

from . import log


def ping(fail: bool = False) -> None:
    url = os.environ.get("HEALTHCHECK_URL", "")
    if not url:
        return
    target = url + ("/fail" if fail else "")
    try:
        req = urllib.request.Request(target, headers={"User-Agent": "claude-fail2ban/0.1"})
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        log.warn("HEALTHCHECK_PING_FAILED", error=str(e))
