"""Mailcow REST API ban backend.

Adds bans to mailcow's built-in fail2ban via `/api/v1/edit/fail2ban`,
which edits the global fail2ban settings — the `blacklist` field is a
comma-separated list of IPs/CIDRs that are permanently blocked. We read
the current value, append, and POST the merged list back. We also pull
the live `active_bans` (mailcow's transient TTL'd bans) into the
`currently_banned()` set so we don't redundantly re-ban what mailcow's
own threshold rules already caught — claude-fail2ban runs *alongside*
mailcow's fail2ban, never replacing it.

Mailcow's `attr.banlist_add` shape that some older docs reference does
not actually persist anything: the API echoes `success` but the IP
doesn't land in `blacklist`, `active_bans`, or `permanent_bans`. Use the
documented `attr.blacklist = "<csv>"` shape from the openapi spec
instead.
"""

from __future__ import annotations

import ipaddress
import os
import re

import requests
from urllib3.exceptions import InsecureRequestWarning

from .. import log
from .base import Action

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore[attr-defined]

_TIMEOUT = 10
# Mailcow accepts comma-separated input but normalises stored blacklist
# values to newline-separated. Split on either, plus whitespace, so the
# parser works in both directions.
_SEP_RE = re.compile(r"[\s,;]+")


class MailcowApiAction(Action):
    name = "mailcow_api"

    def __init__(
        self,
        url_env: str = "MAILCOW_API_URL",
        key_env: str = "MAILCOW_API_KEY",
        tls_verify: bool = True,
    ):
        self.url = os.environ.get(url_env, "").rstrip("/")
        self.key = os.environ.get(key_env, "")
        self.url_env = url_env
        self.key_env = key_env
        self.verify = tls_verify
        # Surface stale or missing keys in Loki at run start, regardless of
        # whether anything ends up needing a ban this cycle. Never raises —
        # the run continues; ban() will return False if auth is bad.
        self._probe_auth()

    def _probe_auth(self) -> None:
        if not self.url or not self.key:
            log.error(
                "MAILCOW_AUTH_FAIL",
                reason="missing_env",
                url_env=self.url_env,
                key_env=self.key_env,
            )
            return
        try:
            r = requests.get(
                f"{self.url}/api/v1/get/status/version",
                headers={"X-API-Key": self.key},
                timeout=_TIMEOUT,
                verify=self.verify,
            )
        except requests.RequestException as e:
            log.error("MAILCOW_AUTH_FAIL", reason="unreachable", detail=str(e))
            return
        if r.status_code in (401, 403):
            log.error("MAILCOW_AUTH_FAIL", reason="bad_key", status=r.status_code)
            return
        if not r.ok:
            log.error("MAILCOW_AUTH_FAIL", reason=f"http_{r.status_code}")
            return
        log.emit("MAILCOW_AUTH_OK", url=self.url)

    def _get_settings(self) -> dict | None:
        try:
            r = requests.get(
                f"{self.url}/api/v1/get/fail2ban",
                headers={"X-API-Key": self.key},
                timeout=_TIMEOUT,
                verify=self.verify,
            )
        except requests.RequestException as e:
            log.warn("MAILCOW_BANLIST_ERROR", detail=str(e))
            return None
        if r.status_code in (401, 403):
            log.error("MAILCOW_AUTH_ERROR", op="get_fail2ban", status=r.status_code)
            return None
        if not r.ok:
            log.warn("MAILCOW_BANLIST_ERROR", status=r.status_code)
            return None
        try:
            return r.json()
        except ValueError:
            return None

    def currently_banned(self) -> set[str]:
        if not self.url or not self.key:
            return set()
        payload = self._get_settings()
        if payload is None:
            return set()
        banned: set[str] = set()
        # Live runtime bans (TTL'd by mailcow's fail2ban).
        for item in payload.get("active_bans") or []:
            net = item.get("network") or item.get("ip")
            if net:
                banned.add(_strip_host_cidr(net))
        # Permanent blacklist (what we add to via `ban()`).
        for tok in _split_csv(payload.get("blacklist") or ""):
            banned.add(_strip_host_cidr(tok))
        # `permanent_bans` if the deployment uses it.
        for item in payload.get("permanent_bans") or []:
            net = item.get("network") if isinstance(item, dict) else item
            if net:
                banned.add(_strip_host_cidr(net))
        return banned

    def ban(self, ip: str, reason: str) -> bool:
        if not self.url or not self.key:
            log.error("BAN_FAILED", ip=ip, reason="missing_env")
            return False
        # mailcow blacklist is a single comma-separated string. Read,
        # append, write the merged list back.
        payload = self._get_settings()
        if payload is None:
            log.error("BAN_FAILED", ip=ip, reason="settings_fetch_failed")
            return False
        existing = _split_csv(payload.get("blacklist") or "")
        new_entry = _to_host_cidr(ip)
        if new_entry is None:
            log.error("BAN_FAILED", ip=ip, reason="bad_ip")
            return False
        # Dedupe by stripping host-CIDR back to bare-IP for comparison.
        existing_bare = {_strip_host_cidr(e) for e in existing}
        if _strip_host_cidr(new_entry) in existing_bare:
            return True  # already banned, no-op success
        merged = ",".join(existing + [new_entry])

        try:
            r = requests.post(
                f"{self.url}/api/v1/edit/fail2ban",
                headers={"X-API-Key": self.key, "Content-Type": "application/json"},
                json={"items": "none", "attr": {"blacklist": merged}},
                timeout=_TIMEOUT,
                verify=self.verify,
            )
        except requests.RequestException as e:
            log.error("BAN_FAILED", ip=ip, action=self.name, error=str(e))
            return False
        if r.status_code in (401, 403):
            log.error("MAILCOW_AUTH_ERROR", op="edit_fail2ban", status=r.status_code, ip=ip)
            return False
        if not r.ok:
            log.error("BAN_FAILED", ip=ip, action=self.name,
                      status=r.status_code, detail=r.text[:200])
            return False
        # mailcow returns 200 even for noop bodies; verify the merged
        # response has a top-level success and that the IP is in the
        # echoed blacklist.
        try:
            body = r.json()
        except ValueError:
            body = None
        ok = False
        if isinstance(body, list):
            ok = any(isinstance(x, dict) and x.get("type") == "success" for x in body)
        elif isinstance(body, dict):
            ok = body.get("type") == "success"
        if not ok:
            log.error("BAN_FAILED", ip=ip, action=self.name,
                      reason="api_returned_non_success",
                      detail=str(body)[:200])
            return False
        return True


def _split_csv(s: str) -> list[str]:
    return [t for t in _SEP_RE.split(s) if t]


def _strip_host_cidr(net: str) -> str:
    # Reduce /32 and /128 to bare IP so the ban set matches what the LLM
    # emits.
    if net.endswith("/32") or net.endswith("/128"):
        return net.rsplit("/", 1)[0]
    return net


def _to_host_cidr(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        # Already a CIDR? Accept as-is if it parses.
        try:
            return str(ipaddress.ip_network(ip, strict=False))
        except ValueError:
            return None
    return f"{addr}/{32 if addr.version == 4 else 128}"
