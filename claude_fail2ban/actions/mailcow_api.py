"""Mailcow REST API ban backend.

Adds bans to mailcow's built-in fail2ban via `/api/v1/edit/fail2ban`. Reads
the existing banlist via `/api/v1/get/fail2ban` so we don't redundantly
re-ban what mailcow's own threshold rules already caught — claude-fail2ban
runs *alongside* mailcow's fail2ban, never replacing it.
"""

from __future__ import annotations

import os

import requests
from urllib3.exceptions import InsecureRequestWarning

from .. import log
from .base import Action

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore[attr-defined]

_TIMEOUT = 10


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

    def currently_banned(self) -> set[str]:
        if not self.url or not self.key:
            return set()
        try:
            r = requests.get(
                f"{self.url}/api/v1/get/fail2ban",
                headers={"X-API-Key": self.key},
                timeout=_TIMEOUT,
                verify=self.verify,
            )
        except requests.RequestException as e:
            log.warn("MAILCOW_BANLIST_ERROR", detail=str(e))
            return set()
        if r.status_code in (401, 403):
            log.error("MAILCOW_AUTH_ERROR", op="get_fail2ban", status=r.status_code)
            return set()
        if not r.ok:
            log.warn("MAILCOW_BANLIST_ERROR", status=r.status_code)
            return set()

        try:
            payload = r.json()
        except ValueError:
            return set()
        # mailcow returns active_bans as a list of {network, ...}.
        banned: set[str] = set()
        for item in payload.get("active_bans", []) or []:
            net = item.get("network") or item.get("ip")
            if not net:
                continue
            # Mailcow returns CIDR (e.g. "1.2.3.4/32"). Reduce /32 and /128
            # to the bare IP so it matches what the LLM emits.
            if net.endswith("/32") or net.endswith("/128"):
                net = net.rsplit("/", 1)[0]
            banned.add(net)
        return banned

    def ban(self, ip: str, reason: str) -> bool:
        if not self.url or not self.key:
            log.error("BAN_FAILED", ip=ip, reason="missing_env")
            return False
        try:
            r = requests.post(
                f"{self.url}/api/v1/edit/fail2ban",
                headers={"X-API-Key": self.key, "Content-Type": "application/json"},
                json={"items": ["banlist_add"], "attr": {"network": ip}},
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
            log.error(
                "BAN_FAILED",
                ip=ip,
                action=self.name,
                status=r.status_code,
                detail=r.text[:200],
            )
            return False
        return True
