"""fail2ban-client backend: ban via `fail2ban-client set <jail> banip <ip>`."""

from __future__ import annotations

import subprocess

from .. import log
from .base import Action


class Fail2banClientAction(Action):
    name = "fail2ban_client"

    def __init__(self, jail: str):
        self.jail = jail

    def currently_banned(self) -> set[str]:
        banned: set[str] = set()
        try:
            result = subprocess.run(
                ["fail2ban-client", "status"],
                capture_output=True, text=True, timeout=10,
            )
            jails: list[str] = []
            for line in result.stdout.splitlines():
                if "Jail list:" in line:
                    jails = [j.strip() for j in line.split(":", 1)[1].split(",")]
                    break

            for jail in jails:
                if not jail:
                    continue
                result = subprocess.run(
                    ["fail2ban-client", "status", jail],
                    capture_output=True, text=True, timeout=10,
                )
                for line in result.stdout.splitlines():
                    if "Banned IP list:" in line:
                        ips = line.split(":", 1)[1].strip().split()
                        banned.update(ips)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            log.warn("FAIL2BAN_ERROR", detail="could not query banned IPs")
        return banned

    def ban(self, ip: str, reason: str) -> bool:
        try:
            result = subprocess.run(
                ["fail2ban-client", "set", self.jail, "banip", ip],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            log.error("BAN_FAILED", ip=ip, error=str(e))
            return False
