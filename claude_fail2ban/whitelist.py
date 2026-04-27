"""IP/CIDR whitelist loader. File is one entry per line; '#' starts a comment."""

from __future__ import annotations

import ipaddress
from pathlib import Path

from . import log

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def load(path: Path) -> list[Network]:
    networks: list[Network] = []
    if not path.exists():
        return networks
    for raw in path.read_text().splitlines():
        entry = raw.strip()
        if not entry or entry.startswith("#"):
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            log.warn("WHITELIST_PARSE_ERROR", entry=entry)
    return networks


def is_whitelisted(ip: str, networks: list[Network]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)
