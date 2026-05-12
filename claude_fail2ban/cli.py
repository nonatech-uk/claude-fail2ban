"""Command-line entrypoint.

Wires config → sources → action → providers and runs one analysis cycle.
Per-cycle and per-event structured logs go to stdout (captured by systemd
journald with SyslogIdentifier=claude-fail2ban → Alloy → Loki).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

from dotenv import load_dotenv

from . import analyzer, config as cfgmod, digest, geoip, health, log, prompts, state, whitelist


def _modal_first_seen(values):
    """Return the most-frequent value; ties broken by first-seen order."""
    counts: Counter = Counter()
    order: list = []
    for v in values:
        if v not in counts:
            order.append(v)
        counts[v] += 1
    if not counts:
        return None
    top = max(counts.values())
    for v in order:
        if counts[v] == top:
            return v
    return None

DEFAULT_ENV_PATHS = [
    Path("/etc/claude-fail2ban/.env"),
    Path("/opt/caddy-claude-analysis/.env"),
]


def _load_env() -> None:
    for p in DEFAULT_ENV_PATHS:
        if p.exists():
            load_dotenv(p, override=False)


def _git_revision() -> str:
    try:
        repo = Path(__file__).resolve().parent.parent
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(repo), capture_output=True, text=True, timeout=2,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return "unknown"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="claude-fail2ban")
    parser.add_argument("--config", default=str(cfgmod.DEFAULT_CONFIG_PATH))
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--warn", action="store_true",
                       help="Warning mode: log only, do not ban")
    group.add_argument("--enforce", action="store_true",
                       help="Enforcement mode: ban IPs via the configured action")
    group.add_argument("--dry-run", action="store_true",
                       help="Dry run: log only, no bans, no digest append")
    parser.add_argument("--send-digest", action="store_true",
                        help="Send accumulated daily digest email and exit")
    args = parser.parse_args(argv)

    _load_env()
    cfg = cfgmod.load(Path(args.config))

    if args.send_digest:
        if not cfg.digest.enabled:
            log.emit("DIGEST_SEND", status="disabled")
            return 0
        if not cfg.digest.email:
            log.error("DIGEST_SEND", status="no_recipient")
            return 1
        digest.send(
            to=cfg.digest.email,
            sender=cfg.digest.sender or f"claude-fail2ban@{os.uname().nodename}",
            path=cfg.paths.digest_file,
            host_role=cfg.host_role,
        )
        return 0

    if args.enforce:
        mode = "enforce"
    elif args.dry_run:
        mode = "dry-run"
    elif args.warn:
        mode = "warn"
    else:
        mode = cfg.mode

    return _run(cfg, mode)


def _run(cfg: cfgmod.Config, mode: str) -> int:
    st = state.load(cfg.paths.state_file)
    networks = whitelist.load(cfg.paths.whitelist_file)
    banned_ips: set[str] = cfg.action.currently_banned() if cfg.action else set()

    log.emit(
        "RUN_START",
        host_role=cfg.host_role,
        mode=mode,
        version=_git_revision(),
        whitelist_networks=len(networks),
        already_banned=len(banned_ips),
        sources=[s.name for s in cfg.sources],
        providers=[p.name for p in cfg.providers],
    )

    # Read all sources, tracking which source each entry came from.
    raw_entries: list[tuple[type[object], dict]] = []
    for source in cfg.sources:
        entries = source.read_new_entries(st)
        for e in entries:
            raw_entries.append((source, e))
    log.emit("LOGS_READ", total_new_entries=len(raw_entries))

    if not raw_entries:
        state.save(st, cfg.paths.state_file)
        log.emit("RUN_END", host_role=cfg.host_role, mode=mode, reason="no_new_entries")
        health.ping()
        return 0

    suspicious: list[dict] = []
    for source, entry in raw_entries:
        ip = source.simplify(entry).get("client_ip", "unknown")
        if whitelist.is_whitelisted(ip, networks):
            continue
        if ip in banned_ips:
            continue
        if not source.is_suspicious(entry):
            continue
        item = source.simplify(entry)
        item["_source"] = source.name
        suspicious.append(item)

    log.emit("FILTERED", suspicious=len(suspicious), raw=len(raw_entries))

    if not suspicious:
        state.save(st, cfg.paths.state_file)
        log.emit("RUN_END", host_role=cfg.host_role, mode=mode, reason="nothing_suspicious")
        health.ping()
        return 0

    if len(suspicious) > cfg.limits.max_batch_size:
        log.warn("BATCH_CAPPED", original=len(suspicious), capped_to=cfg.limits.max_batch_size)
        suspicious = suspicious[: cfg.limits.max_batch_size]

    rep_by_ip: dict[str, dict] = {}
    if cfg.host_role in {"caddy", "mailcow"}:
        lines_by_ip: dict[str, list[dict]] = {}
        for s in suspicious:
            lines_by_ip.setdefault(s.get("client_ip", "?"), []).append(s)
        for ip_, lines in lines_by_ip.items():
            # `flavour` is mail-flow only; `status`/`method`/`ua_family` are
            # nginx/web-only. `_modal_first_seen` returns None when no line
            # carries the field, so it's safe to collect the union.
            rep_by_ip[ip_] = {
                "target_site":  _modal_first_seen(ln.get("target_site")  for ln in lines),
                "target_path":  _modal_first_seen(ln.get("target_path")  for ln in lines),
                "target_user":  _modal_first_seen(ln.get("target_user")  for ln in lines),
                "target_proto": _modal_first_seen(ln.get("target_proto") for ln in lines),
                "flavour":      _modal_first_seen(ln.get("flavour")      for ln in lines),
                "method":       _modal_first_seen(ln.get("method")       for ln in lines),
                "status":       _modal_first_seen(ln.get("status")       for ln in lines),
                "ua_family":    _modal_first_seen(ln.get("ua_family")    for ln in lines),
            }

    shadow_provider = None
    if cfg.shadow.enabled and 0 <= cfg.shadow.provider_index < len(cfg.providers):
        shadow_provider = cfg.providers[cfg.shadow.provider_index]
    elif cfg.shadow.enabled:
        log.warn("SHADOW_MISCONFIGURED",
                 provider_index=cfg.shadow.provider_index,
                 providers_count=len(cfg.providers))

    analysis = analyzer.classify(
        cfg.providers,
        prompts.SYSTEM_PROMPT,
        suspicious,
        shadow_provider=shadow_provider,
    )

    if not analysis:
        state.save(st, cfg.paths.state_file)
        log.emit("RUN_END", host_role=cfg.host_role, mode=mode, reason="empty_analysis", analysed=0, bans=0)
        health.ping(fail=True)
        return 0

    bans_executed = 0
    for item in analysis:
        ip = item.get("ip", "?")
        threat = item.get("threat_level", "?")
        classification = item.get("classification", "?")
        ban_recommended = bool(item.get("ban_recommended"))
        reason = item.get("reason", "")
        country = geoip.lookup_country(ip)

        rep = rep_by_ip.get(ip, {})
        log.emit(
            "ANALYSIS",
            preserve_nulls=True,
            host_role=cfg.host_role,
            ip=ip,
            country=country,
            threat_level=threat,
            classification=classification,
            ban_recommended=ban_recommended,
            reason=reason,
            mode=mode,
            **rep,
        )

        if ban_recommended and mode == "enforce" and cfg.action is not None:
            if whitelist.is_whitelisted(ip, networks):
                log.warn("BAN_BLOCKED", ip=ip, reason="whitelisted")
                continue
            if ip in banned_ips:
                continue
            if bans_executed >= cfg.limits.max_bans_per_run:
                log.warn("BAN_LIMIT", ip=ip, reason="max_bans_reached")
                continue
            if cfg.action.ban(ip, reason):
                bans_executed += 1
                banned_ips.add(ip)
                log.emit(
                    "BANNED",
                    preserve_nulls=True,
                    host_role=cfg.host_role,
                    ip=ip,
                    country=country,
                    threat_level=threat,
                    classification=classification,
                    reason=reason,
                    action=cfg.action.name,
                    **rep,
                )
            else:
                log.error("BAN_FAILED", ip=ip, action=cfg.action.name)

    ip_targets: dict[str, list[str]] = {}
    for entry in suspicious:
        ip = entry.get("client_ip", "?")
        target = _format_target(entry)
        ip_targets.setdefault(ip, [])
        if target not in ip_targets[ip]:
            ip_targets[ip].append(target)

    if mode != "dry-run" and cfg.digest.enabled:
        digest.append(analysis, mode, ip_targets, path=cfg.paths.digest_file)

    state.save(st, cfg.paths.state_file)
    log.emit(
        "RUN_END",
        host_role=cfg.host_role,
        mode=mode,
        analysed=len(analysis),
        bans=bans_executed,
    )
    health.ping()
    return 0


def _format_target(entry: dict) -> str:
    """Render an entry's target_site/target_path pair for the daily digest.

    Mail sources (postfix/dovecot/rspamd) carry a recipient mailbox split
    into local-part (target_path) and domain (target_site); render as
    `local@domain`. Web sources carry a vhost + path; render as
    `site + path`. Either field may be absent (None) — when both are
    absent the target collapses to a single "unknown" placeholder rather
    than e.g. "unknown@unknown".
    """
    site = entry.get("target_site") or "unknown"
    path = entry.get("target_path") or "unknown"
    if site == "unknown" and path == "unknown":
        return "unknown"
    source = entry.get("_source", "")
    is_mail_flow = source in {"mailcow_postfix", "mailcow_dovecot", "mailcow_rspamd"}
    if is_mail_flow:
        return f"{path}@{site}"
    return f"{site}{path}"


if __name__ == "__main__":
    sys.exit(main())
