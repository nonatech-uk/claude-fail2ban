"""Provider-chain orchestrator.

Builds the per-IP user message, walks the configured provider list in order,
and returns the first successful analysis. Emits structured Loki events for
every call attempt and every fallback.
"""

from __future__ import annotations

import json

from . import log
from .providers.base import LLMProvider, ProviderError


def build_user_message(suspicious: list[dict]) -> tuple[str, dict[str, list[dict]]]:
    by_ip: dict[str, list[dict]] = {}
    for entry in suspicious:
        ip = entry.get("client_ip", "unknown")
        by_ip.setdefault(ip, []).append(entry)

    msg = (
        f"Analyze these {len(suspicious)} suspicious log entries "
        f"from {len(by_ip)} unique IPs in the last analysis window:\n\n"
    )
    for ip, entries in sorted(by_ip.items()):
        msg += f"--- IP: {ip} ({len(entries)} requests) ---\n"
        for e in entries[:20]:
            msg += json.dumps(e) + "\n"
        if len(entries) > 20:
            msg += f"... and {len(entries) - 20} more requests\n"
        msg += "\n"
    return msg, by_ip


def classify(
    providers: list[LLMProvider],
    system_prompt: str,
    suspicious: list[dict],
    *,
    shadow_provider: LLMProvider | None = None,
) -> list[dict]:
    """Run the provider chain and return the first parseable analysis.

    If `shadow_provider` is given, additionally call it after the primary
    succeeds and emit comparison events. Shadow failures are logged but
    never affect the return value.
    """
    if not providers:
        log.error("LLM_NO_PROVIDERS")
        return []

    user_message, by_ip = build_user_message(suspicious)

    for idx, provider in enumerate(providers):
        try:
            result = provider.classify(system_prompt, user_message)
        except ProviderError as e:
            log.warn(
                "LLM_FALLBACK",
                provider=provider.name,
                model=provider.model,
                fallback_reason=e.reason,
                detail=e.detail[:200] if e.detail else None,
                next_provider=providers[idx + 1].name if idx + 1 < len(providers) else None,
            )
            continue

        log.emit(
            "LLM_CALL",
            provider=provider.name,
            model=provider.model,
            ips=len(by_ip),
            entries=len(suspicious),
            tokens_in=result.tokens_in,
            tokens_out=result.tokens_out,
            cache_read=result.cache_read,
            cache_create=result.cache_create,
            latency_ms=result.latency_ms,
        )
        # Backwards-compatible event name for one release.
        log.emit(
            "CLAUDE_CALL",
            provider=provider.name,
            ips=len(by_ip),
            entries=len(suspicious),
            input_tokens=result.tokens_in,
            output_tokens=result.tokens_out,
            cache_read=result.cache_read,
            cache_create=result.cache_create,
        )

        if shadow_provider is not None and shadow_provider is not provider:
            _run_shadow(shadow_provider, provider, system_prompt, user_message,
                        primary_analysis=result.analysis, by_ip=by_ip)

        return result.analysis

    log.error("LLM_ALL_FAILED", providers=[p.name for p in providers])
    return []


def _run_shadow(
    shadow: LLMProvider,
    primary: LLMProvider,
    system_prompt: str,
    user_message: str,
    *,
    primary_analysis: list[dict],
    by_ip: dict[str, list[dict]],
) -> None:
    try:
        result = shadow.classify(system_prompt, user_message)
    except ProviderError as e:
        log.warn(
            "LLM_SHADOW_FAILED",
            shadow_provider=shadow.name,
            shadow_model=shadow.model,
            fallback_reason=e.reason,
            detail=e.detail[:200] if e.detail else None,
        )
        return

    log.emit(
        "LLM_SHADOW_CALL",
        provider=shadow.name,
        model=shadow.model,
        ips=len(by_ip),
        tokens_in=result.tokens_in,
        tokens_out=result.tokens_out,
        latency_ms=result.latency_ms,
        shadow=True,
    )

    primary_by_ip = {a.get("ip", "?"): a for a in primary_analysis}
    shadow_by_ip = {a.get("ip", "?"): a for a in result.analysis}
    all_ips = set(primary_by_ip) | set(shadow_by_ip)

    counts = {"agree": 0, "diff_threat": 0, "diff_action": 0,
              "only_primary": 0, "only_shadow": 0}
    for ip in sorted(all_ips):
        p = primary_by_ip.get(ip)
        s = shadow_by_ip.get(ip)
        if p and not s:
            counts["only_primary"] += 1
            verdict = "only_primary"
        elif s and not p:
            counts["only_shadow"] += 1
            verdict = "only_shadow"
        else:
            assert p is not None and s is not None
            if bool(p.get("ban_recommended")) != bool(s.get("ban_recommended")):
                counts["diff_action"] += 1
                verdict = "diff_action"
            elif p.get("threat_level") != s.get("threat_level"):
                counts["diff_threat"] += 1
                verdict = "diff_threat"
            else:
                counts["agree"] += 1
                verdict = "agree"

        log.emit(
            "LLM_SHADOW_COMPARE",
            ip=ip,
            verdict=verdict,
            primary_provider=primary.name,
            shadow_provider=shadow.name,
            primary_threat=(p or {}).get("threat_level"),
            shadow_threat=(s or {}).get("threat_level"),
            primary_class=(p or {}).get("classification"),
            shadow_class=(s or {}).get("classification"),
            primary_ban=(p or {}).get("ban_recommended"),
            shadow_ban=(s or {}).get("ban_recommended"),
            primary_reason=((p or {}).get("reason") or "")[:160],
            shadow_reason=((s or {}).get("reason") or "")[:160],
        )

    log.emit(
        "LLM_SHADOW_SUMMARY",
        primary_provider=primary.name,
        shadow_provider=shadow.name,
        ips_total=len(all_ips),
        **counts,
    )
