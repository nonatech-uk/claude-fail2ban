"""Config loader. Reads /etc/claude-fail2ban/config.toml into typed dataclasses.

Config drives source/action/provider instantiation; every host gets its own
`config.toml` (delivered via fleet-sync).
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .actions.base import Action
from .actions.fail2ban_client import Fail2banClientAction
from .providers.anthropic_provider import AnthropicProvider
from .providers.base import LLMProvider, ProviderError
from .providers.ollama_native import OllamaNativeProvider
from .providers.ollama_openai import OllamaOpenAIProvider
from .sources.base import Source
from .sources.caddy_json import CaddyJsonSource

DEFAULT_CONFIG_PATH = Path("/etc/claude-fail2ban/config.toml")


@dataclass
class Limits:
    max_bans_per_run: int = 10
    max_batch_size: int = 200


@dataclass
class Digest:
    enabled: bool = True
    email: str = ""
    sender: str = ""


@dataclass
class Paths:
    state_file: Path = Path("/var/lib/claude-fail2ban/state.json")
    digest_file: Path = Path("/var/lib/claude-fail2ban/daily-digest.json")
    whitelist_file: Path = Path("/etc/claude-fail2ban/whitelist.txt")


@dataclass
class Shadow:
    """Shadow mode: call a second provider in parallel for verdict comparison.

    Selected by 0-based index into the `providers` list. The shadow result is
    never used to drive bans; it only feeds LLM_SHADOW_COMPARE events for
    quality validation before promoting the shadow to primary.
    """
    enabled: bool = False
    provider_index: int = 1


@dataclass
class Config:
    host_role: str = "caddy"
    mode: str = "warn"
    sources: list[Source] = field(default_factory=list)
    action: Action | None = None
    providers: list[LLMProvider] = field(default_factory=list)
    limits: Limits = field(default_factory=Limits)
    digest: Digest = field(default_factory=Digest)
    paths: Paths = field(default_factory=Paths)
    shadow: Shadow = field(default_factory=Shadow)


def load(path: Path = DEFAULT_CONFIG_PATH) -> Config:
    with open(path, "rb") as f:
        raw = tomllib.load(f)

    cfg = Config()
    cfg.host_role = raw.get("host_role", "caddy")
    cfg.mode = raw.get("mode", "warn")

    for s in raw.get("sources", []):
        cfg.sources.append(_build_source(s))

    action_raw = raw.get("action")
    if action_raw:
        cfg.action = _build_action(action_raw)

    for p in raw.get("providers", []):
        cfg.providers.append(_build_provider(p))

    lim = raw.get("limits", {})
    cfg.limits = Limits(
        max_bans_per_run=int(lim.get("max_bans_per_run", 10)),
        max_batch_size=int(lim.get("max_batch_size", 200)),
    )

    dig = raw.get("digest", {})
    cfg.digest = Digest(
        enabled=bool(dig.get("enabled", True)),
        email=dig.get("email", ""),
        sender=dig.get("sender", ""),
    )

    paths = raw.get("paths", {})
    cfg.paths = Paths(
        state_file=Path(paths.get("state_file", str(cfg.paths.state_file))),
        digest_file=Path(paths.get("digest_file", str(cfg.paths.digest_file))),
        whitelist_file=Path(paths.get("whitelist_file", str(cfg.paths.whitelist_file))),
    )

    shadow = raw.get("shadow", {})
    cfg.shadow = Shadow(
        enabled=bool(shadow.get("enabled", False)),
        provider_index=int(shadow.get("provider_index", 1)),
    )
    return cfg


def _build_source(spec: dict) -> Source:
    typ = spec.get("type")
    if typ == "caddy_json":
        return CaddyJsonSource(log_dir=spec["log_dir"])
    raise ValueError(f"unknown source type: {typ}")


def _build_action(spec: dict) -> Action:
    typ = spec.get("type")
    if typ == "fail2ban_client":
        return Fail2banClientAction(jail=spec["jail"])
    raise ValueError(f"unknown action type: {typ}")


def _build_provider(spec: dict) -> LLMProvider:
    typ = spec.get("type")
    if typ == "anthropic":
        return AnthropicProvider(
            model=spec["model"],
            timeout_seconds=int(spec.get("timeout_seconds", 60)),
        )
    if typ == "ollama_openai":
        return OllamaOpenAIProvider(
            model=spec["model"],
            url_env=spec.get("url_env", "QWEN_URL"),
            token_env=spec.get("token_env", "QWEN_TOKEN"),
            timeout_seconds=int(spec.get("timeout_seconds", 30)),
            tls_verify=bool(spec.get("tls_verify", True)),
        )
    if typ == "ollama_native":
        return OllamaNativeProvider(
            model=spec["model"],
            url_env=spec.get("url_env", "QWEN_URL"),
            token_env=spec.get("token_env", "QWEN_TOKEN"),
            timeout_seconds=int(spec.get("timeout_seconds", 60)),
            tls_verify=bool(spec.get("tls_verify", True)),
            think=bool(spec.get("think", False)),
        )
    raise ValueError(f"unknown provider type: {typ}")
