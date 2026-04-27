"""LLM provider abstraction.

Providers transform a (system_prompt, user_message) pair into a list of
per-IP verdicts. Failures raise ProviderError with a stable `reason` so the
orchestrator can record and fall through to the next provider.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ProviderResult:
    analysis: list[dict]
    tokens_in: int = 0
    tokens_out: int = 0
    cache_read: int = 0
    cache_create: int = 0
    latency_ms: int = 0


class ProviderError(Exception):
    """Raised by a provider when it cannot deliver a parseable result.

    Reason strings (used as Loki field values for filtering):
        unreachable, timeout, http_4xx, http_5xx, invalid_json,
        health_failed, auth_failed, sdk_error, empty_response.
    """

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class LLMProvider(ABC):
    name: str = "provider"
    model: str = "?"

    @abstractmethod
    def classify(self, system_prompt: str, user_message: str) -> ProviderResult:
        ...
