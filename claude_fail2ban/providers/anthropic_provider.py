"""Anthropic Claude provider (Haiku by default), with prompt caching."""

from __future__ import annotations

import json
import re
import time

import anthropic

from .base import LLMProvider, ProviderError, ProviderResult


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, model: str, timeout_seconds: int = 60, max_tokens: int = 4096):
        self.model = model
        self.timeout = timeout_seconds
        self.max_tokens = max_tokens
        self._client = anthropic.Anthropic()

    def classify(self, system_prompt: str, user_message: str) -> ProviderResult:
        started = time.monotonic()
        try:
            response = self._client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                timeout=self.timeout,
                system=[
                    {
                        "type": "text",
                        "text": system_prompt,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                messages=[{"role": "user", "content": user_message}],
            )
        except anthropic.APIStatusError as e:
            status = getattr(e, "status_code", 0)
            reason = "http_4xx" if 400 <= status < 500 else "http_5xx"
            raise ProviderError(reason, str(e)) from e
        except anthropic.APIConnectionError as e:
            raise ProviderError("unreachable", str(e)) from e
        except anthropic.APITimeoutError as e:
            raise ProviderError("timeout", str(e)) from e
        except anthropic.AuthenticationError as e:
            raise ProviderError("auth_failed", str(e)) from e
        except anthropic.APIError as e:
            raise ProviderError("sdk_error", str(e)) from e

        latency_ms = int((time.monotonic() - started) * 1000)
        if not response.content:
            raise ProviderError("empty_response", "no content in response")
        text = response.content[0].text.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\n?", "", text)
            text = re.sub(r"\n?```$", "", text)
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as e:
            raise ProviderError("invalid_json", f"{e}: {text[:200]}") from e

        usage = response.usage
        return ProviderResult(
            analysis=payload.get("analysis", []),
            tokens_in=usage.input_tokens,
            tokens_out=usage.output_tokens,
            cache_read=getattr(usage, "cache_read_input_tokens", 0) or 0,
            cache_create=getattr(usage, "cache_creation_input_tokens", 0) or 0,
            latency_ms=latency_ms,
        )
