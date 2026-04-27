"""Ollama provider via OpenAI-compatible /v1/chat/completions.

Uses Ollama's JSON-mode (`response_format={"type": "json_object"}`) when
available. Falls back to text parsing if Ollama returns the result in a
different shape; ``ProviderError("invalid_json")`` triggers fall-through.
"""

from __future__ import annotations

import json
import os
import re
import time

import requests
from urllib3.exceptions import InsecureRequestWarning

from .base import LLMProvider, ProviderError, ProviderResult

# Self-signed cert behind WireGuard — silence the warning per request when
# tls_verify is false. Module-level: applies to all instances.
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore[attr-defined]


class OllamaOpenAIProvider(LLMProvider):
    name = "ollama"

    def __init__(
        self,
        model: str,
        url_env: str = "QWEN_URL",
        token_env: str = "QWEN_TOKEN",
        timeout_seconds: int = 30,
        tls_verify: bool = True,
        max_tokens: int = 4096,
    ):
        self.model = model
        url = os.environ.get(url_env, "").rstrip("/")
        if not url:
            raise ProviderError("auth_failed", f"{url_env} not set in environment")
        self.url = url
        self.token = os.environ.get(token_env, "")
        self.timeout = timeout_seconds
        self.verify = tls_verify
        self.max_tokens = max_tokens

    def classify(self, system_prompt: str, user_message: str) -> ProviderResult:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "response_format": {"type": "json_object"},
            "max_tokens": self.max_tokens,
            "temperature": 0.1,
        }
        started = time.monotonic()
        try:
            r = requests.post(
                f"{self.url}/v1/chat/completions",
                headers=headers,
                json=body,
                timeout=self.timeout,
                verify=self.verify,
            )
        except requests.exceptions.ConnectionError as e:
            raise ProviderError("unreachable", str(e)) from e
        except requests.exceptions.Timeout as e:
            raise ProviderError("timeout", str(e)) from e
        except requests.exceptions.RequestException as e:
            raise ProviderError("sdk_error", str(e)) from e

        latency_ms = int((time.monotonic() - started) * 1000)
        if r.status_code == 401 or r.status_code == 403:
            raise ProviderError("auth_failed", f"HTTP {r.status_code}: {r.text[:200]}")
        if 400 <= r.status_code < 500:
            raise ProviderError("http_4xx", f"HTTP {r.status_code}: {r.text[:200]}")
        if r.status_code >= 500:
            raise ProviderError("http_5xx", f"HTTP {r.status_code}: {r.text[:200]}")

        try:
            payload = r.json()
        except json.JSONDecodeError as e:
            raise ProviderError("invalid_json", f"top-level: {e}") from e

        choices = payload.get("choices") or []
        if not choices:
            raise ProviderError("empty_response", "no choices in response")
        content = (choices[0].get("message") or {}).get("content", "")
        if not content:
            raise ProviderError("empty_response", "empty message content")

        analysis = _parse_analysis(content)
        if analysis is None:
            raise ProviderError("invalid_json", f"could not parse: {content[:200]}")

        usage = payload.get("usage") or {}
        return ProviderResult(
            analysis=analysis,
            tokens_in=int(usage.get("prompt_tokens") or 0),
            tokens_out=int(usage.get("completion_tokens") or 0),
            latency_ms=latency_ms,
        )


def _parse_analysis(content: str) -> list[dict] | None:
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\n?", "", text)
        text = re.sub(r"\n?```$", "", text)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(payload, dict):
        if isinstance(payload.get("analysis"), list):
            return payload["analysis"]
        # Some models return the list at the top level.
        if all(isinstance(v, dict) for v in payload.values()):
            return list(payload.values())
    if isinstance(payload, list):
        return payload
    return None
