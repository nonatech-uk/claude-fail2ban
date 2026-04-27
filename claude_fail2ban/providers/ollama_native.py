"""Ollama-native /api/chat provider.

Differs from the OpenAI-compat provider in two ways that matter for this job:
- Sends ``think: false`` so reasoning models (qwen3.6:35b-a3b) skip the
  thought phase and return the JSON directly. Empirically ~10× faster.
- Uses ``format: "json"`` for guaranteed JSON output.

Same auth, same TLS posture, same fallback semantics.
"""

from __future__ import annotations

import json
import os
import re
import time

import requests
from urllib3.exceptions import InsecureRequestWarning

from .base import LLMProvider, ProviderError, ProviderResult

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore[attr-defined]


class OllamaNativeProvider(LLMProvider):
    name = "ollama_native"

    def __init__(
        self,
        model: str,
        url_env: str = "QWEN_URL",
        token_env: str = "QWEN_TOKEN",
        timeout_seconds: int = 60,
        tls_verify: bool = True,
        think: bool = False,
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
        self.think = think
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
            "format": "json",
            "think": self.think,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": self.max_tokens,
            },
        }
        started = time.monotonic()
        try:
            r = requests.post(
                f"{self.url}/api/chat",
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
        if r.status_code in (401, 403):
            raise ProviderError("auth_failed", f"HTTP {r.status_code}: {r.text[:200]}")
        if 400 <= r.status_code < 500:
            raise ProviderError("http_4xx", f"HTTP {r.status_code}: {r.text[:200]}")
        if r.status_code >= 500:
            raise ProviderError("http_5xx", f"HTTP {r.status_code}: {r.text[:200]}")

        try:
            payload = r.json()
        except json.JSONDecodeError as e:
            raise ProviderError("invalid_json", f"top-level: {e}") from e

        message = payload.get("message") or {}
        content = message.get("content", "")
        if not content:
            raise ProviderError("empty_response", "empty message content")

        analysis = _parse_analysis(content)
        if analysis is None:
            raise ProviderError("invalid_json", f"could not parse: {content[:200]}")

        return ProviderResult(
            analysis=analysis,
            tokens_in=int(payload.get("prompt_eval_count") or 0),
            tokens_out=int(payload.get("eval_count") or 0),
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
        if all(isinstance(v, dict) for v in payload.values()):
            return list(payload.values())
    if isinstance(payload, list):
        return payload
    return None
