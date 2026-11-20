import json
import math
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal, TypedDict

import httpx


class ChatMessage(TypedDict):
    role: Literal["system", "user", "assistant"]
    content: str


class LlmError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class LlmClient:
    provider: Literal["local", "deepseek"]
    base_url: str
    model: str
    timeout: float
    api_key: str = field(default="", repr=False)
    reasoning_effort: str = ""

    def complete(
        self,
        messages: Sequence[ChatMessage],
        *,
        json_mode: bool = False,
        max_tokens: int = 2048,
    ) -> str:
        """Send a chat request and return the assistant's text."""
        if not messages or max_tokens <= 0:
            raise LlmError("invalid_request", "A chat request requires messages and a positive token limit.")

        body = {
            "model": self.model,
            "messages": list(messages),
            "stream": False,
            "max_tokens": max_tokens,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        if self.provider == "deepseek":
            body["thinking"] = {"type": "disabled"}
        elif self.reasoning_effort:
            # Qwen3 and other reasoning models think by default; that wastes tokens and can break JSON.
            body["reasoning_effort"] = self.reasoning_effort

        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        timeout = httpx.Timeout(self.timeout, connect=min(self.timeout, 5.0))
        try:
            with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=self.provider == "deepseek") as client:
                response = client.post(f"{self.base_url}/chat/completions", json=body, headers=headers)
        except httpx.TimeoutException:
            raise LlmError("timeout", "The model provider did not respond in time.") from None
        except httpx.RequestError:
            raise LlmError("connection_error", "Could not connect to the model provider.") from None

        if not response.is_success:
            code, message = {
                401: ("auth_error", "The model provider rejected the API key."),
                402: ("billing_error", "The model provider reported insufficient balance."),
                403: ("auth_error", "The model provider denied access."),
                429: ("rate_limited", "The model provider is rate-limiting requests."),
            }.get(response.status_code, ("upstream_error", f"The model provider returned HTTP {response.status_code}."))
            raise LlmError(code, message)

        try:
            choice = response.json()["choices"][0]
            finish_reason = choice.get("finish_reason")
            content = choice["message"]["content"]
        except (AttributeError, IndexError, KeyError, TypeError, ValueError):
            raise LlmError("invalid_response", "The model provider returned an invalid chat response.") from None
        if finish_reason not in (None, "stop"):
            raise LlmError("incomplete_response", "The model stopped before producing a complete answer.")
        if not isinstance(content, str) or not content.strip():
            raise LlmError("invalid_response", "The model provider returned an empty answer.")
        if json_mode:
            try:
                value = json.loads(content)
            except ValueError:
                raise LlmError("invalid_response", "The model answer is not valid JSON.") from None
            if not isinstance(value, dict):
                raise LlmError("invalid_response", "The model answer is not a JSON object.")
        return content


def load_llm() -> LlmClient:
    """Build the provider selected by the server environment."""
    provider = os.getenv("LLM_PROVIDER", "").strip().lower()
    if provider in ("", "disabled"):
        raise LlmError("not_configured", "Set LLM_PROVIDER to local or deepseek to enable the model.")
    if provider not in ("local", "deepseek"):
        raise LlmError("bad_config", "LLM_PROVIDER must be local, deepseek, or disabled.")

    try:
        timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "60"))
    except ValueError:
        raise LlmError("bad_config", "LLM_TIMEOUT_SECONDS must be a positive number.") from None
    if not math.isfinite(timeout) or timeout <= 0:
        raise LlmError("bad_config", "LLM_TIMEOUT_SECONDS must be a positive number.")

    if provider == "deepseek":
        api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
        model = os.getenv("DEEPSEEK_MODEL", "deepseek-flash").strip()
        if not api_key or not model:
            raise LlmError("bad_config", "DeepSeek needs DEEPSEEK_API_KEY and a model name.")
        return LlmClient("deepseek", "https://api.deepseek.com", model, timeout, api_key)

    raw_url = os.getenv("LOCAL_LLM_BASE_URL", "http://127.0.0.1:11434/v1").strip()
    try:
        url = httpx.URL(raw_url)
    except httpx.InvalidURL:
        raise LlmError("bad_config", "LOCAL_LLM_BASE_URL must be an HTTP(S) API base URL.") from None
    if url.scheme not in ("http", "https") or not url.host or url.userinfo or url.query or url.fragment:
        raise LlmError("bad_config", "LOCAL_LLM_BASE_URL must be an HTTP(S) API base URL without credentials.")

    model = os.getenv("LOCAL_LLM_MODEL", "").strip()
    if not model:
        raise LlmError("bad_config", "Set LOCAL_LLM_MODEL to a model served by the local provider.")
    return LlmClient(
        "local",
        str(url).rstrip("/"),
        model,
        timeout,
        os.getenv("LOCAL_LLM_API_KEY", "").strip(),
        os.getenv("LOCAL_LLM_REASONING_EFFORT", "none").strip(),
    )
