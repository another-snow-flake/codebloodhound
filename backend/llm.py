import json
import math
import os
import threading
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
                404: ("model_missing", "The model provider does not serve this model."),
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


Provider = Literal["local", "deepseek"]
PROBE_TIMEOUT = 3.0
_selection_lock = threading.Lock()
_selected_id: str | None = None  # chosen in the editor; None means the server environment decides


@dataclass(frozen=True)
class ModelOption:
    id: str
    provider: Provider
    model: str
    available: bool
    reason: str | None = None  # connection_error, model_missing or no_api_key


def _timeout() -> float:
    try:
        timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "60"))
    except ValueError:
        raise LlmError("bad_config", "LLM_TIMEOUT_SECONDS must be a positive number.") from None
    if not math.isfinite(timeout) or timeout <= 0:
        raise LlmError("bad_config", "LLM_TIMEOUT_SECONDS must be a positive number.")
    return timeout


def _base_url(variable: str, default: str) -> str:
    raw_url = os.getenv(variable, default).strip()
    try:
        url = httpx.URL(raw_url)
    except httpx.InvalidURL:
        raise LlmError("bad_config", f"{variable} must be an HTTP(S) API base URL.") from None
    if url.scheme not in ("http", "https") or not url.host or url.userinfo or url.query or url.fragment:
        raise LlmError("bad_config", f"{variable} must be an HTTP(S) API base URL without credentials.")
    return str(url).rstrip("/")


def _names(variable: str, fallback: str = "") -> list[str]:
    raw = os.getenv(variable, "") or fallback
    return list(dict.fromkeys(name.strip() for name in raw.split(",") if name.strip()))


def _option_id(provider: str, model: str) -> str:
    return f"{provider}:{model}"


def build_client(provider: str, model: str) -> LlmClient:
    """Build a client for one provider and model. Keys and addresses come from the server environment."""
    timeout = _timeout()
    if provider == "deepseek":
        api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
        if not api_key or not model:
            raise LlmError("bad_config", "DeepSeek needs DEEPSEEK_API_KEY and a model name.")
        return LlmClient("deepseek", _base_url("DEEPSEEK_BASE_URL", "https://api.deepseek.com"), model, timeout, api_key)
    if provider == "local":
        if not model:
            raise LlmError("bad_config", "Set LOCAL_LLM_MODEL to a model served by the local provider.")
        return LlmClient(
            "local",
            _base_url("LOCAL_LLM_BASE_URL", "http://127.0.0.1:11434/v1"),
            model,
            timeout,
            os.getenv("LOCAL_LLM_API_KEY", "").strip(),
            os.getenv("LOCAL_LLM_REASONING_EFFORT", "none").strip(),
        )
    raise LlmError("bad_config", "LLM_PROVIDER must be local, deepseek, or disabled.")


def _environment_choice() -> tuple[str, str] | None:
    provider = os.getenv("LLM_PROVIDER", "").strip().lower()
    if provider in ("", "disabled"):
        return None
    if provider == "deepseek":
        return provider, os.getenv("DEEPSEEK_MODEL", "deepseek-flash").strip()
    if provider == "local":
        return provider, os.getenv("LOCAL_LLM_MODEL", "").strip()
    raise LlmError("bad_config", "LLM_PROVIDER must be local, deepseek, or disabled.")


def _installed_local_models() -> list[str]:
    """Ask the local OpenAI-compatible server which models it serves."""
    headers = {"Authorization": f"Bearer {key}"} if (key := os.getenv("LOCAL_LLM_API_KEY", "").strip()) else {}
    try:
        with httpx.Client(timeout=PROBE_TIMEOUT, trust_env=False, follow_redirects=False) as client:
            response = client.get(f"{_base_url('LOCAL_LLM_BASE_URL', 'http://127.0.0.1:11434/v1')}/models", headers=headers)
        response.raise_for_status()
        return sorted(str(item["id"]) for item in response.json()["data"])
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        raise LlmError("connection_error", "Could not connect to the local model server.") from None


def list_model_options() -> list[ModelOption]:
    """Models the editor may choose from, with their current status."""
    options = []
    configured = _names("LOCAL_LLM_MODELS", os.getenv("LOCAL_LLM_MODEL", ""))
    try:
        installed = _installed_local_models()
        for model in dict.fromkeys([*installed, *configured]):
            options.append(ModelOption(
                _option_id("local", model), "local", model, model in installed,
                None if model in installed else "model_missing",
            ))
    except LlmError:
        options += [ModelOption(_option_id("local", m), "local", m, False, "connection_error") for m in configured]

    has_key = bool(os.getenv("DEEPSEEK_API_KEY", "").strip())
    for model in _names("DEEPSEEK_MODELS", os.getenv("DEEPSEEK_MODEL", "deepseek-flash")):
        options.append(ModelOption(_option_id("deepseek", model), "deepseek", model, has_key, None if has_key else "no_api_key"))
    return options


def selected_model_id() -> str | None:
    with _selection_lock:
        if _selected_id is not None:
            return _selected_id
    choice = _environment_choice()
    return _option_id(*choice) if choice and choice[1] else None


def select_model(option_id: str, options: Sequence[ModelOption]) -> None:
    """Use this model for the next AI node run and chat message. Requests in flight keep their model."""
    global _selected_id
    option = next((item for item in options if item.id == option_id), None)
    if option is None:
        raise LlmError("unknown_model", "This model is not configured on the server.")
    if option.reason == "no_api_key":
        raise LlmError("no_api_key", "Set DEEPSEEK_API_KEY on the server to use DeepSeek.")
    with _selection_lock:
        _selected_id = option.id


def reset_model_selection() -> None:
    global _selected_id
    with _selection_lock:
        _selected_id = None


def load_llm() -> LlmClient:
    """Build the client for the model chosen in the editor, or by the server environment."""
    with _selection_lock:
        chosen = _selected_id
    if chosen is not None:
        provider, model = chosen.split(":", 1)
        return build_client(provider, model)
    choice = _environment_choice()
    if choice is None:
        raise LlmError("not_configured", "Set LLM_PROVIDER to local or deepseek to enable the model.")
    return build_client(*choice)
