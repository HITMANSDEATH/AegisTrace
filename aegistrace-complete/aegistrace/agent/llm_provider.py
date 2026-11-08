from __future__ import annotations

"""Lazy, explicitly selected model providers.

There is intentionally no automatic Groq-to-Ollama switch: a provider failure
is surfaced as the sanitized 503 required by the HTTP contract.
"""

import os
from typing import Any

try:  # Optional in local tests; importing the agent must not need model packages.
    from langchain_groq import ChatGroq as ChatGroq  # type: ignore
except Exception:  # pragma: no cover - depends on deployment extras
    ChatGroq = None  # type: ignore
try:
    from langchain_ollama import ChatOllama as ChatOllama  # type: ignore
except Exception:  # pragma: no cover - depends on deployment extras
    ChatOllama = None  # type: ignore


class ProviderConfigurationError(RuntimeError):
    pass


def get_llm() -> Any:
    """Construct the configured chat model, without invoking it.

    Groq is the default.  Set ``LLM_PROVIDER=ollama`` (or
    ``AGENT_LLM_PROVIDER``) for a local Ollama deployment.
    """
    provider = (os.getenv("LLM_PROVIDER") or os.getenv("AGENT_LLM_PROVIDER") or "groq").strip().lower()
    if provider == "groq":
        key = os.getenv("GROQ_API_KEY")
        if not key:
            raise ProviderConfigurationError("GROQ_API_KEY is not configured")
        if ChatGroq is None:
            raise ProviderConfigurationError("Groq provider is unavailable")
        try:
            timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "20"))
        except ValueError:
            timeout = 20.0
        if timeout <= 0:
            timeout = 20.0
        kwargs = {
            "model": os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
            "temperature": 0.3,
            "max_retries": 0,
            "max_tokens": 1024,
            # The agent's wait_for enforces LLM_TIMEOUT_SECONDS; leave the SDK a
            # small backstop so the timeout is reported as the agent's 504 path.
            "timeout": timeout + 2,
        }
        # ChatGroq reads the key from its environment, but passing it also
        # makes an injected constructor straightforward to test.
        try:
            return ChatGroq(api_key=key, **kwargs)
        except TypeError:
            return ChatGroq(**kwargs)
    if provider in {"ollama", "local"}:
        if ChatOllama is None:
            raise ProviderConfigurationError("Ollama provider is unavailable")
        return ChatOllama(
            model=os.getenv("OLLAMA_MODEL", "llama3:8b"),
            base_url=os.getenv("OLLAMA_BASE_URL", "http://ollama:11434"),
            temperature=0.3,
        )
    raise ProviderConfigurationError("unsupported LLM provider")
