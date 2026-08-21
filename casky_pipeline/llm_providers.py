"""BYO-LLM provider layer. CASKY_MODEL_PROVIDER selects the backend;
CASKY_MODEL_BASE_URL / CASKY_MODEL_NAME configure it. Default stays
Haiku-tier to match the classifier's current cost profile (harness.py:410-414
used claude-haiku-4-5-20251001) — this is a low-latency classification task,
not a place to default to a larger/thinking model."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod


class LLMProvider(ABC):
    @abstractmethod
    async def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
        cacheable_system: bool = True,
    ) -> str:
        """Returns the raw text completion. Implementations must raise on
        unrecoverable errors (auth failure, 4xx) so pipeline stages can
        surface them; may retry internally on 429/5xx.

        cacheable_system: when True (the default) and the provider supports
        prompt caching, mark system_prompt as an ephemeral cache breakpoint.
        Every pipeline stage's system prompt is static per stage (only
        user_prompt varies per investigation), so this is on by default —
        callers should only pass False for a genuinely one-off system prompt
        that will never repeat (rare in this codebase)."""
        raise NotImplementedError


class AnthropicProvider(LLMProvider):
    """Prompt caching: Anthropic's prompt caching is GA (no beta header
    required for the default 5-minute ephemeral TTL used here). Marking the
    system prompt as cache_control=ephemeral means every pipeline stage
    (TechniqueValidator, SkillSelector, StepOrderer, EvidenceGap) that reuses
    the same system prompt across a burst of investigations only pays full
    input-token price on the first call; subsequent calls within the TTL
    read the cached prefix at a fraction of the cost. This is the single
    highest-leverage cost fix in this pipeline, since the 4-stage design
    means the same static system prompts fire on every investigation."""

    def __init__(self, api_key: str | None = None, model: str = "claude-haiku-4-5") -> None:
        import anthropic
        self._client = anthropic.AsyncAnthropic(
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY")
        )
        self._model = model

    async def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
        cacheable_system: bool = True,
    ) -> str:
        import anthropic

        system_param: list[dict] | None = None
        if system_prompt:
            block: dict = {"type": "text", "text": system_prompt}
            if cacheable_system:
                block["cache_control"] = {"type": "ephemeral"}
            system_param = [block]

        try:
            response = await self._client.messages.create(
                model=self._model,
                max_tokens=max_tokens,
                system=system_param,
                messages=[{"role": "user", "content": user_prompt}],
            )
        except anthropic.AuthenticationError:
            raise
        except anthropic.RateLimitError:
            raise
        except anthropic.APIStatusError:
            raise

        usage = getattr(response, "usage", None)
        if usage is not None:
            cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
            cache_created = getattr(usage, "cache_creation_input_tokens", 0) or 0
            if cache_read or cache_created:
                import sys
                print(
                    f"[casky_pipeline:llm] model={self._model} "
                    f"cache_read={cache_read} cache_created={cache_created} "
                    f"input={usage.input_tokens} output={usage.output_tokens}",
                    file=sys.stderr,
                )
        return response.content[0].text


class OpenAICompatibleProvider(LLMProvider):
    """Any OpenAI-compatible /chat/completions endpoint: OpenAI, Qwen, Kimi,
    local Ollama / LM Studio / vLLM. Implemented over raw HTTP via `requests`
    (already an installed dependency, see repo-root Dockerfile) rather than
    the `openai` package, to avoid adding a new dependency to the runner
    image for this phase.

    cacheable_system is accepted for interface compliance but has no effect
    here: prompt caching is provider-specific (Anthropic's cache_control,
    OpenAI's automatic prefix caching, none/varies for local runtimes) and
    is out of scope for this phase's OpenAI-compatible path — most local
    backends (Ollama/LM Studio/vLLM) either cache automatically or don't
    support explicit cache control at all, so there's nothing correct to do
    here yet without per-backend branching. Revisit if/when a specific
    OpenAI-compatible backend's caching semantics are worth wiring."""

    def __init__(self, base_url: str, model: str, api_key: str | None = None) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._api_key = api_key or os.environ.get("CASKY_MODEL_API_KEY", "")

    async def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
        cacheable_system: bool = True,
    ) -> str:
        import asyncio
        import requests

        def _call() -> str:
            headers = {"Content-Type": "application/json"}
            if self._api_key:
                headers["Authorization"] = f"Bearer {self._api_key}"
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": user_prompt})
            resp = requests.post(
                f"{self._base_url}/chat/completions",
                headers=headers,
                json={"model": self._model, "messages": messages, "max_tokens": max_tokens},
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

        return await asyncio.to_thread(_call)


def build_provider_from_env() -> LLMProvider:
    """
    CASKY_MODEL_PROVIDER  — "anthropic" (default) | "openai_compatible"
    CASKY_MODEL_BASE_URL  — required when CASKY_MODEL_PROVIDER=openai_compatible,
                             e.g. https://api.openai.com/v1, http://localhost:11434/v1 (Ollama),
                             http://localhost:1234/v1 (LM Studio), a vLLM server's /v1 URL
    CASKY_MODEL_NAME      — model name/id passed to the provider
                             (default "claude-haiku-4-5" for anthropic, "gpt-4o-mini" for openai_compatible)
    CASKY_MODEL_API_KEY   — optional bearer token for openai_compatible backends that require one
    """
    provider_kind = os.environ.get("CASKY_MODEL_PROVIDER", "anthropic").lower()
    model_name = os.environ.get("CASKY_MODEL_NAME", "")

    if provider_kind == "anthropic":
        return AnthropicProvider(model=model_name or "claude-haiku-4-5")

    if provider_kind == "openai_compatible":
        base_url = os.environ.get("CASKY_MODEL_BASE_URL", "")
        if not base_url:
            raise ValueError(
                "CASKY_MODEL_BASE_URL is required when CASKY_MODEL_PROVIDER=openai_compatible"
            )
        return OpenAICompatibleProvider(base_url=base_url, model=model_name or "gpt-4o-mini")

    raise ValueError(
        f"Unknown CASKY_MODEL_PROVIDER: {provider_kind!r} (expected 'anthropic' or 'openai_compatible')"
    )
