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
        temperature: float | None = None,
    ) -> str:
        """Returns the raw text completion. Implementations must raise on
        unrecoverable errors (auth failure, 4xx) so pipeline stages can
        surface them; may retry internally on 429/5xx.

        cacheable_system: when True (the default) and the provider supports
        prompt caching, mark system_prompt as an ephemeral cache breakpoint.
        Every pipeline stage's system prompt is static per stage (only
        user_prompt varies per investigation), so this is on by default —
        callers should only pass False for a genuinely one-off system prompt
        that will never repeat (rare in this codebase).

        temperature: None (the default) means "use this provider's own
        configured default" — see each implementation's __init__ and
        CASKY_MODEL_TEMPERATURE (build_provider_from_env), which itself
        defaults to 0.0, not the API's own default (Anthropic's is 1.0 —
        full sampling randomness). Live-caught: a user ran the exact same
        evidence through the classifier pipeline three times and got
        genuinely different MITRE technique sets validated each run (T1046
        alone, vs T1046+T1595+T1018, vs T1018+T1046+T1595), which cascades
        through SkillSelector (selects a variable number of skills PER
        technique) and _narrow_skill_index_by_technique_overlap (whether the
        candidate pool narrows or falls back to the full index depends on
        how many techniques got validated) into wildly different step counts
        (7 vs 12 vs 21 for the same evidence). Every stage in this pipeline
        (technique validation, skill selection, step ordering, evidence-gap
        analysis, memory extraction) is a classification/extraction task,
        not creative writing — determinism is the right default here, not
        an afterthought. A call site can still pass an explicit temperature
        to override the provider's configured default for one call; none do
        today."""
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

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-haiku-4-5",
        temperature: float = 0.0,
    ) -> None:
        import anthropic
        self._client = anthropic.AsyncAnthropic(
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY")
        )
        self._model = model
        self._temperature = temperature

    async def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
        cacheable_system: bool = True,
        temperature: float | None = None,
    ) -> str:
        import anthropic

        system_param: list[dict] | None = None
        if system_prompt:
            block: dict = {"type": "text", "text": system_prompt}
            if cacheable_system:
                block["cache_control"] = {"type": "ephemeral"}
            system_param = [block]

        effective_temperature = self._temperature if temperature is None else temperature

        try:
            response = await self._client.messages.create(
                model=self._model,
                max_tokens=max_tokens,
                system=system_param,
                messages=[{"role": "user", "content": user_prompt}],
                # `temperature` was removed from this SDK version's typed
                # messages.create() signature entirely (confirmed via
                # inspect.signature() — no temperature/top_p/top_k/seed
                # param exists on it at all in anthropic==1.0.0). The REST
                # API itself still honors it though — empirically verified
                # with a live call passing extra_body={"temperature": 0.0}
                # against the real API, which succeeded. extra_body merges
                # straight into the raw JSON request body, bypassing the
                # typed surface entirely.
                extra_body={"temperature": effective_temperature},
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

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str | None = None,
        temperature: float = 0.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._api_key = api_key or os.environ.get("CASKY_MODEL_API_KEY", "")
        self._temperature = temperature

    async def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
        cacheable_system: bool = True,
        temperature: float | None = None,
    ) -> str:
        import asyncio
        import requests

        effective_temperature = self._temperature if temperature is None else temperature

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
                json={
                    "model": self._model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": effective_temperature,
                },
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

        return await asyncio.to_thread(_call)


def _temperature_from_env() -> float:
    """CASKY_MODEL_TEMPERATURE — defaults to 0.0 (see LLMProvider.complete's
    docstring for why: every pipeline stage is classification/extraction,
    not creative writing, and 0.0 is what collapses the run-to-run variance
    live-caught on a real investigation). An unparseable value falls back to
    0.0 with a printed warning rather than crashing the whole harness over a
    typo'd env var — same "never hard-break on bad optional config" pattern
    DATABASE_URL/CASKY_API_KEY etc. already follow elsewhere in this repo."""
    raw = os.environ.get("CASKY_MODEL_TEMPERATURE", "0.0")
    try:
        return float(raw)
    except ValueError:
        import sys
        print(
            f"[casky_pipeline:llm] CASKY_MODEL_TEMPERATURE={raw!r} is not a valid float — "
            "using 0.0 instead.",
            file=sys.stderr,
        )
        return 0.0


def build_provider_from_env() -> LLMProvider:
    """
    CASKY_MODEL_PROVIDER    — "anthropic" (default) | "openai_compatible"
    CASKY_MODEL_BASE_URL    — required when CASKY_MODEL_PROVIDER=openai_compatible,
                               e.g. https://api.openai.com/v1, http://localhost:11434/v1 (Ollama),
                               http://localhost:1234/v1 (LM Studio), a vLLM server's /v1 URL
    CASKY_MODEL_NAME        — model name/id passed to the provider
                               (default "claude-haiku-4-5" for anthropic, "gpt-4o-mini" for openai_compatible)
    CASKY_MODEL_API_KEY     — optional bearer token for openai_compatible backends that require one
    CASKY_MODEL_TEMPERATURE — sampling temperature for every pipeline stage's LLM call
                               (default 0.0 — see LLMProvider.complete's docstring)
    """
    provider_kind = os.environ.get("CASKY_MODEL_PROVIDER", "anthropic").lower()
    model_name = os.environ.get("CASKY_MODEL_NAME", "")
    temperature = _temperature_from_env()

    if provider_kind == "anthropic":
        return AnthropicProvider(model=model_name or "claude-haiku-4-5", temperature=temperature)

    if provider_kind == "openai_compatible":
        base_url = os.environ.get("CASKY_MODEL_BASE_URL", "")
        if not base_url:
            raise ValueError(
                "CASKY_MODEL_BASE_URL is required when CASKY_MODEL_PROVIDER=openai_compatible"
            )
        return OpenAICompatibleProvider(
            base_url=base_url, model=model_name or "gpt-4o-mini", temperature=temperature
        )

    raise ValueError(
        f"Unknown CASKY_MODEL_PROVIDER: {provider_kind!r} (expected 'anthropic' or 'openai_compatible')"
    )
