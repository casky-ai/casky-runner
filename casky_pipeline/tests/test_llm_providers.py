"""Unit tests for casky_pipeline.llm_providers (Phase 1 Contract, Section 4).

Every async call site is exercised via asyncio.run(...) inside plain `def
test_...():` functions rather than an async-def test + a pytest-asyncio
marker, so these tests don't depend on pytest-asyncio's mode configuration
(auto vs strict) or any pytest.ini/pyproject.toml settings.

No real network calls are made anywhere in this file: AnthropicProvider tests
replace `anthropic.AsyncAnthropic` itself before any provider is constructed,
and OpenAICompatibleProvider tests patch `requests.post`.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import anthropic
import httpx2
import pytest

from casky_pipeline.llm_providers import (
    AnthropicProvider,
    OpenAICompatibleProvider,
    build_provider_from_env,
)


# ── helpers ──────────────────────────────────────────────────────────────

def _fake_anthropic_response(text: str = "ok") -> SimpleNamespace:
    return SimpleNamespace(
        content=[SimpleNamespace(text=text)],
        usage=SimpleNamespace(
            cache_read_input_tokens=0,
            cache_creation_input_tokens=0,
            input_tokens=1,
            output_tokens=1,
        ),
    )


def _make_fake_anthropic_client(create_mock: AsyncMock):
    """Returns a class usable as a drop-in replacement for
    anthropic.AsyncAnthropic: constructing it never touches the network,
    and .messages.create is the given AsyncMock."""

    class _FakeMessages:
        def __init__(self) -> None:
            self.create = create_mock

    class _FakeAsyncAnthropic:
        def __init__(self, *args, **kwargs) -> None:
            self.messages = _FakeMessages()

    return _FakeAsyncAnthropic


def _anthropic_status_error(cls, status_code: int, message: str):
    request = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    response = httpx2.Response(status_code, request=request)
    return cls(message, response=response, body=None)


# ── (1) build_provider_from_env() default vs. openai_compatible ────────────

def test_build_provider_from_env_defaults_to_anthropic(monkeypatch):
    monkeypatch.delenv("CASKY_MODEL_PROVIDER", raising=False)
    # Constructing a real AnthropicProvider only builds a client object (no
    # network call happens at construction time) but the SDK does require a
    # resolvable credential, so provide a dummy one.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")

    provider = build_provider_from_env()

    assert isinstance(provider, AnthropicProvider)


def test_build_provider_from_env_openai_compatible(monkeypatch):
    monkeypatch.setenv("CASKY_MODEL_PROVIDER", "openai_compatible")
    monkeypatch.setenv("CASKY_MODEL_BASE_URL", "http://localhost:11434/v1")

    provider = build_provider_from_env()

    assert isinstance(provider, OpenAICompatibleProvider)


# ── (2) openai_compatible without CASKY_MODEL_BASE_URL raises ──────────────

def test_build_provider_from_env_openai_compatible_missing_base_url(monkeypatch):
    monkeypatch.setenv("CASKY_MODEL_PROVIDER", "openai_compatible")
    monkeypatch.delenv("CASKY_MODEL_BASE_URL", raising=False)

    with pytest.raises(ValueError):
        build_provider_from_env()


# ── (3) unknown provider name raises ────────────────────────────────────────

def test_build_provider_from_env_unknown_provider(monkeypatch):
    monkeypatch.setenv("CASKY_MODEL_PROVIDER", "totally_bogus_provider")

    with pytest.raises(ValueError):
        build_provider_from_env()


# ── (3b) CASKY_MODEL_TEMPERATURE ─────────────────────────────────────────────
# Requested directly: make temperature configurable via .env, not just
# hardcoded — the pipeline's own default is 0.0 (see LLMProvider.complete's
# docstring), but an operator should be able to override it without a code
# change.

def test_build_provider_from_env_defaults_temperature_to_zero(monkeypatch):
    monkeypatch.delenv("CASKY_MODEL_TEMPERATURE", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")

    provider = build_provider_from_env()

    assert provider._temperature == 0.0


def test_build_provider_from_env_reads_temperature_for_anthropic(monkeypatch):
    monkeypatch.setenv("CASKY_MODEL_TEMPERATURE", "0.3")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")

    provider = build_provider_from_env()

    assert provider._temperature == 0.3


def test_build_provider_from_env_reads_temperature_for_openai_compatible(monkeypatch):
    monkeypatch.setenv("CASKY_MODEL_PROVIDER", "openai_compatible")
    monkeypatch.setenv("CASKY_MODEL_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("CASKY_MODEL_TEMPERATURE", "0.5")

    provider = build_provider_from_env()

    assert provider._temperature == 0.5


def test_build_provider_from_env_falls_back_to_zero_on_unparseable_temperature(monkeypatch, capsys):
    monkeypatch.setenv("CASKY_MODEL_TEMPERATURE", "not-a-number")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")

    provider = build_provider_from_env()

    assert provider._temperature == 0.0
    assert "not-a-number" in capsys.readouterr().err


# ── (4) AnthropicProvider.complete() cache_control on system block ─────────

def test_anthropic_provider_complete_sets_cache_control_when_cacheable(monkeypatch):
    create_mock = AsyncMock(return_value=_fake_anthropic_response())
    fake_client_cls = _make_fake_anthropic_client(create_mock)
    monkeypatch.setattr(anthropic, "AsyncAnthropic", fake_client_cls)

    provider = AnthropicProvider(api_key="test-key", model="claude-haiku-4-5")

    result = asyncio.run(
        provider.complete("you are a classifier", "evidence text", cacheable_system=True)
    )

    assert result == "ok"
    create_mock.assert_awaited_once()
    kwargs = create_mock.call_args.kwargs
    assert kwargs["system"] == [
        {
            "type": "text",
            "text": "you are a classifier",
            "cache_control": {"type": "ephemeral"},
        }
    ]
    assert kwargs["messages"] == [{"role": "user", "content": "evidence text"}]


def test_anthropic_provider_complete_omits_cache_control_when_not_cacheable(monkeypatch):
    create_mock = AsyncMock(return_value=_fake_anthropic_response())
    fake_client_cls = _make_fake_anthropic_client(create_mock)
    monkeypatch.setattr(anthropic, "AsyncAnthropic", fake_client_cls)

    provider = AnthropicProvider(api_key="test-key", model="claude-haiku-4-5")

    asyncio.run(
        provider.complete("one-off system prompt", "evidence text", cacheable_system=False)
    )

    kwargs = create_mock.call_args.kwargs
    assert kwargs["system"] == [{"type": "text", "text": "one-off system prompt"}]
    assert "cache_control" not in kwargs["system"][0]


# ── (4b) temperature defaults to 0.0, overridable, env-configurable ────────
#
# Live-caught: with no temperature pinned, every classifier-pipeline LLM call
# ran at the Anthropic API's own default (1.0, full sampling randomness) —
# the same evidence run three times validated different MITRE technique sets
# each time, cascading into wildly different investigation step counts (7 vs
# 12 vs 21). Every pipeline stage is classification/extraction, not creative
# writing, so 0.0 is the right default, not an afterthought left to the API.
#
# AnthropicProvider passes temperature via extra_body, not a direct
# messages.create() kwarg — this SDK version (anthropic==1.0.0) removed
# temperature from that method's typed signature entirely (confirmed via
# inspect.signature(); no temperature/top_p/top_k/seed param exists on it at
# all), but the REST API itself still honors it, verified with a real,
# live call. extra_body merges straight into the raw JSON request body.

def test_anthropic_provider_complete_defaults_temperature_to_zero(monkeypatch):
    create_mock = AsyncMock(return_value=_fake_anthropic_response())
    monkeypatch.setattr(anthropic, "AsyncAnthropic", _make_fake_anthropic_client(create_mock))

    provider = AnthropicProvider(api_key="test-key", model="claude-haiku-4-5")
    asyncio.run(provider.complete("system", "user"))

    assert create_mock.call_args.kwargs["extra_body"] == {"temperature": 0.0}


def test_anthropic_provider_complete_temperature_is_overridable_per_call(monkeypatch):
    create_mock = AsyncMock(return_value=_fake_anthropic_response())
    monkeypatch.setattr(anthropic, "AsyncAnthropic", _make_fake_anthropic_client(create_mock))

    provider = AnthropicProvider(api_key="test-key", model="claude-haiku-4-5")
    asyncio.run(provider.complete("system", "user", temperature=0.7))

    assert create_mock.call_args.kwargs["extra_body"] == {"temperature": 0.7}


def test_anthropic_provider_uses_its_own_configured_temperature_when_not_overridden(monkeypatch):
    """The CASKY_MODEL_TEMPERATURE -> AnthropicProvider(temperature=...) path —
    a call site that doesn't pass temperature (i.e. every real pipeline call
    site today) gets the provider's configured default, not always 0.0."""
    create_mock = AsyncMock(return_value=_fake_anthropic_response())
    monkeypatch.setattr(anthropic, "AsyncAnthropic", _make_fake_anthropic_client(create_mock))

    provider = AnthropicProvider(api_key="test-key", model="claude-haiku-4-5", temperature=0.4)
    asyncio.run(provider.complete("system", "user"))

    assert create_mock.call_args.kwargs["extra_body"] == {"temperature": 0.4}


def test_openai_compatible_provider_complete_defaults_temperature_to_zero():
    provider = OpenAICompatibleProvider(base_url="http://localhost:1234/v1", model="gpt-4o-mini")

    with patch("requests.post", return_value=_fake_requests_response("hello")) as mock_post:
        asyncio.run(provider.complete("system prompt", "user prompt"))

    assert mock_post.call_args.kwargs["json"]["temperature"] == 0.0


# ── (5) AnthropicProvider.complete() re-raises SDK errors ──────────────────

@pytest.mark.parametrize(
    "error_cls,status_code",
    [
        (anthropic.AuthenticationError, 401),
        (anthropic.RateLimitError, 429),
        (anthropic.APIStatusError, 500),
    ],
)
def test_anthropic_provider_complete_reraises_sdk_errors(monkeypatch, error_cls, status_code):
    error = _anthropic_status_error(error_cls, status_code, "boom")
    create_mock = AsyncMock(side_effect=error)
    fake_client_cls = _make_fake_anthropic_client(create_mock)
    monkeypatch.setattr(anthropic, "AsyncAnthropic", fake_client_cls)

    provider = AnthropicProvider(api_key="test-key", model="claude-haiku-4-5")

    with pytest.raises(error_cls):
        asyncio.run(provider.complete("system", "user", cacheable_system=True))


# ── (6) OpenAICompatibleProvider.complete() request shape + auth header ────

def _fake_requests_response(content: str = "hi") -> MagicMock:
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"choices": [{"message": {"content": content}}]}
    return resp


def test_openai_compatible_provider_complete_sends_messages_and_auth_header():
    provider = OpenAICompatibleProvider(
        base_url="http://localhost:1234/v1", model="gpt-4o-mini", api_key="secret-123"
    )

    with patch("requests.post", return_value=_fake_requests_response("hello")) as mock_post:
        result = asyncio.run(provider.complete("system prompt", "user prompt"))

    assert result == "hello"
    mock_post.assert_called_once()
    _, kwargs = mock_post.call_args
    assert kwargs["headers"]["Authorization"] == "Bearer secret-123"
    body = kwargs["json"]
    assert body["messages"] == [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": "user prompt"},
    ]
    assert body["model"] == "gpt-4o-mini"


def test_openai_compatible_provider_complete_omits_auth_header_without_key(monkeypatch):
    monkeypatch.delenv("CASKY_MODEL_API_KEY", raising=False)
    provider = OpenAICompatibleProvider(
        base_url="http://localhost:1234/v1", model="gpt-4o-mini", api_key=None
    )

    with patch("requests.post", return_value=_fake_requests_response("hello")) as mock_post:
        asyncio.run(provider.complete("system prompt", "user prompt"))

    _, kwargs = mock_post.call_args
    assert "Authorization" not in kwargs["headers"]
