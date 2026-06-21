"""
Synsema LLM Provider System.

The LLM is to Synsema what V8 is to JavaScript — the reasoning engine.
But unlike V8, the LLM provider is swappable. You configure which model
powers the language's reasoning operations.

Supported operations:
    - reason: Free-form reasoning about a subject with context
    - decide: Choose between options given data
    - analyze: Analyze data for a specific objective
    - generate: Generate content (text, code, etc.)

Provider interface:
    Every provider implements the same interface. The language doesn't
    care if it's Claude, GPT, Llama, or a local model.
"""

import json
import os
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field


@dataclass
class LLMRequest:
    """A request to the LLM."""
    operation: str  # reason, decide, analyze, generate
    data: Dict[str, Any] = field(default_factory=dict)
    model: Optional[str] = None  # override default model
    temperature: float = 0.7
    max_tokens: int = 2048


@dataclass
class LLMResponse:
    """Response from the LLM."""
    content: str
    model: str = ""
    tokens_used: int = 0
    duration_ms: float = 0
    raw_response: Optional[Dict] = None


class LLMProvider(ABC):
    """Base class for LLM providers."""

    @abstractmethod
    def call(self, request: LLMRequest) -> LLMResponse:
        """Make a call to the LLM."""
        pass

    @abstractmethod
    def name(self) -> str:
        """Provider name."""
        pass

    def _build_prompt(self, request: LLMRequest) -> str:
        """Build a prompt from the request data."""
        # Use contextual prompt if the engine built one
        if "_contextual_prompt" in request.data:
            return request.data["_contextual_prompt"]

        op = request.operation
        data = request.data

        if op == "reason":
            subject = data.get("subject", "")
            context = data.get("context", {})
            prompt = f"Reason about the following:\n\nSubject: {subject}\n"
            if context:
                prompt += "\nContext:\n"
                for k, v in context.items():
                    prompt += f"  {k}: {v}\n"
            prompt += "\nProvide a clear, structured analysis."
            return prompt

        elif op == "decide":
            options = data.get("options", "")
            given = data.get("given", "")
            prompt = f"Given the following information:\n{given}\n\n"
            prompt += f"Choose the best option from: {options}\n"
            prompt += "Respond with ONLY the chosen option, nothing else."
            return prompt

        elif op == "analyze":
            data_str = data.get("data", "")
            objective = data.get("objective", "")
            prompt = f"Analyze the following data:\n{data_str}\n\n"
            prompt += f"Objective: {objective}\n"
            prompt += "Provide a concise analysis."
            return prompt

        elif op == "generate":
            target = data.get("target", "")
            given = data.get("given", "")
            params = data.get("parameters", {})
            prompt = f"Generate: {target}\n"
            if given:
                prompt += f"\nBased on: {given}\n"
            if params:
                prompt += "\nParameters:\n"
                for k, v in params.items():
                    prompt += f"  {k}: {v}\n"
            return prompt

        return str(data)


class AnthropicProvider(LLMProvider):
    """Claude (Anthropic) provider — uses the Messages API."""

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-sonnet-4-20250514"):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model
        self.api_url = "https://api.anthropic.com/v1/messages"

    def name(self) -> str:
        return f"anthropic:{self.model}"

    def call(self, request: LLMRequest) -> LLMResponse:
        import urllib.request
        import time

        if not self.api_key:
            return LLMResponse(
                content="[Anthropic API key not configured. Set ANTHROPIC_API_KEY]",
                model=self.model,
            )

        prompt = self._build_prompt(request)
        model = request.model or self.model

        payload = json.dumps({
            "model": model,
            "max_tokens": request.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": request.temperature,
        })

        req = urllib.request.Request(self.api_url)
        req.add_header("Content-Type", "application/json")
        req.add_header("x-api-key", self.api_key)
        req.add_header("anthropic-version", "2023-06-01")
        req.data = payload.encode("utf-8")

        start = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                duration = (time.perf_counter() - start) * 1000
                content = body.get("content", [{}])[0].get("text", "")
                tokens = body.get("usage", {}).get("output_tokens", 0)
                return LLMResponse(
                    content=content,
                    model=model,
                    tokens_used=tokens,
                    duration_ms=duration,
                    raw_response=body,
                )
        except Exception as e:
            return LLMResponse(
                content=f"[Anthropic API error: {e}]",
                model=model,
            )


class OpenAIProvider(LLMProvider):
    """OpenAI (GPT) provider."""

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o"):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.model = model
        self.api_url = "https://api.openai.com/v1/chat/completions"

    def name(self) -> str:
        return f"openai:{self.model}"

    def call(self, request: LLMRequest) -> LLMResponse:
        import urllib.request
        import time

        if not self.api_key:
            return LLMResponse(
                content="[OpenAI API key not configured. Set OPENAI_API_KEY]",
                model=self.model,
            )

        prompt = self._build_prompt(request)
        model = request.model or self.model

        payload = json.dumps({
            "model": model,
            "max_tokens": request.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": request.temperature,
        })

        req = urllib.request.Request(self.api_url)
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {self.api_key}")
        req.data = payload.encode("utf-8")

        start = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                duration = (time.perf_counter() - start) * 1000
                content = body["choices"][0]["message"]["content"]
                tokens = body.get("usage", {}).get("completion_tokens", 0)
                return LLMResponse(
                    content=content,
                    model=model,
                    tokens_used=tokens,
                    duration_ms=duration,
                    raw_response=body,
                )
        except Exception as e:
            return LLMResponse(
                content=f"[OpenAI API error: {e}]",
                model=model,
            )


class OllamaProvider(LLMProvider):
    """Ollama (local model) provider."""

    def __init__(self, model: str = "llama3", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url

    def name(self) -> str:
        return f"ollama:{self.model}"

    def call(self, request: LLMRequest) -> LLMResponse:
        import urllib.request
        import time

        prompt = self._build_prompt(request)
        model = request.model or self.model

        payload = json.dumps({
            "model": model,
            "prompt": prompt,
            "stream": False,
        })

        url = f"{self.base_url}/api/generate"
        req = urllib.request.Request(url)
        req.add_header("Content-Type", "application/json")
        req.data = payload.encode("utf-8")

        start = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                duration = (time.perf_counter() - start) * 1000
                return LLMResponse(
                    content=body.get("response", ""),
                    model=model,
                    tokens_used=body.get("eval_count", 0),
                    duration_ms=duration,
                    raw_response=body,
                )
        except Exception as e:
            return LLMResponse(
                content=f"[Ollama error: {e}. Is Ollama running?]",
                model=model,
            )


class MiniMaxProvider(LLMProvider):
    """
    MiniMax M3 provider — uses the Anthropic-compatible Messages API.

    MiniMax exposes an endpoint that accepts the same format as Anthropic's
    Messages API, so we reuse that structure: messages array with role/content,
    model field, max_tokens, etc.

    Endpoint: https://api.minimax.io/anthropic/v1/messages
    Auth: x-api-key header (same as Anthropic)
    Doc: https://platform.minimax.io/docs/api-reference/text-anthropic-api
    """

    def __init__(self, api_key: Optional[str] = None, model: str = "MiniMax-M3"):
        self.api_key = api_key or os.environ.get("MINIMAX_API_KEY", "")
        self.model = model
        self.api_url = "https://api.minimax.io/anthropic/v1/messages"

    def name(self) -> str:
        return f"minimax:{self.model}"

    def call(self, request: LLMRequest) -> LLMResponse:
        import urllib.request
        import time

        if not self.api_key:
            return LLMResponse(
                content="[MiniMax API key not configured. Set MINIMAX_API_KEY]",
                model=self.model,
            )

        prompt = self._build_prompt(request)
        model = request.model or self.model

        # Anthropic Messages API format
        payload = json.dumps({
            "model": model,
            "max_tokens": request.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        })

        req = urllib.request.Request(self.api_url)
        req.add_header("Content-Type", "application/json")
        req.add_header("x-api-key", self.api_key)
        req.add_header("anthropic-version", "2023-06-01")
        req.data = payload.encode("utf-8")

        start = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                duration = (time.perf_counter() - start) * 1000

                # Anthropic response format: content[0].text
                content = ""
                if "content" in body and body["content"]:
                    content = body["content"][0].get("text", "")

                tokens = body.get("usage", {}).get("output_tokens", 0)
                return LLMResponse(
                    content=content,
                    model=model,
                    tokens_used=tokens,
                    duration_ms=duration,
                    raw_response=body,
                )
        except Exception as e:
            return LLMResponse(
                content=f"[MiniMax API error: {e}]",
                model=model,
            )


class MockProvider(LLMProvider):
    """Mock provider for testing — returns predictable responses."""

    def __init__(self, responses: Dict[str, str] = None):
        self.responses = responses or {}
        self.call_log: List[LLMRequest] = []

    def name(self) -> str:
        return "mock"

    def call(self, request: LLMRequest) -> LLMResponse:
        self.call_log.append(request)
        content = self.responses.get(
            request.operation,
            f"[mock:{request.operation}]"
        )
        return LLMResponse(content=content, model="mock")


def create_provider(provider_name: str, **kwargs) -> LLMProvider:
    """Factory: create an LLM provider by name."""
    providers = {
        "anthropic": AnthropicProvider,
        "claude": AnthropicProvider,
        "openai": OpenAIProvider,
        "gpt": OpenAIProvider,
        "minimax": MiniMaxProvider,
        "minimax-m1": MiniMaxProvider,
        "ollama": OllamaProvider,
        "local": OllamaProvider,
        "mock": MockProvider,
    }
    cls = providers.get(provider_name.lower())
    if cls is None:
        raise ValueError(
            f"Unknown LLM provider: '{provider_name}'. "
            f"Available: {list(providers.keys())}"
        )
    return cls(**kwargs)
