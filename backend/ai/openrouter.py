"""OpenRouter chat client with model fallback chain + SSE streaming."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator

import httpx

from backend.config import settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are the AI copilot of TECXE-netmap, a live 3D network map built from Nmap scans.
You are a senior network security analyst. You answer questions about the CURRENT graph state
(hosts, services, CVEs, trust relationships, attack paths) provided in context.

Rules:
- Be concise and concrete. Cite IPs, ports, and CVE IDs from the graph.
- When asked for paths, walk through hops explicitly.
- If data is absent from the graph state, say so instead of inventing it.
- Prefer bullet points over walls of text."""


class OpenRouterClient:
    def __init__(self):
        self.api_key = settings.OPENROUTER_API_KEY
        self.base_url = settings.OPENROUTER_BASE_URL.rstrip("/")
        self.models = [settings.OPENROUTER_PRIMARY_MODEL, settings.OPENROUTER_FALLBACK_MODEL]

    async def stream_chat(self, messages: list[dict]) -> AsyncIterator[str]:
        if not self.api_key:
            yield "[OpenRouter API key not configured — set OPENROUTER_API_KEY in .env]"
            return

        last_error: Exception | None = None
        for model in self.models:
            try:
                async for token in self._stream_model(model, messages):
                    yield token
                return
            except Exception as exc:  # noqa: BLE001 — fallback on ANY upstream failure
                last_error = exc
                logger.warning("Model %s failed (%s); falling back…", model, exc)
                continue

        yield f"[All models failed. Last error: {last_error}]"

    async def _stream_model(self, model: str, messages: list[dict]) -> AsyncIterator[str]:
        payload = {
            "model": model,
            "messages": messages,
            "stream": True,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=90.0) as client:
            async with client.stream(
                "POST", f"{self.base_url}/chat/completions", json=payload, headers=headers
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    data = line[6:]
                    if data.strip() == "[DONE]":
                        return
                    import json

                    try:
                        chunk = json.loads(data)
                        delta = chunk["choices"][0]["delta"]
                        token = delta.get("content")
                        if token:
                            yield token
                    except (json.JSONDecodeError, KeyError, IndexError):
                        continue


async def stream_chat(messages: list[dict]) -> AsyncIterator[str]:
    client = OpenRouterClient()
    async for token in client.stream_chat(messages):
        yield token
