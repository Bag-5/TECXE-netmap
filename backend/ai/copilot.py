"""AI copilot — builds graph-context prompts and streams answers."""

from __future__ import annotations

import logging

from backend.ai.openrouter import SYSTEM_PROMPT, stream_chat
from backend.graph.builder import graph_summary_for_ai
from backend.graph.model import AttackPath, HostNode, TrustEdge

logger = logging.getLogger(__name__)

# Keep the most recent conversation turns bounded
MAX_HISTORY_TURNS = 12


def build_messages(
    question: str,
    history: list[dict],
    hosts: list[HostNode] | None = None,
    edges: list[TrustEdge] | None = None,
    paths: list[AttackPath] | None = None,
) -> list[dict]:
    context_json = "{}"
    if hosts is not None:
        summary = graph_summary_for_ai(hosts, edges or [], paths or [])
        import json

        context_json = json.dumps(summary, separators=(",", ":"))

    messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.append(
        {
            "role": "system",
            "content": f"CURRENT NETWORK GRAPH STATE:\n{context_json}",
        }
    )
    # Trim history to recent turns, keep alternation sane
    trimmed = history[-(MAX_HISTORY_TURNS * 2):]
    messages.extend(trimmed)
    messages.append({"role": "user", "content": question})
    return messages


async def answer_question(
    question: str,
    history: list[dict],
    hosts: list[HostNode] | None = None,
    edges: list[TrustEdge] | None = None,
    paths: list[AttackPath] | None = None,
):
    messages = build_messages(question, history, hosts, edges, paths)
    async for token in stream_chat(messages):
        yield token
