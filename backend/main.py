"""TECXE-netmap backend — FastAPI entrypoint."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from backend.ai.copilot import answer_question
from backend.config import settings
from backend.diffing.anomaly import diff_snapshots
from backend.graph.builder import compute_attack_paths, build_graph
from backend.graph.model import GraphSnapshot
from backend.graph.trust import infer_trust_edges
from backend.persistence.db import AsyncSessionLocal
from backend.persistence.repository import (
    create_snapshot,
    list_snapshots,
    load_latest_hosts,
    save_graph_snapshot,
    set_crown_jewels,
)
from backend.scanner.nmap_runner import NmapRunner
from backend.vulns.nvd_client import enrich_hosts_with_vulns
from backend.websocket.manager import manager

logging.basicConfig(level=settings.LOG_LEVEL)
logger = logging.getLogger(__name__)

_scan_lock = asyncio.Lock()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("TECXE-netmap backend starting…")
    yield
    await manager.broadcast_json({"type": "shutdown"})


app = FastAPI(title="TECXE-netmap", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------- #
# Models for request bodies
# --------------------------------------------------------------------------- #

class ScanRequest(BaseModel):
    cidr: str | None = None
    profile: str = "quick"


class ChatRequest(BaseModel):
    question: str
    history: list[dict] = []


class CrownJewelsRequest(BaseModel):
    ips: list[str]


# --------------------------------------------------------------------------- #
# Scan pipeline
# --------------------------------------------------------------------------- #

async def run_scan_pipeline(cidr: str, profile_name: str) -> GraphSnapshot:
    """Full pipeline: nmap → NVD → trust edges → attack paths → alerts → persist."""
    from typing import cast

    from backend.graph.model import HostNode

    runner = NmapRunner()
    hosts: list[HostNode] = []
    async for kind, payload in runner.scan_stream(cidr, profile_name):
        if kind == "progress":
            await manager.broadcast_json(
                {"type": "scan_progress", "message": payload}
            )
        elif kind == "result":
            hosts = cast(list[HostNode], payload)

    await manager.broadcast_json(
        {"type": "scan_progress", "message": f"Enriching {len(hosts)} hosts with CVE data…"}
    )
    try:
        await enrich_hosts_with_vulns(hosts)
    except Exception as exc:  # noqa: BLE001 — enrichment failure shouldn't kill the scan
        logger.warning("NVD enrichment failed (continuing without): %s", exc)

    prev_hosts = []
    snapshot_id = None
    async with AsyncSessionLocal() as session:
        prev_hosts = await load_latest_hosts(session)
        snapshot_id = await create_snapshot(session, profile_name, cidr)

    edges = infer_trust_edges(hosts)
    crown_ips = [h.ip for h in hosts if h.is_crown_jewel]
    graph = build_graph(hosts, edges)
    paths = compute_attack_paths(graph, crown_ips)

    # Preserve crown-jewel flags from previous scans by IP
    prev_crown = {h.ip for h in prev_hosts if h.is_crown_jewel}
    for h in hosts:
        if h.ip in prev_crown:
            h.is_crown_jewel = True

    # Recompute paths now that crown jewels are restored
    if not crown_ips and prev_crown:
        crown_ips = [h.ip for h in hosts if h.is_crown_jewel]
        graph = build_graph(hosts, edges)
        paths = compute_attack_paths(graph, crown_ips)

    alerts = diff_snapshots(prev_hosts, hosts) if prev_hosts else []

    snapshot = GraphSnapshot(
        snapshot_id=str(snapshot_id),
        hosts=hosts,
        edges=edges,
        attack_paths=paths,
        alerts=alerts,
    )

    async with AsyncSessionLocal() as session:
        await save_graph_snapshot(session, snapshot_id, snapshot)

    return snapshot


@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    cidr = req.cidr or settings.TARGET_CIDR
    if _scan_lock.locked():
        raise HTTPException(status_code=409, detail="A scan is already running")
    async with _scan_lock:
        try:
            snapshot = await run_scan_pipeline(cidr, req.profile)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Scan failed")
            raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"status": "completed", "snapshot_id": snapshot.snapshot_id}


@app.post("/api/scan/background")
async def start_scan_background(req: ScanRequest):
    """Kick off a scan without blocking; progress arrives over WebSocket."""
    cidr = req.cidr or settings.TARGET_CIDR
    if _scan_lock.locked():
        raise HTTPException(status_code=409, detail="A scan is already running")

    async def _job():
        async with _scan_lock:
            try:
                snapshot = await run_scan_pipeline(cidr, req.profile)
                await manager.broadcast_json(
                    {
                        "type": "graph_update",
                        "snapshot": snapshot.model_dump(),
                    }
                )
                await manager.broadcast_json(
                    {"type": "scan_done", "snapshot_id": snapshot.snapshot_id}
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception("Background scan failed")
                await manager.broadcast_json({"type": "scan_error", "error": str(exc)})

    task = asyncio.create_task(_job())
    task.add_done_callback(lambda t: t.exception() if t.exception() else None)
    return {"status": "started", "cidr": cidr, "profile": req.profile}


# --------------------------------------------------------------------------- #
# Graph / snapshots REST
# --------------------------------------------------------------------------- #

@app.get("/api/snapshots")
async def get_snapshots():
    async with AsyncSessionLocal() as session:
        return await list_snapshots(session)


@app.get("/api/graph/latest")
async def get_latest_graph():
    """Reconstruct the latest graph from persistence (for page reload)."""
    from backend.persistence.repository import get_latest_full_graph

    async with AsyncSessionLocal() as session:
        snap = await get_latest_full_graph(session)
    if snap is None:
        return {"snapshot": None}
    return {"snapshot": snap.model_dump()}


@app.get("/api/config")
async def get_config():
    return {
        "target_cidr": settings.TARGET_CIDR,
        "scan_profile": settings.SCAN_PROFILE,
        "profiles": [
            {"name": p.name, "description": p.description, "requires_admin": p.requires_admin}
            for p in _all_profiles()
        ],
        "ai_enabled": bool(settings.OPENROUTER_API_KEY),
    }


def _all_profiles():
    from backend.scanner.profiles import PROFILES

    return PROFILES.values()


@app.post("/api/crown-jewels")
async def update_crown_jewels(req: CrownJewelsRequest):
    async with AsyncSessionLocal() as session:
        await set_crown_jewels(session, req.ips)
    return {"status": "ok", "crown_jewels": req.ips}


# --------------------------------------------------------------------------- #
# AI copilot (SSE streaming)
# --------------------------------------------------------------------------- #

@app.post("/api/chat")
async def chat(req: ChatRequest):
    from backend.persistence.repository import get_latest_graph_context

    async with AsyncSessionLocal() as session:
        hosts, edges, paths = await get_latest_graph_context(session)

    async def event_stream():
        async for token in answer_question(
            req.question, req.history, hosts, edges, paths
        ):
            yield token

    return StreamingResponse(event_stream(), media_type="text/plain")


# --------------------------------------------------------------------------- #
# WebSocket
# --------------------------------------------------------------------------- #

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            # keepalive; client messages ignored for MVP
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)
