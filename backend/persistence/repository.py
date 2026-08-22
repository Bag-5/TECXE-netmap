"""Persistence operations for snapshots, hosts, edges, paths, alerts."""

from __future__ import annotations

import uuid
import logging
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.graph.model import (
    AlertItem,
    AttackPath,
    GraphSnapshot,
    HostNode,
    TrustEdge,
)
from backend.persistence.models import (
    AlertRecord,
    AttackPathRecord,
    HostRecord,
    ScanSnapshot,
    TrustEdgeRecord,
)

logger = logging.getLogger(__name__)


async def create_snapshot(
    session: AsyncSession, profile: str, target_cidr: str
) -> uuid.UUID:
    snap = ScanSnapshot(profile=profile, target_cidr=target_cidr, status="running")
    session.add(snap)
    await session.commit()
    return snap.id


async def save_graph_snapshot(
    session: AsyncSession,
    snapshot_id: uuid.UUID,
    graph: GraphSnapshot,
) -> None:
    # Clear any prior rows for this snapshot id (idempotent re-save)
    for model in (HostRecord, TrustEdgeRecord, AttackPathRecord, AlertRecord):
        existing = await session.execute(
            select(model).where(model.snapshot_id == snapshot_id)
        )
        for row in existing.scalars():
            await session.delete(row)

    prev_snap = await get_latest_snapshot_id(session, exclude=snapshot_id)

    for h in graph.hosts:
        session.add(
            HostRecord(
                snapshot_id=snapshot_id,
                ip=h.ip,
                mac=h.mac,
                hostname=h.hostname,
                os_name=h.os_name,
                os_accuracy=h.os_accuracy,
                os_family=h.os_family,
                ports=[p.model_dump() for p in h.ports],
                vulns=[v.model_dump() for v in h.vulns],
                criticality_score=h.criticality_score,
                is_crown_jewel=h.is_crown_jewel,
            )
        )

    for e in graph.edges:
        session.add(
            TrustEdgeRecord(
                snapshot_id=snapshot_id,
                source_ip=e.source_ip,
                target_ip=e.target_ip,
                trust_type=e.trust_type,
                weight=e.weight,
                evidence=e.evidence,
            )
        )

    for p in graph.attack_paths:
        session.add(
            AttackPathRecord(
                snapshot_id=snapshot_id,
                source_host_ip=p.source_ip,
                target_host_ip=p.target_ip,
                path_hops=[h.ip for h in p.hops],
                total_weight=p.total_weight,
                risk_score=p.risk_score,
            )
        )

    for a in graph.alerts:
        session.add(
            AlertRecord(
                snapshot_id=snapshot_id,
                prev_snapshot_id=prev_snap,
                alert_type=a.alert_type,
                severity=a.severity,
                description=a.description,
                details=a.details,
            )
        )

    await session.execute(
        update(ScanSnapshot)
        .where(ScanSnapshot.id == snapshot_id)
        .values(
            status="completed",
            completed_at=datetime.now(timezone.utc),
            host_count=len(graph.hosts),
            edge_count=len(graph.edges),
        )
    )
    await session.commit()


async def get_latest_snapshot_id(
    session: AsyncSession, exclude: uuid.UUID | None = None
) -> uuid.UUID | None:
    q = (
        select(ScanSnapshot.id)
        .where(ScanSnapshot.status == "completed")
        .order_by(ScanSnapshot.started_at.desc())
        .limit(1)
    )
    if exclude:
        q = q.where(ScanSnapshot.id != exclude)
    row = (await session.execute(q)).scalar_one_or_none()
    return row


async def load_latest_hosts(session: AsyncSession) -> list[HostNode]:
    snap_id = await get_latest_snapshot_id(session)
    if not snap_id:
        return []
    result = await session.execute(
        select(HostRecord).where(HostRecord.snapshot_id == snap_id)
    )
    hosts = []
    for rec in result.scalars():
        hosts.append(
            HostNode(
                ip=str(rec.ip),
                mac=str(rec.mac) if rec.mac else None,
                hostname=rec.hostname,
                os_name=rec.os_name,
                os_family=rec.os_family,
                os_accuracy=rec.os_accuracy,
                ports=rec.ports or [],
                vulns=rec.vulns or [],
                criticality_score=rec.criticality_score or 0.0,
                is_crown_jewel=rec.is_crown_jewel or False,
            )
        )
    return hosts


async def list_snapshots(session: AsyncSession, limit: int = 50) -> list[dict]:
    result = await session.execute(
        select(ScanSnapshot).order_by(ScanSnapshot.started_at.desc()).limit(limit)
    )
    return [
        {
            "id": str(s.id),
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "profile": s.profile,
            "target_cidr": str(s.target_cidr),
            "status": s.status,
            "host_count": s.host_count,
            "edge_count": s.edge_count,
        }
        for s in result.scalars()
    ]


async def set_crown_jewels(session: AsyncSession, ips: list[str]) -> None:
    """Mark crown-jewel flags on the latest completed snapshot's hosts."""
    snap_id = await get_latest_snapshot_id(session)
    if not snap_id:
        return
    await session.execute(
        update(HostRecord)
        .where(HostRecord.snapshot_id == snap_id)
        .values(is_crown_jewel=False)
    )
    if ips:
        await session.execute(
            update(HostRecord)
            .where(HostRecord.snapshot_id == snap_id, HostRecord.ip.in_(ips))
            .values(is_crown_jewel=True)
        )
    await session.commit()


async def get_latest_full_graph(session: AsyncSession) -> GraphSnapshot | None:
    """Load the most recent completed snapshot as a full GraphSnapshot."""
    snap_id = await get_latest_snapshot_id(session)
    if not snap_id:
        return None

    hosts_q = await session.execute(
        select(HostRecord).where(HostRecord.snapshot_id == snap_id)
    )
    edges_q = await session.execute(
        select(TrustEdgeRecord).where(TrustEdgeRecord.snapshot_id == snap_id)
    )
    paths_q = await session.execute(
        select(AttackPathRecord).where(AttackPathRecord.snapshot_id == snap_id)
    )

    from backend.graph.model import AttackPathHop, ServicePort, Vuln

    hosts = []
    for r in hosts_q.scalars():
        ports = [ServicePort(**p) for p in (r.ports or [])]
        vulns = [Vuln(**v) for v in (r.vulns or [])]
        hosts.append(
            HostNode(
                ip=r.ip,
                mac=r.mac,
                hostname=r.hostname,
                os_name=r.os_name,
                os_family=r.os_family,
                os_accuracy=r.os_accuracy,
                ports=ports,
                vulns=vulns,
                criticality_score=r.criticality_score or 0.0,
                is_crown_jewel=bool(r.is_crown_jewel),
            )
        )

    edges = [
        TrustEdge(
            source_ip=e.source_ip,
            target_ip=e.target_ip,
            trust_type=e.trust_type,
            weight=e.weight,
            evidence=e.evidence or {},
        )
        for e in edges_q.scalars()
    ]

    paths = [
        AttackPath(
            source_ip=p.source_host_ip,
            target_ip=p.target_host_ip,
            hops=[AttackPathHop(hop_index=i, ip=ip) for i, ip in enumerate(p.path_hops or [])],
            total_weight=p.total_weight,
            risk_score=p.risk_score,
        )
        for p in paths_q.scalars()
    ]

    return GraphSnapshot(
        snapshot_id=str(snap_id), hosts=hosts, edges=edges, attack_paths=paths, alerts=[]
    )


async def get_latest_graph_context(
    session: AsyncSession,
) -> tuple[list[HostNode], list[TrustEdge], list[AttackPath]]:
    """Convenience accessor for the AI copilot."""
    snap = await get_latest_full_graph(session)
    if snap is None:
        return [], [], []
    return snap.hosts, snap.edges, snap.attack_paths
