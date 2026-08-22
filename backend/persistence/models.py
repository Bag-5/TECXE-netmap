"""ORM models mirroring the Neon schema."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, CIDR, INET, JSONB, MACADDR, UUID
from sqlalchemy.orm import Mapped, mapped_column

from backend.persistence.db import Base


class ScanSnapshot(Base):
    __tablename__ = "scan_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    profile: Mapped[str] = mapped_column(String(20))
    target_cidr: Mapped[str] = mapped_column(CIDR)
    status: Mapped[str] = mapped_column(String(20), default="running")
    host_count: Mapped[int] = mapped_column(Integer, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, default=0)


class HostRecord(Base):
    __tablename__ = "hosts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())
    snapshot_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    ip: Mapped[str] = mapped_column(INET)
    mac: Mapped[str | None] = mapped_column(MACADDR, nullable=True)
    hostname: Mapped[str | None] = mapped_column(Text, nullable=True)
    os_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    os_accuracy: Mapped[int | None] = mapped_column(Integer, nullable=True)
    os_family: Mapped[str | None] = mapped_column(Text, nullable=True)
    ports: Mapped[list] = mapped_column(JSONB, default=list)
    vulns: Mapped[list] = mapped_column(JSONB, default=list)
    criticality_score: Mapped[float] = mapped_column(Float, default=0.0)
    is_crown_jewel: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class TrustEdgeRecord(Base):
    __tablename__ = "trust_edges"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())
    snapshot_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    source_ip: Mapped[str] = mapped_column(INET)
    target_ip: Mapped[str] = mapped_column(INET)
    trust_type: Mapped[str] = mapped_column(String(20))
    weight: Mapped[float] = mapped_column(Float)
    evidence: Mapped[dict] = mapped_column(JSONB, default=dict)


class AttackPathRecord(Base):
    __tablename__ = "attack_paths"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())
    snapshot_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    source_host_ip: Mapped[str] = mapped_column(INET)
    target_host_ip: Mapped[str] = mapped_column(INET)
    path_hops: Mapped[list[str]] = mapped_column(ARRAY(INET))
    total_weight: Mapped[float] = mapped_column(Float)
    risk_score: Mapped[float] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AlertRecord(Base):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())
    snapshot_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    prev_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    alert_type: Mapped[str] = mapped_column(String(30))
    severity: Mapped[str] = mapped_column(String(10))
    description: Mapped[str] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
