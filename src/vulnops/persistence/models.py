"""Relational identities and validated domain snapshots stored as JSONB."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, ForeignKeyConstraint, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class TenantSnapshot:
    tenant_id: Mapped[UUID] = mapped_column(primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)


class VulnerabilityRecord(TenantSnapshot, Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (UniqueConstraint("tenant_id", "cve_id", name="uq_vulnerabilities_cve"),)

    vulnerability_id: Mapped[UUID] = mapped_column(primary_key=True)
    cve_id: Mapped[str | None] = mapped_column(String)


class AssetRecord(TenantSnapshot, Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("tenant_id", "external_id", name="uq_assets_external_id"),)

    asset_id: Mapped[UUID] = mapped_column(primary_key=True)
    external_id: Mapped[str | None] = mapped_column(String)


class InstalledComponentRecord(TenantSnapshot, Base):
    __tablename__ = "installed_components"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "asset_id"], ["assets.tenant_id", "assets.asset_id"]),
        UniqueConstraint("tenant_id", "asset_id", "position", name="uq_component_position"),
    )

    component_id: Mapped[UUID] = mapped_column(primary_key=True)
    asset_id: Mapped[UUID] = mapped_column(nullable=False)
    position: Mapped[int] = mapped_column(Integer, nullable=False)


class EvidenceRecord(TenantSnapshot, Base):
    __tablename__ = "evidence"

    evidence_id: Mapped[UUID] = mapped_column(primary_key=True)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CaseRecord(TenantSnapshot, Base):
    __tablename__ = "vulnerability_cases"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "vulnerability_id"],
            ["vulnerabilities.tenant_id", "vulnerabilities.vulnerability_id"],
        ),
        ForeignKeyConstraint(["tenant_id", "asset_id"], ["assets.tenant_id", "assets.asset_id"]),
        UniqueConstraint("tenant_id", "vulnerability_id", "asset_id", name="uq_case_pair"),
    )

    case_id: Mapped[UUID] = mapped_column(primary_key=True)
    vulnerability_id: Mapped[UUID] = mapped_column(nullable=False)
    asset_id: Mapped[UUID] = mapped_column(nullable=False)
    state: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class CaseEventRecord(TenantSnapshot, Base):
    __tablename__ = "case_events"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "case_id"], ["vulnerability_cases.tenant_id", "vulnerability_cases.case_id"]),
        UniqueConstraint("tenant_id", "case_id", "sequence", name="uq_case_event_sequence"),
    )

    event_id: Mapped[UUID] = mapped_column(primary_key=True)
    case_id: Mapped[UUID] = mapped_column(nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
