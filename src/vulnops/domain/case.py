"""Operational risk snapshots for one canonical vulnerability and one asset."""

from enum import StrEnum
from typing import Self
from uuid import UUID, uuid4

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnops.domain.vulnerability import Vulnerability
from vulnops.workflow.states import CaseState


class AffectedStatus(StrEnum):
    """Asset-specific assessment, distinct from a source's version-range status."""

    AFFECTED = "AFFECTED"
    NOT_AFFECTED = "NOT_AFFECTED"
    UNKNOWN = "UNKNOWN"


class CaseExposure(BaseModel):
    """Reported exposure snapshot; None remains unknown, never implicitly False."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    internet_exposed: bool | None = None
    externally_reachable: bool | None = None


class VulnerabilityCase(BaseModel):
    """A validated snapshot, not an affectedness evaluator or lifecycle engine.

    Definitive affectedness requires evidence references. Their existence and
    suitability must be resolved by the future application/persistence boundary.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    case_id: UUID = Field(default_factory=uuid4)
    vulnerability_id: UUID
    cve_id: str | None = None
    asset_id: UUID
    state: CaseState = CaseState.DISCOVERED
    affected_status: AffectedStatus = AffectedStatus.UNKNOWN
    exposure: CaseExposure = Field(default_factory=CaseExposure)
    priority: str | None = Field(default=None, min_length=1)
    remediation_plan_id: UUID | None = None
    approval_id: UUID | None = None
    verification_id: UUID | None = None
    # Accept ordinary input lists/JSON arrays while retaining immutable references.
    evidence_ids: tuple[UUID, ...] = Field(default_factory=tuple, strict=False)
    created_at: AwareDatetime
    updated_at: AwareDatetime

    @field_validator("cve_id")
    @classmethod
    def validate_cve_id(cls, value: str | None) -> str | None:
        return Vulnerability.validate_cve_id(value)

    @model_validator(mode="after")
    def validate_snapshot(self) -> Self:
        if self.affected_status is not AffectedStatus.UNKNOWN and not self.evidence_ids:
            raise ValueError("AFFECTED and NOT_AFFECTED cases require evidence_ids")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        return self
