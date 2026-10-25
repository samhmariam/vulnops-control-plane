"""Attributable observations; evidence does not establish truth or decide risk."""

from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class EvidenceSource(StrEnum):
    """Supported categories of evidence provenance."""

    CVE = "CVE"
    CISA_KEV = "CISA_KEV"
    EPSS = "EPSS"
    VENDOR = "VENDOR"
    ASSET_INVENTORY = "ASSET_INVENTORY"
    SBOM = "SBOM"
    VULNERABILITY_SCANNER = "VULNERABILITY_SCANNER"
    HUMAN = "HUMAN"
    SYSTEM = "SYSTEM"


class Evidence(BaseModel):
    """A source's claim with provenance, separate from findings and decisions.

    Claim and metadata content remain untrusted data. Confidence describes the
    observation and never establishes correctness, affectedness, or risk.
    """

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        validate_assignment=True,
    )

    evidence_id: UUID = Field(default_factory=uuid4)
    source_type: EvidenceSource
    source_name: str
    source_uri: str | None = None
    retrieved_at: AwareDatetime
    source_published_at: AwareDatetime | None = None
    subject_type: str
    subject_id: str
    claim_type: str
    claim: str
    raw_payload_hash: str | None = None
    confidence: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    metadata: dict[str, Any] = Field(default_factory=dict)
