"""Product identity and source-reported applicability, independent of assets."""

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from vulnops.domain.version import VersionConstraint


class ProductIdentity(BaseModel):
    """Identifiers as supplied by an adapter; names alone do not prove a match."""

    model_config = ConfigDict(strict=True, extra="forbid", validate_assignment=True)

    vendor: str | None = None
    product: str = Field(min_length=1)
    ecosystem: str | None = None
    purl: str | None = None
    cpe: str | None = None
    package_name: str | None = None
    aliases: list[str] = Field(default_factory=list)


class AffectedProduct(BaseModel):
    """A product applicability claim, with provenance for its version constraints."""

    model_config = ConfigDict(strict=True, extra="forbid", validate_assignment=True)

    product: ProductIdentity
    version_constraints: list[VersionConstraint] = Field(default_factory=list)
    evidence_ids: list[UUID] = Field(min_length=1)
