"""Source-reported version constraints without universal comparison semantics."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class VersionStatus(StrEnum):
    """A source's version status, not an enterprise asset assessment."""

    AFFECTED = "AFFECTED"
    NOT_AFFECTED = "NOT_AFFECTED"
    UNKNOWN = "UNKNOWN"


class VersionConstraint(BaseModel):
    """One reported exact version or range; no ordering or matching is inferred.

    Introduced and last-affected endpoints are inclusive; fixed is exclusive.
    Adapters must only map source boundaries they can represent faithfully.
    Missing endpoints remain unknown, not evidence of safety or a missing fix.
    """

    model_config = ConfigDict(strict=True, extra="forbid", validate_assignment=True)

    exact_version: str | None = Field(default=None, min_length=1)
    introduced_version: str | None = Field(default=None, min_length=1)
    last_affected_version: str | None = Field(default=None, min_length=1)
    fixed_version: str | None = Field(default=None, min_length=1)
    status: VersionStatus = VersionStatus.UNKNOWN
    version_scheme: str | None = Field(default=None, min_length=1)
