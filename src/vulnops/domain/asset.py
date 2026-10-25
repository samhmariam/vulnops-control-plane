"""Minimal enterprise context and attributable installed-component observations."""

from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from vulnops.domain.product import ProductIdentity


class AssetType(StrEnum):
    """Supported categories of enterprise resources."""

    VM = "VM"
    CONTAINER = "CONTAINER"
    APPLICATION = "APPLICATION"
    REPOSITORY = "REPOSITORY"
    MANAGED_SERVICE = "MANAGED_SERVICE"


class Environment(StrEnum):
    PRODUCTION = "PRODUCTION"
    STAGING = "STAGING"
    DEVELOPMENT = "DEVELOPMENT"
    TEST = "TEST"
    UNKNOWN = "UNKNOWN"


class BusinessCriticality(StrEnum):
    """Business-provided impact context, not a computed vulnerability risk score."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class InstalledComponent(BaseModel):
    """A discovered product on one asset, with provenance and an optional version."""

    model_config = ConfigDict(strict=True, extra="forbid", validate_assignment=True)

    component_id: UUID = Field(default_factory=uuid4, frozen=True)
    asset_id: UUID = Field(frozen=True)
    identity: ProductIdentity
    installed_version: str | None = Field(default=None, min_length=1)
    discovered_at: AwareDatetime
    source: str = Field(min_length=1)
    evidence_ids: list[UUID] = Field(min_length=1)


class Asset(BaseModel):
    """Evidence-backed enterprise context consumed from upstream systems.

    None exposure flags mean unknown, not False. An empty component list does
    not establish a complete inventory or prove the asset is unaffected.
    """

    model_config = ConfigDict(strict=True, extra="forbid", validate_assignment=True)

    asset_id: UUID = Field(default_factory=uuid4, frozen=True)
    external_id: str | None = Field(default=None, min_length=1)
    hostname: str | None = Field(default=None, min_length=1)
    asset_type: AssetType
    environment: Environment = Environment.UNKNOWN
    business_service: str | None = None
    business_criticality: BusinessCriticality = BusinessCriticality.UNKNOWN
    internet_exposed: bool | None = None
    externally_reachable: bool | None = None
    data_classification: str | None = None
    owner: str | None = None
    components: list[InstalledComponent] = Field(default_factory=list)
    evidence_ids: list[UUID] = Field(min_length=1)

    @field_validator("components")
    @classmethod
    def validate_component_ownership(
        cls, components: list[InstalledComponent], info: ValidationInfo
    ) -> list[InstalledComponent]:
        asset_id = info.data.get("asset_id")
        if asset_id is not None and any(component.asset_id != asset_id for component in components):
            raise ValueError("Every installed component must reference its containing asset_id")
        return components
