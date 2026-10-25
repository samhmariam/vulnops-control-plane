"""Evidence-linked resolution of one installed-component/product candidate pair."""

from uuid import UUID

from pydantic import BaseModel, ConfigDict

from vulnops.domain.asset import InstalledComponent
from vulnops.domain.case import AffectedStatus
from vulnops.domain.product import AffectedProduct, ProductIdentity
from vulnops.domain.version import VersionStatus
from vulnops.matching.product_matcher import ProductMatchMethod, ProductMatchStatus, match_product
from vulnops.matching.version_matcher import match_version


class AffectedResolution(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    status: AffectedStatus
    component_id: UUID
    asset_id: UUID
    matched_component_id: UUID | None
    matched_product: ProductIdentity | None
    identity_status: ProductMatchStatus
    reason: str
    evidence_ids: tuple[UUID, ...]
    matching_method: ProductMatchMethod
    version_method: str | None
    certainty_explanation: str


def resolve_affected(component: InstalledComponent, affected_product: AffectedProduct) -> AffectedResolution:
    """Assess only this pair; never close a case or declare an entire asset safe."""
    component = InstalledComponent.model_validate_json(component.model_dump_json())
    affected_product = AffectedProduct.model_validate_json(affected_product.model_dump_json())
    identity = match_product(component.identity, affected_product.product)
    status = AffectedStatus.UNKNOWN
    reason = identity.reason
    version_method = None
    if identity.status is ProductMatchStatus.DIFFERENT:
        status = AffectedStatus.NOT_AFFECTED
    elif identity.status is ProductMatchStatus.MATCH:
        hints = (*identity.component_version_hints, *identity.product_version_hints)
        if hints and any(hint != component.installed_version for hint in hints):
            reason = "Structured version hints disagree with the installed version or constrain a different release."
        else:
            version = match_version(component.installed_version, affected_product.version_constraints)
            status, version_method = version.status, version.method
            reason = f"{identity.reason} {version.reason}"
            if identity.method is ProductMatchMethod.VENDOR_PRODUCT and status is AffectedStatus.NOT_AFFECTED:
                status = AffectedStatus.UNKNOWN
                reason = "Name-only identity cannot justify a definitive version-based exclusion."
            if (
                identity.product_version_hints and status is AffectedStatus.NOT_AFFECTED
                and any(constraint.status is VersionStatus.AFFECTED for constraint in affected_product.version_constraints)
            ):
                status = AffectedStatus.UNKNOWN
                reason = "Version-specific product identity conflicts with the supplied affected-range exclusion."
    return AffectedResolution(
        status=status, component_id=component.component_id, asset_id=component.asset_id,
        matched_component_id=component.component_id if identity.status is ProductMatchStatus.MATCH else None,
        matched_product=affected_product.product if identity.status is ProductMatchStatus.MATCH else None,
        identity_status=identity.status, reason=reason,
        evidence_ids=tuple(dict.fromkeys((*component.evidence_ids, *affected_product.evidence_ids))),
        matching_method=identity.method, version_method=version_method,
        certainty_explanation=(
            "Deterministic evaluation of the supplied candidate pair and source claims only; "
            "no probabilistic score, source-truth guarantee, or asset-wide safety conclusion."
        ),
    )
