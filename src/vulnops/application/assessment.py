"""Conservative asset-level aggregation over complete fixture inventory claims."""

from pydantic import BaseModel, ConfigDict
from uuid import UUID

from vulnops.domain.asset import Asset
from vulnops.domain.case import AffectedStatus
from vulnops.domain.evidence import Evidence, EvidenceSource
from vulnops.domain.vulnerability import Vulnerability
from vulnops.matching.affected_resolver import AffectedResolution, resolve_affected
from vulnops.matching.product_matcher import ProductMatchStatus


class AssetAssessment(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    asset_id: UUID
    status: AffectedStatus
    candidate: bool
    inventory_complete: bool
    reason: str
    comparisons: list[AffectedResolution]
    evidence_ids: tuple[UUID, ...]


def assess_asset(vulnerability: Vulnerability, asset: Asset, evidence: list[Evidence]) -> AssetAssessment:
    records = {item.evidence_id: item for item in evidence}
    required = set(vulnerability.evidence_ids) | set(asset.evidence_ids)
    required.update(ref for product in vulnerability.affected_products for ref in product.evidence_ids)
    required.update(ref for component in asset.components for ref in component.evidence_ids)
    if not required <= records.keys():
        raise ValueError("Assessment requires resolved evidence")
    inventory_claims = [item for item in evidence if item.evidence_id in asset.evidence_ids
                        and item.source_type is EvidenceSource.ASSET_INVENTORY
                        and item.subject_type == "asset" and item.subject_id == str(asset.asset_id)]
    complete = bool(inventory_claims) and all(
        item.metadata.get("component_inventory_complete") is True for item in inventory_claims
    )
    comparisons = [resolve_affected(component, product)
                   for component in asset.components for product in vulnerability.affected_products]
    candidate = not comparisons or any(item.identity_status is not ProductMatchStatus.DIFFERENT for item in comparisons)
    statuses = {item.status for item in comparisons}
    # Conflicting or unsupported observations must not be outvoted by another match.
    if AffectedStatus.UNKNOWN in statuses or not comparisons:
        status, reason = AffectedStatus.UNKNOWN, "Missing, ambiguous, or conflicting component/product evidence."
    elif AffectedStatus.AFFECTED in statuses:
        status, reason = AffectedStatus.AFFECTED, "At least one supported component/product comparison is affected."
    elif complete:
        status, reason = AffectedStatus.NOT_AFFECTED, "Complete inventory claim and every component/product comparison excludes affectedness."
    else:
        status, reason = AffectedStatus.UNKNOWN, "No affected match, but inventory completeness is not established."
    return AssetAssessment(
        asset_id=asset.asset_id, status=status, candidate=candidate, inventory_complete=complete,
        reason=reason, comparisons=comparisons, evidence_ids=tuple(sorted(required, key=str)),
    )
