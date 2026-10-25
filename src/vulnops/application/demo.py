"""Offline fixture-to-domain-to-assessment walking skeleton; no state writes."""

from pathlib import Path

from pydantic import BaseModel, ConfigDict

from vulnops.domain.asset import Asset
from vulnops.domain.evidence import Evidence
from vulnops.domain.vulnerability import Vulnerability
from vulnops.matching.affected_resolver import AffectedResolution, resolve_affected
from vulnops.matching.product_matcher import ProductMatchStatus
from vulnops.sources.fixtures import FixtureVulnerabilitySource, load_fixture_inventory


class DemoAssessment(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    cve_id: str
    result: AffectedResolution


class DemoReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    synthetic: bool = True
    persisted: bool = False
    scope: str = "Component/product assessments only; no asset-wide safety conclusion or lifecycle changes."
    vulnerabilities: list[Vulnerability]
    assets: list[Asset]
    evidence: list[Evidence]
    assessments: list[DemoAssessment]


def run_demo(lab_dir: Path) -> DemoReport:
    vulnerabilities = FixtureVulnerabilitySource(lab_dir / "fixtures").fetch()
    assets = load_fixture_inventory(lab_dir / "inventory")
    assessments = []
    for source in vulnerabilities:
        for inventory in assets:
            for component in inventory.asset.components:
                for product in source.vulnerability.affected_products:
                    result = resolve_affected(component, product)
                    if result.identity_status is not ProductMatchStatus.DIFFERENT:
                        assessments.append(DemoAssessment(cve_id=source.vulnerability.cve_id, result=result))
    return DemoReport(
        vulnerabilities=[item.vulnerability for item in vulnerabilities],
        assets=[item.asset for item in assets],
        evidence=[evidence for item in (*vulnerabilities, *assets) for evidence in item.evidence],
        assessments=assessments,
    )
