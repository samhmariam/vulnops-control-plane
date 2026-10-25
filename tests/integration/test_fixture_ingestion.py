"""Offline source-to-domain ingestion and PostgreSQL replay contracts."""

from pathlib import Path

import pytest
from sqlalchemy import func, select

from vulnops.matching.affected_resolver import resolve_affected
from vulnops.persistence.models import AssetRecord, VulnerabilityRecord
from vulnops.persistence.repositories import Repositories
from vulnops.persistence.session import tenant_session
from vulnops.sources.base import VulnerabilitySource
from vulnops.sources.fixtures import FixtureVulnerabilitySource, load_fixture_inventory


LAB = Path(__file__).resolve().parents[2] / "lab"


def test_fixture_source_reaches_canonical_domain_and_matching():
    source = FixtureVulnerabilitySource(LAB / "fixtures")
    assert isinstance(source, VulnerabilitySource)
    vulnerabilities = {item.vulnerability.cve_id: item for item in source.fetch()}
    assets = {item.asset.external_id.split(":")[1]: item.asset
              for item in load_fixture_inventory(LAB / "inventory")}
    assert len(vulnerabilities) == 5
    assert len(assets) == 6
    # Independent expected outcomes, never fields supplied by the source.
    expectations = [
        (1, "asset-web-01", "web", "AFFECTED"),
        (1, "asset-web-02", "web", "NOT_AFFECTED"),
        (1, "asset-dev-01", "web", "AFFECTED"),
        (1, "asset-legacy-01", "web", "UNKNOWN"),
        (2, "asset-web-01", "common", "AFFECTED"),
        (2, "asset-web-02", "common", "NOT_AFFECTED"),
        (2, "asset-api-01", "common", "AFFECTED"),
        (2, "asset-dev-01", "common", "AFFECTED"),
        (3, "asset-api-01", "api", "AFFECTED"),
        (3, "asset-dev-01", "api", "AFFECTED"),
        (4, "asset-db-01", "store", "NOT_AFFECTED"),
        (5, "asset-legacy-01", "legacy", "UNKNOWN"),
    ]
    for number, asset_name, package, expected in expectations:
        vulnerability = vulnerabilities[f"CVE-2099-90000{number}"].vulnerability
        component = next(item for item in assets[asset_name].components
                         if item.identity.package_name == "vulnops-lab-" + package)
        result = resolve_affected(component, vulnerability.affected_products[0])
        assert result.status.value == expected
        assert result.evidence_ids and result.reason
    no_fix = vulnerabilities["CVE-2099-900003"].vulnerability
    assert all(item.fixed_version is None for item in no_fix.affected_products[0].version_constraints)
    assert vulnerabilities["CVE-2099-900001"].vulnerability.kev_observation.listed
    assert vulnerabilities["CVE-2099-900001"].vulnerability.epss_observation.probability == 0.8
    assert assets["asset-web-01"].internet_exposed is True
    assert assets["asset-web-01"].business_criticality.value == "CRITICAL"
    assert assets["asset-api-01"].internet_exposed is False
    assert assets["asset-dev-01"].environment.value == "DEVELOPMENT"
    assert assets["asset-db-01"].data_classification == "RESTRICTED"
    assert assets["asset-legacy-01"].environment.value == "UNKNOWN"


@pytest.mark.integration
def test_fixture_snapshots_persist_and_replay_without_duplicates(database, tenant_id):
    source = FixtureVulnerabilitySource(LAB / "fixtures")
    for _ in range(2):
        vulnerabilities = source.fetch()
        assets = load_fixture_inventory(LAB / "inventory")
        with tenant_session(database[0], tenant_id) as session:
            repository = Repositories(session, tenant_id)
            for item in (*vulnerabilities, *assets):
                for evidence in item.evidence:
                    repository.save_evidence(evidence)
            for item in vulnerabilities:
                assert repository.save_vulnerability(item.vulnerability) == item.vulnerability
            for item in assets:
                assert repository.save_asset(item.asset) == item.asset
    with tenant_session(database[0], tenant_id) as session:
        repository = Repositories(session, tenant_id)
        assert session.scalar(select(func.count()).select_from(VulnerabilityRecord).where(VulnerabilityRecord.tenant_id == tenant_id)) == 5
        assert session.scalar(select(func.count()).select_from(AssetRecord).where(AssetRecord.tenant_id == tenant_id)) == 6
        for item in vulnerabilities:
            assert repository.load_vulnerability(item.vulnerability.vulnerability_id) == item.vulnerability
        for item in assets:
            assert repository.load_asset(item.asset.asset_id) == item.asset
        assert repository.list_assets(limit=100, offset=0) == sorted(
            [item.asset for item in assets], key=lambda asset: asset.asset_id,
        )
