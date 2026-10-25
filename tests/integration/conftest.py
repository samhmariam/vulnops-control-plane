"""Real PostgreSQL fixtures. No SQLite or in-memory substitutes."""

from datetime import datetime, timezone
import os
from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import text

from vulnops.domain.asset import Asset, AssetType, Environment, InstalledComponent
from vulnops.domain.case import VulnerabilityCase
from vulnops.domain.evidence import Evidence, EvidenceSource
from vulnops.domain.product import AffectedProduct, ProductIdentity
from vulnops.domain.version import VersionConstraint, VersionStatus
from vulnops.domain.vulnerability import Vulnerability
from vulnops.persistence.repositories import Repositories
from vulnops.persistence.session import create_database_engine, tenant_session


@pytest.fixture(scope="session")
def database():
    app_url = os.environ.get("VULNOPS_TEST_DATABASE_URL")
    admin_url = os.environ.get("VULNOPS_TEST_ADMIN_DATABASE_URL")
    if not app_url or not admin_url:
        pytest.skip("Set VULNOPS_TEST_DATABASE_URL and VULNOPS_TEST_ADMIN_DATABASE_URL for PostgreSQL tests")
    admin = create_database_engine(admin_url)
    app = create_database_engine(app_url)
    try:
        configuration = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
        with admin.begin() as connection:
            configuration.attributes["connection"] = connection
            command.upgrade(configuration, "head")
        with app.connect() as connection:
            role = connection.execute(text(
                "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
            )).one()
            assert role == (False, False), "Integration tests must use a restricted runtime role"
        yield app, admin
    finally:
        app.dispose()
        admin.dispose()


@pytest.fixture
def tenant_id():
    return uuid4()


@pytest.fixture
def dataset():
    timestamp = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)
    evidence = Evidence(
        source_type=EvidenceSource.SYSTEM,
        source_name="synthetic-persistence-fixture",
        retrieved_at=timestamp,
        subject_type="fixture",
        subject_id="day1",
        claim_type="test_observation",
        claim="Synthetic records for testing storage behaviour, not security conclusions.",
    )
    identity = ProductIdentity(product="Widget", ecosystem="pypi", purl="pkg:pypi/widget")
    vulnerability = Vulnerability(
        cve_id="CVE-2026-12345",
        title="Synthetic fixture vulnerability",
        description="An attributable fixture claim.",
        evidence_ids=[evidence.evidence_id],
        affected_products=[AffectedProduct(
            product=identity, evidence_ids=[evidence.evidence_id],
            version_constraints=[VersionConstraint(exact_version="1.0", status=VersionStatus.AFFECTED)],
        )],
    )
    asset_id = uuid4()
    asset = Asset(
        asset_id=asset_id,
        external_id="fixture-inventory:asset-1",
        asset_type=AssetType.APPLICATION,
        environment=Environment.PRODUCTION,
        evidence_ids=[evidence.evidence_id],
        components=[InstalledComponent(
            asset_id=asset_id, identity=identity, installed_version="1.0",
            discovered_at=timestamp, source="fixture-inventory", evidence_ids=[evidence.evidence_id],
        )],
    )
    case = VulnerabilityCase(
        vulnerability_id=vulnerability.vulnerability_id, cve_id=vulnerability.cve_id,
        asset_id=asset.asset_id, evidence_ids=[evidence.evidence_id],
        created_at=timestamp, updated_at=timestamp,
    )
    return {"evidence": evidence, "vulnerability": vulnerability, "asset": asset, "case": case}


@pytest.fixture
def stored(database, tenant_id, dataset):
    with tenant_session(database[0], tenant_id) as session:
        repository = Repositories(session, tenant_id)
        repository.save_evidence(dataset["evidence"])
        repository.save_vulnerability(dataset["vulnerability"])
        repository.save_asset(dataset["asset"])
        repository.save_case(dataset["case"])
    return dataset
