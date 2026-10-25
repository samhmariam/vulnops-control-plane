"""Synthetic source claims; no network, database, or probabilistic matching."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from vulnops.domain.asset import InstalledComponent
from vulnops.domain.product import AffectedProduct, ProductIdentity
from vulnops.domain.version import VersionConstraint, VersionStatus


@pytest.fixture
def component():
    return InstalledComponent(
        asset_id=uuid4(), identity=ProductIdentity(product="Widget", purl="pkg:pypi/widget"),
        installed_version="1.5.0", discovered_at=datetime(2026, 10, 25, tzinfo=timezone.utc),
        source="synthetic-inventory", evidence_ids=[uuid4()],
    )


@pytest.fixture
def affected_product():
    return AffectedProduct(
        product=ProductIdentity(product="Widget", purl="pkg:pypi/widget"),
        version_constraints=[VersionConstraint(
            introduced_version="1.0.0", fixed_version="2.0.0",
            version_scheme="semver", status=VersionStatus.AFFECTED,
        )],
        evidence_ids=[uuid4()],
    )
