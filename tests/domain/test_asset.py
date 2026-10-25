"""Asset context stays separate from vulnerability claims and preserves uncertainty."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from vulnops.domain.asset import (
    Asset,
    AssetType,
    BusinessCriticality,
    Environment,
    InstalledComponent,
)
from vulnops.domain.evidence import Evidence, EvidenceSource
from vulnops.domain.product import ProductIdentity


@pytest.fixture
def asset_fields():
    return {
        "asset_id": uuid4(),
        "asset_type": AssetType.APPLICATION,
        "evidence_ids": [uuid4()],
    }


@pytest.fixture
def component_fields(asset_fields):
    return {
        "asset_id": asset_fields["asset_id"],
        "identity": ProductIdentity(product="Widget", purl="pkg:pypi/widget"),
        "installed_version": "1.2.3",
        "discovered_at": datetime(2026, 10, 25, 10, 0, tzinfo=timezone.utc),
        "source": "enterprise-inventory",
        "evidence_ids": [uuid4()],
    }


def test_production_internet_facing_asset(asset_fields, component_fields):
    component = InstalledComponent(**component_fields)
    asset = Asset(
        **asset_fields,
        external_id="cmdb:payroll-001",
        hostname="payroll.example.test",
        environment=Environment.PRODUCTION,
        business_service="Payroll",
        business_criticality=BusinessCriticality.CRITICAL,
        internet_exposed=True,
        externally_reachable=True,
        data_classification="confidential",
        owner="payroll-platform-team",
        components=[component],
    )

    assert asset.environment is Environment.PRODUCTION
    assert asset.internet_exposed is True
    assert asset.externally_reachable is True
    assert asset.business_criticality is BusinessCriticality.CRITICAL
    assert asset.components[0].asset_id == asset.asset_id
    assert asset.components[0].identity.purl == "pkg:pypi/widget"
    assert Asset.model_validate_json(asset.model_dump_json()) == asset


def test_internal_application(asset_fields):
    asset = Asset(
        **asset_fields,
        hostname="internal.example.test",
        environment=Environment.PRODUCTION,
        business_service="Employee portal",
        business_criticality=BusinessCriticality.HIGH,
        internet_exposed=False,
        externally_reachable=False,
        owner="workplace-platform-team",
    )

    assert asset.asset_type is AssetType.APPLICATION
    assert asset.internet_exposed is False
    assert asset.externally_reachable is False
    assert asset.business_service == "Employee portal"


def test_unknown_environment_and_exposure_are_not_inferred(asset_fields):
    asset = Asset(**asset_fields)

    assert asset.environment is Environment.UNKNOWN
    assert asset.business_criticality is BusinessCriticality.UNKNOWN
    assert asset.internet_exposed is None
    assert asset.externally_reachable is None
    assert asset.owner is None
    assert asset.components == []


@pytest.mark.parametrize("asset_type", list(AssetType))
def test_all_asset_types_allow_resources_without_hostnames(asset_fields, asset_type):
    asset = Asset(**{**asset_fields, "asset_type": asset_type})

    assert asset.asset_type is asset_type
    assert asset.hostname is None


@pytest.mark.parametrize("environment", list(Environment))
def test_all_environments_are_representable(asset_fields, environment):
    assert Asset(**asset_fields, environment=environment).environment is environment


def test_multiple_installed_components_keep_distinct_identity_and_provenance(
    asset_fields, component_fields
):
    first = InstalledComponent(**component_fields)
    second = InstalledComponent(
        **{
            **component_fields,
            "identity": ProductIdentity(product="Other", package_name="other"),
            "installed_version": "2:4.1-1ubuntu2",
            "source": "authenticated-scanner",
            "evidence_ids": [uuid4()],
        }
    )
    asset = Asset(**asset_fields, components=[first, second])

    assert asset.components == [first, second]
    assert first.component_id != second.component_id
    assert second.installed_version == "2:4.1-1ubuntu2"
    assert first.evidence_ids != second.evidence_ids


@pytest.mark.parametrize("evidence_ids", [None, [], ["not-a-uuid"]])
def test_missing_or_invalid_component_evidence_is_rejected(component_fields, evidence_ids):
    fields = {**component_fields, "evidence_ids": evidence_ids}
    if evidence_ids is None:
        fields.pop("evidence_ids")

    with pytest.raises(ValidationError) as error:
        InstalledComponent(**fields)

    assert error.value.errors()[0]["loc"][0] == "evidence_ids"


def test_component_observation_links_to_evidence(asset_fields, component_fields):
    evidence = Evidence(
        source_type=EvidenceSource.ASSET_INVENTORY,
        source_name=component_fields["source"],
        retrieved_at=component_fields["discovered_at"],
        subject_type="asset",
        subject_id=str(asset_fields["asset_id"]),
        claim_type="installed_version",
        claim="Inventory reports Widget version 1.2.3.",
    )
    component = InstalledComponent(
        **{**component_fields, "evidence_ids": [evidence.evidence_id]}
    )

    assert component.evidence_ids == [evidence.evidence_id]
    assert component.source == evidence.source_name


def test_unknown_component_version_is_not_fabricated(component_fields):
    component_fields.pop("installed_version")
    component = InstalledComponent(**component_fields)

    assert component.installed_version is None
    assert component.identity.package_name is None


def test_naive_discovery_time_is_rejected(component_fields):
    with pytest.raises(ValidationError) as error:
        InstalledComponent(**{**component_fields, "discovered_at": datetime(2026, 10, 25)})

    assert error.value.errors()[0]["type"] == "timezone_aware"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("asset_type", "APPLICATION"),
        ("environment", "PRODUCTION"),
        ("business_criticality", 5),
        ("internet_exposed", "false"),
        ("externally_reachable", 1),
        ("asset_id", "not-a-uuid"),
    ],
)
def test_asset_python_values_are_strictly_typed(asset_fields, field, value):
    with pytest.raises(ValidationError) as error:
        Asset(**{**asset_fields, field: value})

    assert error.value.errors()[0]["loc"] == (field,)


@pytest.mark.parametrize(("field", "value"), [("installed_version", 1.2), ("source", 42)])
def test_component_python_values_are_strictly_typed(component_fields, field, value):
    with pytest.raises(ValidationError):
        InstalledComponent(**{**component_fields, field: value})


def test_extra_cmdb_and_component_fields_are_rejected(asset_fields, component_fields):
    for model, fields, extra in (
        (Asset, asset_fields, {"purchase_order": "PO-123"}),
        (InstalledComponent, component_fields, {"risk_score": 9.8}),
    ):
        with pytest.raises(ValidationError) as error:
            model(**fields, **extra)
        assert error.value.errors()[0]["type"] == "extra_forbidden"


def test_asset_requires_provenance(asset_fields):
    with pytest.raises(ValidationError):
        Asset(**{**asset_fields, "evidence_ids": []})


def test_component_cannot_reference_a_different_asset(asset_fields, component_fields):
    component = InstalledComponent(**{**component_fields, "asset_id": uuid4()})

    with pytest.raises(ValidationError, match="containing asset_id"):
        Asset(**asset_fields, components=[component])


def test_component_list_assignment_rejects_wrong_asset_without_changing_list(
    asset_fields, component_fields
):
    asset = Asset(**asset_fields)
    component = InstalledComponent(**{**component_fields, "asset_id": uuid4()})

    with pytest.raises(ValidationError):
        asset.components = [component]

    assert asset.components == []


def test_identity_fields_cannot_silently_reparent_components(asset_fields, component_fields):
    asset = Asset(**asset_fields)
    component = InstalledComponent(**component_fields)
    for model, field in ((asset, "asset_id"), (component, "asset_id"), (component, "component_id")):
        original = getattr(model, field)
        with pytest.raises(ValidationError):
            setattr(model, field, uuid4())
        assert getattr(model, field) == original


def test_generated_asset_id_and_component_defaults_are_independent():
    first = Asset(asset_type=AssetType.VM, evidence_ids=[uuid4()])
    second = Asset(asset_type=AssetType.VM, evidence_ids=[uuid4()])

    assert isinstance(first.asset_id, UUID)
    assert first.asset_id != second.asset_id
    assert first.components is not second.components
