"""Product identity retains machine identifiers and evidence attribution."""

from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnops.domain.product import AffectedProduct, ProductIdentity
from vulnops.domain.version import VersionConstraint


def test_product_preserves_multiple_identifiers_and_aliases():
    identity = ProductIdentity(
        vendor="Example",
        product="Widget",
        ecosystem="pypi",
        purl="pkg:pypi/example-widget",
        cpe="cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*",
        package_name="example-widget",
        aliases=["Widget Server", "Example Widget"],
    )

    assert ProductIdentity.model_validate_json(identity.model_dump_json()) == identity
    assert identity.purl == "pkg:pypi/example-widget"
    assert identity.cpe == "cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*"
    assert identity.package_name == "example-widget"
    assert identity.aliases == ["Widget Server", "Example Widget"]


def test_same_display_name_does_not_discard_distinct_package_identities():
    first = ProductIdentity(product="Widget", purl="pkg:pypi/widget")
    second = ProductIdentity(product="Widget", purl="pkg:npm/widget")

    assert first.product == second.product
    assert first.purl != second.purl
    assert first != second


def test_incomplete_identity_is_representable_without_inventing_identifiers():
    identity = ProductIdentity(product="Widget")

    assert identity.vendor is None
    assert identity.purl is None
    assert identity.cpe is None
    assert identity.package_name is None


def test_product_defaults_are_independent():
    first = ProductIdentity(product="Widget")
    second = ProductIdentity(product="Widget")
    first.aliases.append("Observed alias")

    assert second.aliases == []


def test_affected_product_can_represent_unknown_versions():
    evidence_id = uuid4()
    affected = AffectedProduct(product=ProductIdentity(product="Widget"), evidence_ids=[evidence_id])

    assert affected.version_constraints == []
    assert affected.evidence_ids == [evidence_id]


@pytest.mark.parametrize("evidence_ids", [[], ["not-a-uuid"]])
def test_affected_product_requires_typed_evidence_references(evidence_ids):
    with pytest.raises(ValidationError):
        AffectedProduct(product=ProductIdentity(product="Widget"), evidence_ids=evidence_ids)


@pytest.mark.parametrize(
    ("model", "fields"),
    [
        (ProductIdentity, {"product": "Widget", "upstream_only": True}),
        (
            AffectedProduct,
            {"product": ProductIdentity(product="Widget"), "evidence_ids": [uuid4()], "risk": 9.0},
        ),
        (VersionConstraint, {"unrecognised_boundary": "1.2"}),
    ],
)
def test_unknown_fields_require_explicit_adapter_mapping(model, fields):
    with pytest.raises(ValidationError) as error:
        model(**fields)

    assert error.value.errors()[0]["type"] == "extra_forbidden"
