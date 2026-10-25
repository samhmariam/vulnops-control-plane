"""Evidence-linked pair resolution, with no automatic case or asset conclusions."""

from uuid import uuid4

import pytest

from vulnops.domain.case import AffectedStatus
from vulnops.domain.product import ProductIdentity
from vulnops.domain.version import VersionConstraint, VersionStatus
from vulnops.matching.affected_resolver import AffectedResolution, resolve_affected
from vulnops.matching.product_matcher import ProductMatchMethod, ProductMatchStatus


def test_known_affected_version_has_matched_records_reason_and_evidence(component, affected_product):
    result = resolve_affected(component, affected_product)

    assert result.status is AffectedStatus.AFFECTED
    assert result.component_id == result.matched_component_id == component.component_id
    assert result.asset_id == component.asset_id
    assert result.matched_product == affected_product.product
    assert result.matching_method is ProductMatchMethod.PURL
    assert result.identity_status is ProductMatchStatus.MATCH
    assert result.evidence_ids == tuple([*component.evidence_ids, *affected_product.evidence_ids])
    assert result.reason
    assert result.certainty_explanation
    assert AffectedResolution.model_validate_json(result.model_dump_json()) == result


def test_known_fixed_version_is_not_affected_by_this_pair(component, affected_product):
    component.installed_version = "2.0.0"

    assert resolve_affected(component, affected_product).status is AffectedStatus.NOT_AFFECTED


def test_different_structured_product_excludes_only_this_candidate_pair(component, affected_product):
    component.identity = ProductIdentity(product="Other", purl="pkg:pypi/other")
    result = resolve_affected(component, affected_product)

    assert result.status is AffectedStatus.NOT_AFFECTED
    assert result.identity_status is ProductMatchStatus.DIFFERENT
    assert result.matched_component_id is None
    assert result.matched_product is None


def test_ambiguous_identity_is_unknown_even_with_known_fixed_version(component, affected_product):
    component.identity = ProductIdentity(product="Widget")
    component.installed_version = "2.0.0"
    affected_product.product = ProductIdentity(product="Widget")

    assert resolve_affected(component, affected_product).status is AffectedStatus.UNKNOWN


def test_unknown_version_is_not_cleared_by_a_structured_identity_match(component, affected_product):
    component.installed_version = None

    assert resolve_affected(component, affected_product).status is AffectedStatus.UNKNOWN


def test_package_name_and_vendor_product_fallbacks_can_support_affectedness(component, affected_product):
    for identity, method in (
        (ProductIdentity(product="Widget", ecosystem="pypi", package_name="widget"), ProductMatchMethod.PACKAGE),
        (ProductIdentity(vendor="Example", product="Widget"), ProductMatchMethod.VENDOR_PRODUCT),
    ):
        component.identity = identity
        affected_product.product = identity
        result = resolve_affected(component, affected_product)
        assert result.status is AffectedStatus.AFFECTED
        assert result.matching_method is method


def test_name_only_identity_cannot_create_false_reassurance_from_a_fixed_version(component, affected_product):
    component.identity = ProductIdentity(vendor="Example", product="Widget")
    affected_product.product = ProductIdentity(vendor="Example", product="Widget")
    component.installed_version = "2.0.0"

    assert resolve_affected(component, affected_product).status is AffectedStatus.UNKNOWN


@pytest.mark.parametrize("side", ["component", "affected_product"])
def test_identifier_version_disagreement_is_unknown(component, affected_product, side):
    identity = ProductIdentity(product="Widget", purl="pkg:pypi/widget@1.0.0")
    if side == "component":
        component.identity = identity
    else:
        affected_product.product = identity

    assert resolve_affected(component, affected_product).status is AffectedStatus.UNKNOWN


@pytest.mark.parametrize("identifier", ["purl", "cpe"])
def test_version_specific_product_scope_conflicting_with_fixed_boundary_is_unknown(component, affected_product, identifier):
    component.installed_version = "2.0.0"
    if identifier == "purl":
        affected_product.product.purl = "pkg:pypi/widget@2.0.0"
    else:
        component.identity = ProductIdentity(product="Widget", cpe="cpe:2.3:a:example:widget:2.0.0:*:*:*:*:*:*:*")
        affected_product.product = ProductIdentity(product="Widget", cpe="cpe:2.3:a:example:widget:2.0.0:*:*:*:*:*:*:*")

    assert resolve_affected(component, affected_product).status is AffectedStatus.UNKNOWN


def test_version_specific_explicit_exemption_is_not_a_conflicting_affected_claim(component, affected_product):
    affected_product.product.purl = "pkg:pypi/widget@1.5.0"
    affected_product.version_constraints = [VersionConstraint(
        exact_version="1.5.0", status=VersionStatus.NOT_AFFECTED,
    )]

    assert resolve_affected(component, affected_product).status is AffectedStatus.NOT_AFFECTED


def test_unsupported_semantics_remain_unknown_regardless_of_source_certainty(component, affected_product):
    affected_product.version_constraints = [VersionConstraint(
        fixed_version="2.0.0", version_scheme="vendor-specific", status=VersionStatus.AFFECTED,
    )]

    result = resolve_affected(component, affected_product)

    assert result.status is AffectedStatus.UNKNOWN
    assert "confidence" not in result.model_dump()


def test_resolution_does_not_mutate_inputs_and_evidence_is_deduplicated(component, affected_product):
    affected_product.evidence_ids.append(component.evidence_ids[0])
    component_before = component.model_dump()
    product_before = affected_product.model_dump()
    result = resolve_affected(component, affected_product)

    assert component.model_dump() == component_before
    assert affected_product.model_dump() == product_before
    assert len(result.evidence_ids) == 2
    component.evidence_ids.append(uuid4())
    assert len(result.evidence_ids) == 2
