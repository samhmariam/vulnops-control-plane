"""Identifier precedence, scoped comparisons, and ambiguity handling."""

import pytest

from vulnops.domain.product import ProductIdentity
from vulnops.matching.product_matcher import ProductMatchMethod, ProductMatchStatus, match_product


@pytest.mark.parametrize(
    ("left", "right", "method"),
    [
        ({"purl": "pkg:pypi/widget@1.5.0"}, {"purl": "pkg:pypi/widget"}, ProductMatchMethod.PURL),
        ({"purl": "pkg:pypi/My_Widget"}, {"purl": "pkg:pypi/my.widget"}, ProductMatchMethod.PURL),
        ({"purl": "pkg:npm/%40example/widget"}, {"purl": "pkg:npm/%40example/widget"}, ProductMatchMethod.PURL),
        ({"purl": "pkg:pypi/widget"}, {"ecosystem": "pypi", "package_name": "widget"}, ProductMatchMethod.PACKAGE),
        (
            {"cpe": "cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*"},
            {"cpe": "cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*"}, ProductMatchMethod.CPE,
        ),
        ({"ecosystem": "pypi", "package_name": "My_Widget"}, {"ecosystem": "pypi", "package_name": "my.widget"}, ProductMatchMethod.PACKAGE),
        ({"ecosystem": "npm", "package_name": "@example/widget"}, {"ecosystem": "npm", "package_name": "@example/widget"}, ProductMatchMethod.PACKAGE),
        ({"vendor": " Example   Corp ", "product": "WIDGET"}, {"vendor": "example corp", "product": " widget "}, ProductMatchMethod.VENDOR_PRODUCT),
    ],
)
def test_supported_identity_matches(left, right, method):
    result = match_product(ProductIdentity(**{"product": "Widget", **left}), ProductIdentity(**{"product": "Widget", **right}))

    assert result.status is ProductMatchStatus.MATCH
    assert result.method is method
    assert result.reason


def test_purl_is_preferred_when_other_structured_identifiers_agree():
    identity = ProductIdentity(
        product="Widget", purl="pkg:pypi/widget", ecosystem="pypi", package_name="widget",
        cpe="cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*",
    )

    assert match_product(identity, identity).method is ProductMatchMethod.PURL


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ({"purl": "pkg:pypi/widget"}, {"purl": "pkg:pypi/other"}),
        ({"ecosystem": "pypi", "package_name": "widget"}, {"ecosystem": "pypi", "package_name": "other"}),
        ({"cpe": "cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*"}, {"cpe": "cpe:2.3:a:example:other:*:*:*:*:*:*:*:*"}),
    ],
)
def test_distinct_structured_products_are_different_for_this_pair(left, right):
    result = match_product(ProductIdentity(product="Label", **left), ProductIdentity(product="Label", **right))

    assert result.status is ProductMatchStatus.DIFFERENT


def test_conflicting_purl_and_cpe_cannot_be_resolved_by_identifier_priority():
    left = ProductIdentity(product="Widget", purl="pkg:pypi/widget", cpe="cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*")
    right = ProductIdentity(product="Widget", purl="pkg:pypi/widget", cpe="cpe:2.3:a:example:other:*:*:*:*:*:*:*:*")

    result = match_product(left, right)

    assert result.status is ProductMatchStatus.UNKNOWN
    assert result.method is ProductMatchMethod.CONFLICT


@pytest.mark.parametrize(
    "fields",
    [
        {"purl": "not-a-purl", "vendor": "Example"},
        {"purl": "pkg:generic/*", "vendor": "Example"},
        {"purl": "pkg:pypi/widget", "ecosystem": "pypi", "package_name": "other"},
        {"purl": "pkg:pypi/widget", "ecosystem": "npm"},
        {"cpe": "cpe:/a:example:widget"},
        {"cpe": "cpe:2.3:a:*:widget:*:*:*:*:*:*:*:*"},
        {"cpe": "cpe:2.3:a:example:widget:*:enterprise:*:*:*:*:*:*"},
        {"cpe": r"cpe:2.3:a:example:widget\:server:*:*:*:*:*:*:*:*"},
        {"ecosystem": "unsupported", "package_name": "widget"},
    ],
)
def test_malformed_unsupported_or_conflicting_identifiers_do_not_fall_back_to_names(fields):
    result = match_product(ProductIdentity(product="Widget", **fields), ProductIdentity(product="Widget", vendor="Example"))

    assert result.status is ProductMatchStatus.UNKNOWN


@pytest.mark.parametrize("right_purl", ["pkg:deb/widget?arch=arm64", "pkg:deb/widget", "pkg:deb/widget?arch=amd64#different"])
def test_qualifier_or_subpath_ambiguity_is_not_a_product_exclusion(right_purl):
    left = ProductIdentity(product="Widget", purl="pkg:deb/widget?arch=amd64")
    right = ProductIdentity(product="Widget", purl=right_purl)

    assert match_product(left, right).status is ProductMatchStatus.UNKNOWN


def test_one_sided_qualifiers_cannot_fall_back_to_a_broad_package_name():
    left = ProductIdentity(product="Widget", purl="pkg:pypi/widget?arch=arm64")
    right = ProductIdentity(product="Widget", ecosystem="pypi", package_name="widget")

    assert match_product(left, right).status is ProductMatchStatus.UNKNOWN


@pytest.mark.parametrize(
    ("left", "right"),
    [
        (ProductIdentity(product="Widget"), ProductIdentity(product="Widget")),
        (ProductIdentity(product="Widget", aliases=["Other"]), ProductIdentity(product="Other")),
        (ProductIdentity(vendor="Example", product="Widget Pro"), ProductIdentity(vendor="Example", product="Widget")),
        (ProductIdentity(vendor="Example", product="widget-server"), ProductIdentity(vendor="Example", product="widgetserver")),
    ],
)
def test_incomplete_names_aliases_and_fuzzy_similarity_remain_unknown(left, right):
    assert match_product(left, right).status is ProductMatchStatus.UNKNOWN
