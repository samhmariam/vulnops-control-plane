"""Conservative version boundaries, disjoint ranges, and contradictory claims."""

import pytest

from vulnops.domain.case import AffectedStatus
from vulnops.domain.version import VersionConstraint, VersionStatus
from vulnops.matching.version_matcher import match_version


def affected(**fields):
    return VersionConstraint(status=VersionStatus.AFFECTED, **fields)


def test_literal_exact_version_does_not_require_invented_ordering():
    assert match_version("1.0-vendor", [affected(exact_version="1.0-vendor")]).status is AffectedStatus.AFFECTED
    assert match_version("1.1-vendor", [affected(exact_version="1.0-vendor")]).status is AffectedStatus.UNKNOWN


@pytest.mark.parametrize(
    ("installed", "status"),
    [("0.9.0", AffectedStatus.NOT_AFFECTED), ("1.0.0", AffectedStatus.AFFECTED),
     ("1.9.0", AffectedStatus.AFFECTED), ("2.0.0", AffectedStatus.NOT_AFFECTED), ("2.1.0", AffectedStatus.NOT_AFFECTED)],
)
def test_introduced_is_inclusive_and_fixed_is_exclusive(installed, status):
    constraint = affected(introduced_version="1.0.0", fixed_version="2.0.0", version_scheme="semver")

    assert match_version(installed, [constraint]).status is status


def test_less_than_fixed_range_compares_numeric_components_not_strings():
    constraint = affected(fixed_version="1.10.0", version_scheme="semver")

    assert match_version("1.9.0", [constraint]).status is AffectedStatus.AFFECTED
    assert match_version("1.10.0", [constraint]).status is AffectedStatus.NOT_AFFECTED


def test_introduced_with_unknown_fix_does_not_imply_non_affectedness():
    constraint = affected(introduced_version="1.0.0", version_scheme="semver")

    assert match_version("9.0.0", [constraint]).status is AffectedStatus.AFFECTED


def test_last_affected_boundary_is_inclusive():
    constraint = affected(last_affected_version="1.5.0", version_scheme="semver")

    assert match_version("1.5.0", [constraint]).status is AffectedStatus.AFFECTED
    assert match_version("1.5.1", [constraint]).status is AffectedStatus.NOT_AFFECTED


def test_disjoint_ranges_form_a_union_not_a_conflict():
    constraints = [
        affected(introduced_version="1.0.0", fixed_version="1.5.0", version_scheme="semver"),
        affected(introduced_version="2.0.0", fixed_version="2.5.0", version_scheme="semver"),
    ]

    assert match_version("2.1.0", constraints).status is AffectedStatus.AFFECTED
    assert match_version("1.8.0", constraints).status is AffectedStatus.NOT_AFFECTED
    assert match_version("3.0.0", constraints).status is AffectedStatus.NOT_AFFECTED


def test_explicit_exemption_conflicting_with_affected_range_is_unknown():
    constraints = [
        affected(fixed_version="2.0.0", version_scheme="semver"),
        VersionConstraint(exact_version="1.5.0", status=VersionStatus.NOT_AFFECTED),
    ]

    assert match_version("1.5.0", constraints).status is AffectedStatus.UNKNOWN


def test_unsupported_sibling_range_cannot_turn_an_exclusion_into_reassurance():
    constraints = [
        affected(fixed_version="1.0.0", version_scheme="semver"),
        affected(fixed_version="9.0", version_scheme="vendor-specific"),
    ]

    assert match_version("2.0.0", constraints).status is AffectedStatus.UNKNOWN


def test_supported_positive_evidence_is_not_cleared_by_an_unknown_sibling():
    constraints = [affected(exact_version="1.5.0"), VersionConstraint()]

    assert match_version("1.5.0", constraints).status is AffectedStatus.AFFECTED


@pytest.mark.parametrize("installed", [None, "", " ", "UNKNOWN", "*", "latest"])
def test_unknown_installed_version_is_first_class(installed):
    assert match_version(installed, [affected(exact_version="1.5.0")]).status is AffectedStatus.UNKNOWN


@pytest.mark.parametrize("installed", ["1.5", "1.5.0-rc.1", "1.5.0+build.1", "v1.5.0", "01.5.0", "1:1.5.0-1ubuntu1"])
def test_unsupported_release_syntax_is_not_ordered(installed):
    assert match_version(installed, [affected(fixed_version="2.0.0", version_scheme="semver")]).status is AffectedStatus.UNKNOWN


@pytest.mark.parametrize(
    "constraint",
    [
        affected(fixed_version="2.0.0"),
        affected(exact_version="1.5.0", version_scheme="rpm"),
        affected(introduced_version="2.0.0", fixed_version="1.0.0", version_scheme="semver"),
        affected(last_affected_version="2.0.0", fixed_version="2.0.0", version_scheme="semver"),
        affected(exact_version="1.5.0", fixed_version="2.0.0", version_scheme="semver"),
        VersionConstraint(exact_version="1.5.0"),
        affected(version_scheme="semver"),
    ],
)
def test_ambiguous_incomplete_or_unsupported_constraints_are_unknown(constraint):
    assert match_version("1.5.0", [constraint]).status is AffectedStatus.UNKNOWN


def test_missing_constraints_do_not_mean_no_affected_versions():
    assert match_version("1.5.0", []).status is AffectedStatus.UNKNOWN


def test_explicit_not_affected_claim_applies_only_to_its_own_scope():
    constraint = VersionConstraint(exact_version="1.5.0", status=VersionStatus.NOT_AFFECTED)

    assert match_version("1.5.0", [constraint]).status is AffectedStatus.NOT_AFFECTED
    assert match_version("1.6.0", [constraint]).status is AffectedStatus.UNKNOWN
