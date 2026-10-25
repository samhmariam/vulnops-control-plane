"""Version constraints preserve source claims without applying ordering rules."""

import pytest
from pydantic import ValidationError

from vulnops.domain.version import VersionConstraint, VersionStatus


def test_exact_affected_version():
    constraint = VersionConstraint(exact_version="1.2.3", status=VersionStatus.AFFECTED)

    assert constraint.exact_version == "1.2.3"
    assert constraint.status is VersionStatus.AFFECTED
    assert constraint.fixed_version is None


def test_reported_range_retains_endpoints_and_scheme():
    constraint = VersionConstraint(
        introduced_version="1.0",
        last_affected_version="1.9.9",
        fixed_version="2.0",
        version_scheme="semver",
        status=VersionStatus.AFFECTED,
    )

    assert VersionConstraint.model_validate_json(constraint.model_dump_json()) == constraint
    assert constraint.introduced_version == "1.0"
    assert constraint.last_affected_version == "1.9.9"
    assert constraint.fixed_version == "2.0"


def test_unknown_fixed_version_does_not_clear_affected_status():
    constraint = VersionConstraint(introduced_version="1.0", status=VersionStatus.AFFECTED)

    assert constraint.fixed_version is None
    assert constraint.status is VersionStatus.AFFECTED


def test_missing_version_information_remains_unknown():
    constraint = VersionConstraint()

    assert constraint.status is VersionStatus.UNKNOWN
    assert constraint.exact_version is None
    assert constraint.introduced_version is None
    assert constraint.last_affected_version is None
    assert constraint.fixed_version is None


@pytest.mark.parametrize("version", ["1:2.0-3ubuntu1", "2026.10-hotfixA", "v1.2.3-rc.1+build.7"])
def test_ecosystem_specific_versions_are_preserved_without_comparison(version):
    constraint = VersionConstraint(exact_version=version)

    assert constraint.exact_version == version
    assert constraint.status is VersionStatus.UNKNOWN


@pytest.mark.parametrize("status", list(VersionStatus))
def test_all_source_statuses_are_representable(status):
    assert VersionConstraint(status=status).status is status


def test_version_fields_reject_numeric_coercion():
    with pytest.raises(ValidationError):
        VersionConstraint(exact_version=1.2)
