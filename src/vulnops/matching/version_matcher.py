"""Literal exact claims and a deliberately small, explicit SemVer release subset."""

from dataclasses import dataclass
import re

from pydantic import BaseModel, ConfigDict

from vulnops.domain.case import AffectedStatus
from vulnops.domain.version import VersionConstraint, VersionStatus


class VersionMatch(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    status: AffectedStatus
    method: str
    reason: str


@dataclass(frozen=True)
class _Evaluation:
    status: AffectedStatus
    explicit: bool
    method: str
    reason: str


def _release(value: str) -> tuple[int, int, int] | None:
    match = re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value)
    if match is None:
        return None
    try:
        return tuple(int(part) for part in match.groups())
    except ValueError:
        return None


def _unknown(reason: str) -> _Evaluation:
    return _Evaluation(AffectedStatus.UNKNOWN, False, "UNSUPPORTED_OR_INCOMPLETE", reason)


def _evaluate(installed: str, constraint: VersionConstraint) -> _Evaluation:
    if constraint.status is VersionStatus.UNKNOWN:
        return _unknown("The source's version status is UNKNOWN.")
    boundaries = [constraint.introduced_version, constraint.last_affected_version, constraint.fixed_version]
    if constraint.exact_version is not None and any(value is not None for value in boundaries):
        return _unknown("Exact and range claims are mixed in one constraint.")
    if constraint.version_scheme not in {None, "semver"}:
        return _unknown("The declared version scheme is unsupported.")
    if constraint.exact_version is not None and constraint.version_scheme is None:
        if installed != constraint.exact_version:
            return _unknown("Unequal opaque versions cannot establish non-affectedness.")
        status = AffectedStatus(constraint.status.value)
        return _Evaluation(status, True, "LITERAL_EXACT", "Installed version equals the explicit source version claim.")
    if constraint.version_scheme != "semver":
        return _unknown("Range ordering requires an explicitly supported version scheme.")
    parsed = _release(installed)
    fields = [constraint.exact_version, *boundaries]
    values = [_release(value) if value is not None else None for value in fields]
    if parsed is None or any(raw is not None and value is None for raw, value in zip(fields, values)):
        return _unknown("Only plain three-part SemVer releases are supported; no guessing for other syntax.")
    exact, introduced, last, fixed = values
    if all(value is None for value in values):
        return _unknown("No exact version or range boundary was supplied.")
    if (
        (introduced is not None and fixed is not None and introduced >= fixed)
        or (introduced is not None and last is not None and introduced > last)
        or (last is not None and fixed is not None and last >= fixed)
    ):
        return _unknown("Version boundaries are contradictory or empty.")
    applies = (
        (exact is None or parsed == exact)
        and (introduced is None or parsed >= introduced)
        and (last is None or parsed <= last)
        and (fixed is None or parsed < fixed)
    )
    if applies:
        return _Evaluation(
            AffectedStatus(constraint.status.value), True, "SEMVER_RELEASE",
            "Installed release is inside the explicitly declared source constraint.",
        )
    if constraint.status is VersionStatus.NOT_AFFECTED:
        return _unknown("Being outside an explicit exemption does not establish affectedness.")
    return _Evaluation(
        AffectedStatus.NOT_AFFECTED, False, "SEMVER_RELEASE",
        "Installed release is outside this declared affected constraint, including its fixed boundary.",
    )


def match_version(installed_version: str | None, constraints: list[VersionConstraint]) -> VersionMatch:
    """Resolve the supplied constraint set, keeping unsupported gaps conservative."""
    if (
        installed_version is None or not installed_version.strip()
        or installed_version.strip().casefold() in {"unknown", "n/a", "na", "*", "-", "latest", "unspecified", "all"}
    ):
        return VersionMatch(status=AffectedStatus.UNKNOWN, method="NONE", reason="Installed version is unknown or a placeholder.")
    if not constraints:
        return VersionMatch(status=AffectedStatus.UNKNOWN, method="NONE", reason="No source version constraints are available.")
    evaluations = [_evaluate(installed_version, constraint) for constraint in constraints]
    affected = [item for item in evaluations if item.status is AffectedStatus.AFFECTED]
    exemptions = [item for item in evaluations if item.explicit and item.status is AffectedStatus.NOT_AFFECTED]
    if affected and exemptions:
        return VersionMatch(status=AffectedStatus.UNKNOWN, method="CONFLICT", reason="Source constraints explicitly disagree about this installed version.")
    if affected:
        return VersionMatch(status=AffectedStatus.AFFECTED, method=affected[0].method, reason=affected[0].reason)
    uncertain = [item for item in evaluations if item.status is AffectedStatus.UNKNOWN]
    if uncertain:
        return VersionMatch(status=AffectedStatus.UNKNOWN, method=uncertain[0].method, reason=uncertain[0].reason)
    return VersionMatch(
        status=AffectedStatus.NOT_AFFECTED, method="ALL_CONSTRAINTS_EVALUATED",
        reason="Every supplied constraint supports non-affectedness for this candidate product/version pair.",
    )
