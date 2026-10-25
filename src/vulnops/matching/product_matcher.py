"""Structured identity comparison, with conservative explicit fallbacks."""

from dataclasses import dataclass
from enum import StrEnum
import re

from packageurl import PackageURL
from pydantic import BaseModel, ConfigDict

from vulnops.domain.product import ProductIdentity


class ProductMatchStatus(StrEnum):
    MATCH = "MATCH"
    DIFFERENT = "DIFFERENT"
    UNKNOWN = "UNKNOWN"


class ProductMatchMethod(StrEnum):
    PURL = "PURL"
    CPE = "CPE"
    PACKAGE = "PACKAGE"
    VENDOR_PRODUCT = "VENDOR_PRODUCT"
    NONE = "NONE"
    CONFLICT = "CONFLICT"


class ProductMatch(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    status: ProductMatchStatus
    method: ProductMatchMethod
    reason: str
    component_version_hints: tuple[str, ...] = ()
    product_version_hints: tuple[str, ...] = ()


class _UnsupportedIdentity(ValueError):
    pass


def _package_key(ecosystem: str, name: str) -> tuple[str, str]:
    if ecosystem == "pypi" and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", name):
        return ecosystem, re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == "npm" and re.fullmatch(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*", name):
        return ecosystem, name
    raise _UnsupportedIdentity("Unsupported or ambiguous ecosystem/package identifier.")


@dataclass(frozen=True)
class _Signals:
    purl_key: tuple | None
    cpe_key: tuple | None
    package_key: tuple | None
    version_hints: tuple[str, ...]


def _signals(identity: ProductIdentity) -> _Signals:
    purl_key = cpe_key = package_key = None
    hints = []
    purl_package = None
    if identity.purl is not None:
        try:
            if identity.purl != identity.purl.strip():
                raise ValueError("Whitespace")
            purl = PackageURL.from_string(identity.purl)
        except (ValueError, TypeError) as error:
            raise _UnsupportedIdentity("Malformed PURL; no fallback can establish identity.") from error
        if purl.type not in {"pypi", "npm", "maven", "cargo", "nuget", "golang", "deb", "rpm", "generic"}:
            raise _UnsupportedIdentity("Unsupported PURL type.")
        if identity.ecosystem is not None and identity.ecosystem != purl.type:
            raise _UnsupportedIdentity("PURL type and declared ecosystem contradict each other.")
        if any(character in (purl.namespace or "") + purl.name for character in "*?\\"):
            raise _UnsupportedIdentity("Wildcard or escaped PURL identity is unsupported.")
        name = purl.name
        if purl.type in {"pypi", "npm"}:
            full_name = f"{purl.namespace}/{name}" if purl.namespace else name
            purl_package = _package_key(purl.type, full_name)
            if purl.type == "pypi":
                name = purl_package[1]
        purl_key = (purl.type, purl.namespace, name, tuple(sorted(purl.qualifiers.items())), purl.subpath)
        if purl.version is not None:
            hints.append(purl.version)
    if identity.cpe is not None:
        parts = identity.cpe.split(":")
        if (
            len(parts) != 13 or parts[:2] != ["cpe", "2.3"] or parts[2] not in {"a", "o", "h"}
            or any(re.fullmatch(r"[a-z0-9][a-z0-9._-]*", value) is None for value in parts[3:5])
            or any(value != "*" for value in parts[6:])
            or (parts[5] != "*" and re.fullmatch(r"[a-z0-9][a-z0-9._-]*", parts[5]) is None)
        ):
            raise _UnsupportedIdentity("CPE is outside the supported literal CPE 2.3 subset.")
        cpe_key = tuple(parts[2:5])
        if parts[5] != "*":
            hints.append(parts[5])
    if identity.ecosystem is not None and identity.package_name is not None:
        package_key = _package_key(identity.ecosystem, identity.package_name)
    if purl_package is not None and package_key is not None and purl_package != package_key:
        raise _UnsupportedIdentity("PURL and package identifier contradict each other.")
    if package_key is None and purl_package is not None and not purl.qualifiers and not purl.subpath:
        package_key = purl_package
    if len(set(hints)) > 1:
        raise _UnsupportedIdentity("Structured identifiers contain conflicting version hints.")
    return _Signals(purl_key, cpe_key, package_key, tuple(dict.fromkeys(hints)))


def _normalised_name(value: str | None) -> str | None:
    if value is None or not value.strip() or not value.isascii():
        return None
    return " ".join(value.split()).casefold()


def match_product(component: ProductIdentity, product: ProductIdentity) -> ProductMatch:
    """Compare one candidate pair, not a complete asset or all product aliases."""
    try:
        left, right = _signals(component), _signals(product)
    except _UnsupportedIdentity as error:
        return ProductMatch(status=ProductMatchStatus.UNKNOWN, method=ProductMatchMethod.NONE, reason=str(error))
    common = dict(component_version_hints=left.version_hints, product_version_hints=right.version_hints)
    if (left.purl_key is None) != (right.purl_key is None):
        one_sided_purl = left.purl_key or right.purl_key
        if one_sided_purl[3] or one_sided_purl[4]:
            return ProductMatch(
                status=ProductMatchStatus.UNKNOWN, method=ProductMatchMethod.PURL,
                reason="One-sided PURL qualifiers or subpaths have no comparable source scope.", **common,
            )
    comparisons = []
    for method, left_key, right_key in (
        (ProductMatchMethod.PURL, left.purl_key, right.purl_key),
        (ProductMatchMethod.CPE, left.cpe_key, right.cpe_key),
        (ProductMatchMethod.PACKAGE, left.package_key, right.package_key),
    ):
        if left_key is None or right_key is None:
            continue
        if method is ProductMatchMethod.PURL and left_key[:3] == right_key[:3] and left_key[3:] != right_key[3:]:
            return ProductMatch(
                status=ProductMatchStatus.UNKNOWN, method=method,
                reason="PURL qualifiers or subpaths differ; artifact applicability is ambiguous.", **common,
            )
        comparisons.append((method, left_key == right_key))
    if comparisons:
        if len({equal for _, equal in comparisons}) > 1:
            return ProductMatch(
                status=ProductMatchStatus.UNKNOWN, method=ProductMatchMethod.CONFLICT,
                reason="Comparable structured identifiers disagree; priority cannot erase a conflict.", **common,
            )
        method, equal = comparisons[0]
        return ProductMatch(
            status=ProductMatchStatus.MATCH if equal else ProductMatchStatus.DIFFERENT,
            method=method, reason="Structured product identifiers agree." if equal else "Structured product identifiers identify different candidate products.",
            **common,
        )
    left_names = (_normalised_name(component.vendor), _normalised_name(component.product))
    right_names = (_normalised_name(product.vendor), _normalised_name(product.product))
    if all(left_names) and all(right_names) and left_names == right_names:
        return ProductMatch(
            status=ProductMatchStatus.MATCH, method=ProductMatchMethod.VENDOR_PRODUCT,
            reason="Complete vendor/product names agree after case and whitespace normalisation.", **common,
        )
    return ProductMatch(
        status=ProductMatchStatus.UNKNOWN, method=ProductMatchMethod.NONE,
        reason="Identity is incomplete or names differ; aliases and fuzzy similarity are not proof.", **common,
    )
