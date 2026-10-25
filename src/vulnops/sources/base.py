"""The boundary future live feeds implement without changing domain consumers."""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from vulnops.domain.asset import Asset
from vulnops.domain.evidence import Evidence
from vulnops.domain.vulnerability import Vulnerability


class SourceError(ValueError):
    """A source snapshot cannot be represented safely by this adapter."""


@dataclass(frozen=True)
class SourcedVulnerability:
    vulnerability: Vulnerability
    evidence: tuple[Evidence, ...]


@dataclass(frozen=True)
class SourcedAsset:
    asset: Asset
    evidence: tuple[Evidence, ...]


@runtime_checkable
class VulnerabilitySource(Protocol):
    def fetch(self) -> Iterable[SourcedVulnerability]:
        """Return canonical observations plus the evidence needed to persist them."""
        ...
