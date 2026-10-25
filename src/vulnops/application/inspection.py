"""Read-only use cases over a tenant-scoped domain repository boundary."""

from typing import Protocol
from uuid import UUID

from vulnops.domain.asset import Asset
from vulnops.domain.case import VulnerabilityCase
from vulnops.domain.vulnerability import Vulnerability
from vulnops.workflow.events import CaseEvent


class RecordNotFound(LookupError):
    """The requested record is not visible in the current tenant."""


class InspectionRepository(Protocol):
    def find_vulnerability_by_cve(self, cve_id: str) -> Vulnerability | None: ...
    def load_asset(self, asset_id: UUID) -> Asset | None: ...
    def list_assets(self, *, limit: int, offset: int) -> list[Asset]: ...
    def load_case(self, case_id: UUID) -> VulnerabilityCase | None: ...
    def list_cases(self, *, limit: int, offset: int) -> list[VulnerabilityCase]: ...
    def list_case_history(self, case_id: UUID) -> list[CaseEvent]: ...


def _page(limit: int, offset: int):
    if not 1 <= limit <= 1000 or offset < 0:
        raise ValueError("Use limit 1–1000 and a nonnegative offset")


def _required(value):
    if value is None:
        raise RecordNotFound("Record not found in this tenant")
    return value


class InspectionService:
    def __init__(self, repository: InspectionRepository):
        self._repository = repository

    def show_vulnerability(self, cve_id: str) -> Vulnerability:
        validated = Vulnerability.validate_cve_id(cve_id)
        if validated is None:
            raise ValueError("A CVE identifier is required")
        return _required(self._repository.find_vulnerability_by_cve(validated))

    def list_assets(self, *, limit: int = 100, offset: int = 0) -> list[Asset]:
        _page(limit, offset)
        return self._repository.list_assets(limit=limit, offset=offset)

    def show_asset(self, asset_id: UUID) -> Asset:
        return _required(self._repository.load_asset(asset_id))

    def list_cases(self, *, limit: int = 100, offset: int = 0) -> list[VulnerabilityCase]:
        _page(limit, offset)
        return self._repository.list_cases(limit=limit, offset=offset)

    def show_case(self, case_id: UUID) -> VulnerabilityCase:
        return _required(self._repository.load_case(case_id))

    def case_history(self, case_id: UUID) -> list[CaseEvent]:
        self.show_case(case_id)
        return self._repository.list_case_history(case_id)
