from unittest.mock import Mock
from uuid import uuid4

import pytest

from vulnops.application.inspection import InspectionRepository, InspectionService, RecordNotFound


@pytest.mark.parametrize("limit,offset", [(0, 0), (1001, 0), (10, -1)])
def test_invalid_pagination_never_reaches_repository(limit, offset):
    repository = Mock(spec=InspectionRepository)
    service = InspectionService(repository)
    for operation in (service.list_assets, service.list_cases):
        with pytest.raises(ValueError):
            operation(limit=limit, offset=offset)
    assert repository.mock_calls == []


def test_invalid_cve_never_reaches_repository():
    repository = Mock(spec=InspectionRepository)
    with pytest.raises(ValueError):
        InspectionService(repository).show_vulnerability("bad-cve")
    assert repository.mock_calls == []


def test_history_distinguishes_missing_case_from_empty_history():
    repository = Mock(spec=InspectionRepository)
    repository.load_case.return_value = None
    with pytest.raises(RecordNotFound):
        InspectionService(repository).case_history(uuid4())
    repository.list_case_history.assert_not_called()
