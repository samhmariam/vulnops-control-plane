from contextlib import contextmanager
import json
from pathlib import Path
from unittest.mock import Mock
from uuid import uuid4

import pytest
from sqlalchemy.exc import OperationalError

from vulnops import cli
from vulnops.application.inspection import InspectionService, RecordNotFound
from vulnops.application.walking_skeleton import DEMO_TENANT_ID, DemoAcceptanceError


@pytest.fixture
def service(monkeypatch):
    service = Mock(spec=InspectionService)
    @contextmanager
    def opening(tenant_id):
        assert isinstance(tenant_id, type(uuid4()))
        yield service
    monkeypatch.setattr(cli, "open_inspection", opening)
    return service


@pytest.mark.parametrize("arguments,method", [
    (["vulnerability", "show", "CVE-2099-900001"], "show_vulnerability"),
    (["asset", "list"], "list_assets"),
    (["asset", "show", str(uuid4())], "show_asset"),
    (["case", "list"], "list_cases"),
    (["case", "show", str(uuid4())], "show_case"),
    (["case", "history", str(uuid4())], "case_history"),
])
def test_command_dispatch_and_evidence_serialization(service, capsys, arguments, method):
    evidence_id = str(uuid4())
    getattr(service, method).return_value = {"evidence_ids": [evidence_id], "claim": "untrusted\x1b[31mtext"}
    assert cli.main(["--tenant-id", str(uuid4()), *arguments]) == 0
    output = capsys.readouterr().out
    assert "\x1b" not in output
    assert json.loads(output)["evidence_ids"] == [evidence_id]
    getattr(service, method).assert_called_once()


def test_demo_uses_application_service_and_dedicated_default_tenant(monkeypatch, capsys):
    monkeypatch.delenv("VULNOPS_TENANT_ID", raising=False)
    operation = Mock(return_value={"synthetic": True, "persisted": True})
    monkeypatch.setattr(cli, "run_walking_demo", operation)
    lab = Path(__file__).resolve().parents[1] / "lab"
    assert cli.main(["demo", "--lab-dir", str(lab)]) == 0
    output = capsys.readouterr().out
    payload, tail = output.split("\nBLOCKED:", 1)
    assert json.loads(payload)["persisted"] is True
    assert tail.endswith("DAY-1 ACCEPTANCE: PASS\n")
    operation.assert_called_once_with(lab, DEMO_TENANT_ID)


@pytest.mark.parametrize("error", [DemoAcceptanceError("failure"), OperationalError("COMMIT", {}, Exception("failure"))])
def test_demo_never_prints_pass_on_application_or_commit_failure(monkeypatch, capsys, error):
    monkeypatch.setattr(cli, "run_walking_demo", Mock(side_effect=error))
    assert cli.main(["demo"]) == 1
    captured = capsys.readouterr()
    assert "DAY-1 ACCEPTANCE: PASS" not in captured.out + captured.err


def test_missing_lab_is_reported_cleanly(capsys, tmp_path):
    assert cli.main(["demo", "--lab-dir", str(tmp_path)]) == 1
    assert "lab snapshot" in capsys.readouterr().err


def test_missing_tenant_fails_before_opening_database(monkeypatch, capsys):
    monkeypatch.delenv("VULNOPS_TENANT_ID", raising=False)
    with pytest.raises(SystemExit) as error:
        cli.main(["asset", "list"])
    assert error.value.code == 2
    assert "require --tenant-id" in capsys.readouterr().err


def test_tenant_environment_and_pagination(service, monkeypatch, capsys):
    monkeypatch.setenv("VULNOPS_TENANT_ID", str(uuid4()))
    service.list_assets.return_value = []
    assert cli.main(["asset", "list", "--limit", "2", "--offset", "3"]) == 0
    service.list_assets.assert_called_once_with(limit=2, offset=3)
    assert json.loads(capsys.readouterr().out) == []


@pytest.mark.parametrize("failure,code", [
    (RecordNotFound("private record"), 3),
    (ValueError("private config"), 2),
    (OperationalError("private SQL", {}, Exception("secret database credentials")), 1),
])
def test_failures_are_nonzero_and_do_not_expose_raw_details(service, capsys, failure, code):
    service.list_cases.side_effect = failure
    assert cli.main(["--tenant-id", str(uuid4()), "case", "list"]) == code
    captured = capsys.readouterr()
    assert not captured.out
    assert "private" not in captured.err and "secret" not in captured.err


@pytest.mark.parametrize("arguments", [
    ["asset", "show", "bad-uuid"],
    ["--tenant-id", "bad-uuid", "case", "list"],
])
def test_invalid_identifiers_fail_without_traceback(arguments, capsys):
    try:
        result = cli.main(arguments)
    except SystemExit as error:
        result = error.code
    assert result == 2
    assert "Traceback" not in capsys.readouterr().err
