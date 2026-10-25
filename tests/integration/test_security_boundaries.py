"""Persisted security-boundary checks without production actions or external feeds."""

from pathlib import Path
from uuid import uuid4

from pydantic import ValidationError
import pytest

from vulnops import cli
from vulnops.application import walking_skeleton
from vulnops.application.bootstrap import run_walking_demo
from vulnops.domain.evidence import Evidence
from vulnops.persistence.repositories import Repositories, RepositoryConflict
from vulnops.persistence.session import tenant_session
from vulnops.sources.fixtures import load_fixture_inventory
from vulnops.workflow.events import CaseEvent


pytestmark = pytest.mark.integration
LAB = Path(__file__).resolve().parents[2] / "lab"


def test_foreign_component_injection_cannot_commit_false_asset_conclusions(database, tenant_id, monkeypatch, capsys):
    monkeypatch.setenv("DATABASE_URL", database[0].url.render_as_string(hide_password=False))
    inventory = load_fixture_inventory(LAB / "inventory")
    victim = next(item.asset for item in inventory if item.asset.external_id.endswith("asset-web-01"))
    fixed = next(item.asset for item in inventory if item.asset.external_id.endswith("asset-web-02"))
    victim.components[:] = fixed.components
    monkeypatch.setattr(walking_skeleton, "load_fixture_inventory", lambda root: inventory)
    assert cli.main(["--tenant-id", str(tenant_id), "demo", "--lab-dir", str(LAB)]) != 0
    output = capsys.readouterr()
    assert "DAY-1 ACCEPTANCE: PASS" not in output.out + output.err
    with tenant_session(database[0], tenant_id) as session:
        repository = Repositories(session, tenant_id)
        assert repository.list_cases(limit=100, offset=0) == []
        assert repository.list_assets(limit=100, offset=0) == []
        assert repository.find_vulnerability_by_cve("CVE-2099-900001") is None


def test_trusted_model_copy_cannot_persist_blank_attribution(database, tenant_id):
    source = walking_skeleton.load_demo_vulnerability(LAB)
    malformed = source.evidence[0].model_copy(update={"evidence_id": uuid4(), "source_name": "   "})
    assert isinstance(malformed, Evidence)
    with tenant_session(database[0], tenant_id) as session:
        repository = Repositories(session, tenant_id)
        with pytest.raises(ValidationError):
            repository.save_evidence(malformed)
        assert repository.load_evidence(malformed.evidence_id) is None


def test_retargeting_historical_event_cannot_change_another_case(database, tenant_id, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", database[0].url.render_as_string(hide_password=False))
    report = run_walking_demo(LAB, tenant_id)
    original, other = report.outcomes[:2]
    retargeted = CaseEvent.model_validate({**original.history[0].model_dump(), "case_id": other.case.case_id})
    with tenant_session(database[0], tenant_id) as session:
        repository = Repositories(session, tenant_id)
        with pytest.raises(RepositoryConflict):
            repository.append_case_event(retargeted)
        for outcome in (original, other):
            assert repository.load_case(outcome.case.case_id) == outcome.case
            assert repository.list_case_history(outcome.case.case_id) == outcome.history
