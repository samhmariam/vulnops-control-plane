import json
from pathlib import Path
import subprocess
import os
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from vulnops import cli
from vulnops.application.bootstrap import run_walking_demo
from vulnops.application.walking_skeleton import DemoAcceptanceError
from vulnops.persistence.models import CaseEventRecord, CaseRecord, EvidenceRecord
from vulnops.persistence.repositories import Repositories
from vulnops.persistence.session import tenant_session
from vulnops.workflow.states import CaseState


pytestmark = pytest.mark.integration
LAB = Path(__file__).resolve().parents[2] / "lab"


def test_demo_persists_scenarios_and_replays_identical_cases_history_and_evidence(database, tenant_id, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", database[0].url.render_as_string(hide_password=False))
    first = run_walking_demo(LAB, tenant_id)
    second = run_walking_demo(LAB, tenant_id)
    assert first == second
    assert first.persisted
    assert len(first.outcomes) == 4
    assert {item.case.state for item in first.outcomes} == {
        CaseState.AFFECTED_CONFIRMED, CaseState.NOT_AFFECTED, CaseState.MANUAL_INVESTIGATION,
    }
    assert json.loads(first.blocked_transition.claim)["blocked"] is True
    with tenant_session(database[0], tenant_id) as session:
        for model, expected in [(CaseRecord, 4), (CaseEventRecord, 12), (EvidenceRecord, len(first.evidence))]:
            assert session.scalar(select(func.count()).select_from(model).where(model.tenant_id == tenant_id)) == expected
        repository = Repositories(session, tenant_id)
        for outcome in first.outcomes:
            assert repository.load_case(outcome.case.case_id) == outcome.case
            assert repository.list_case_history(outcome.case.case_id) == outcome.history
            assert all(event.to_state is not CaseState.APPROVED for event in outcome.history)
        for evidence in first.evidence:
            assert repository.load_evidence(evidence.evidence_id) == evidence
    with tenant_session(database[0], uuid4()) as session:
        repository = Repositories(session, session.info["tenant_id"])
        assert repository.load_case(first.outcomes[0].case.case_id) is None
        assert repository.load_evidence(first.blocked_transition.evidence_id) is None
        assert repository.list_case_history(first.outcomes[0].case.case_id) == []


def test_demo_rolls_back_everything_and_does_not_print_pass_when_audit_append_fails(database, tenant_id, monkeypatch, capsys):
    monkeypatch.setenv("DATABASE_URL", database[0].url.render_as_string(hide_password=False))
    original = Repositories.append_case_event
    def failing(repository, event):
        original(repository, event)
        if event.to_state is CaseState.NOT_AFFECTED:
            raise DemoAcceptanceError("Injected failure after event persistence")
        return event
    monkeypatch.setattr(Repositories, "append_case_event", failing)
    assert cli.main(["--tenant-id", str(tenant_id), "demo", "--lab-dir", str(LAB)]) == 1
    output = capsys.readouterr()
    assert "DAY-1 ACCEPTANCE: PASS" not in output.out + output.err
    with tenant_session(database[0], tenant_id) as session:
        for model in (CaseRecord, CaseEventRecord, EvidenceRecord):
            assert session.scalar(select(func.count()).select_from(model).where(model.tenant_id == tenant_id)) == 0


def test_illegal_transition_being_accepted_prevents_pass_and_rolls_back(database, tenant_id, monkeypatch, capsys):
    monkeypatch.setenv("DATABASE_URL", database[0].url.render_as_string(hide_password=False))
    monkeypatch.setattr(Repositories, "transition_case", lambda *args, **kwargs: None)
    assert cli.main(["--tenant-id", str(tenant_id), "demo", "--lab-dir", str(LAB)]) == 1
    output = capsys.readouterr()
    assert "DAY-1 ACCEPTANCE: PASS" not in output.out + output.err
    with tenant_session(database[0], tenant_id) as session:
        assert session.scalar(select(func.count()).select_from(CaseRecord).where(CaseRecord.tenant_id == tenant_id)) == 0


def test_post_commit_readback_failure_never_prints_pass(database, tenant_id, monkeypatch, capsys):
    from vulnops.application import bootstrap
    monkeypatch.setenv("DATABASE_URL", database[0].url.render_as_string(hide_password=False))
    original = bootstrap.verify_demo
    calls = 0
    def failing(*args):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise DemoAcceptanceError("Injected committed-data readback failure")
        return original(*args)
    monkeypatch.setattr(bootstrap, "verify_demo", failing)
    assert cli.main(["--tenant-id", str(tenant_id), "demo", "--lab-dir", str(LAB)]) == 1
    output = capsys.readouterr()
    assert "DAY-1 ACCEPTANCE: PASS" not in output.out + output.err
    with tenant_session(database[0], tenant_id) as session:
        assert session.scalar(select(func.count()).select_from(CaseRecord).where(CaseRecord.tenant_id == tenant_id)) == 4


def test_bare_demo_command_survives_process_restart(database, tenant_id):
    environment = {**os.environ, "DATABASE_URL": database[0].url.render_as_string(hide_password=False),
                   "VULNOPS_TENANT_ID": str(tenant_id)}
    # Exercise the actual console entry point in separate application processes.
    outputs = []
    for _ in range(2):
        completed = subprocess.run(["uv", "run", "vulnops", "demo"], env=environment,
                                   cwd=LAB.parent, capture_output=True, text=True, timeout=60, check=True)
        assert completed.stdout.endswith("DAY-1 ACCEPTANCE: PASS\n")
        outputs.append(completed.stdout)
    assert outputs[0] == outputs[1]
