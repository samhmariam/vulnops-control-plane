"""PostgreSQL durability, idempotency, concurrency, and audit atomicity."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import json
from pathlib import Path
import subprocess
import sys
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import event, text
from sqlalchemy.exc import DBAPIError

from vulnops.domain.asset import Asset
from vulnops.domain.case import VulnerabilityCase
from vulnops.domain.vulnerability import Vulnerability
from vulnops.persistence.repositories import MissingReference, Repositories, RepositoryConflict
from vulnops.persistence.session import tenant_session
from vulnops.workflow.events import Actor, ActorType, CaseEvent
from vulnops.workflow.states import CaseState
from vulnops.workflow.transitions import StateConflictError, TransitionError


pytestmark = pytest.mark.integration
ACTOR = Actor(actor_type=ActorType.SYSTEM, actor_id="integration-worker")


def advance(repository, case, target, **overrides):
    request = {
        "expected_current_state": case.state,
        "new_state": target,
        "actor": ACTOR,
        "reason": "Synthetic evidence supports this lifecycle step.",
        "evidence_ids": case.evidence_ids,
        "occurred_at": case.updated_at + timedelta(minutes=1),
    }
    request.update(overrides)
    return repository.transition_case(case.case_id, **request)


def test_vulnerability_asset_components_and_case_persist_as_domain_objects(database, tenant_id, stored):
    with tenant_session(database[0], tenant_id) as session:
        repository = Repositories(session, tenant_id)
        assert repository.load_vulnerability(stored["vulnerability"].vulnerability_id) == stored["vulnerability"]
        assert repository.load_asset(stored["asset"].asset_id) == stored["asset"]
        assert repository.load_case(stored["case"].case_id) == stored["case"]
        assert repository.load_evidence(stored["evidence"].evidence_id) == stored["evidence"]
        assert isinstance(repository.load_asset(stored["asset"].asset_id), Asset)


def test_state_and_history_survive_separate_application_processes(database, tenant_id, dataset, tmp_path):
    fixture = tmp_path / "synthetic-fixture.json"
    fixture.write_text(json.dumps({key: value.model_dump(mode="json") for key, value in dataset.items()}), encoding="utf-8")
    probe = Path(__file__).with_name("restart_probe.py")
    results = []
    for mode in ("write", "read"):
        completed = subprocess.run(
            [sys.executable, str(probe), mode, str(tenant_id), str(fixture)],
            cwd=tmp_path, capture_output=True, text=True, check=True, timeout=30,
        )
        results.append(json.loads(completed.stdout))
    written, restarted = results
    assert written.pop("pid") != restarted.pop("pid")
    assert restarted == written
    assert restarted["case"]["state"] == "ENRICHED"
    assert restarted["history"][0]["from_state"] == "DISCOVERED"
    assert restarted["history"][0]["to_state"] == "ENRICHED"
    assert restarted["vulnerability"] == dataset["vulnerability"].model_dump(mode="json")
    assert restarted["asset"] == dataset["asset"].model_dump(mode="json")


def test_processing_fixture_twice_is_idempotent(database, tenant_id, stored):
    with tenant_session(database[0], tenant_id) as session:
        repository = Repositories(session, tenant_id)
        for _ in range(2):
            assert repository.save_evidence(stored["evidence"]) == stored["evidence"]
            assert repository.save_vulnerability(stored["vulnerability"]) == stored["vulnerability"]
            assert repository.save_asset(stored["asset"]) == stored["asset"]
            assert repository.save_case(stored["case"]) == stored["case"]
        for table in ("vulnerabilities", "assets", "installed_components", "evidence", "vulnerability_cases"):
            assert session.scalar(text(f'SELECT count(*) FROM "{table}" WHERE tenant_id = :tenant'), {"tenant": tenant_id}) == 1


def test_natural_keys_reuse_canonical_ids_when_input_ids_are_regenerated(database, tenant_id, stored):
    vulnerability = Vulnerability.model_validate({**stored["vulnerability"].model_dump(), "vulnerability_id": uuid4()})
    asset_fields = stored["asset"].model_dump()
    asset_fields["asset_id"] = uuid4()
    for component in asset_fields["components"]:
        component["asset_id"] = asset_fields["asset_id"]
    asset = Asset.model_validate(asset_fields)
    with tenant_session(database[0], tenant_id) as session:
        repository = Repositories(session, tenant_id)
        assert repository.save_vulnerability(vulnerability).vulnerability_id == stored["vulnerability"].vulnerability_id
        assert repository.save_asset(asset).asset_id == stored["asset"].asset_id


def test_conflicting_replay_does_not_overwrite_source_snapshot(database, tenant_id, stored):
    changed = Vulnerability.model_validate({**stored["vulnerability"].model_dump(), "description": "A different claim"})
    with tenant_session(database[0], tenant_id) as session:
        repository = Repositories(session, tenant_id)
        with pytest.raises(RepositoryConflict):
            repository.save_vulnerability(changed)
        assert repository.load_vulnerability(changed.vulnerability_id) == stored["vulnerability"]


def test_case_pair_is_unique_and_initial_save_cannot_skip_lifecycle(database, tenant_id, stored):
    replacement = VulnerabilityCase.model_validate({**stored["case"].model_dump(), "case_id": uuid4()})
    with tenant_session(database[0], tenant_id) as session:
        repository = Repositories(session, tenant_id)
        assert repository.save_case(replacement).case_id == stored["case"].case_id
        updated = advance(repository, stored["case"], CaseState.ENRICHED).case
        with pytest.raises(RepositoryConflict):
            repository.save_case(updated)
        with pytest.raises(RepositoryConflict):
            repository.save_case(stored["case"])
        assert repository.load_case(updated.case_id) == updated


def test_events_remain_historical_and_exact_event_replay_is_idempotent(database, tenant_id, stored):
    with tenant_session(database[0], tenant_id) as session:
        repository = Repositories(session, tenant_id)
        first = advance(repository, stored["case"], CaseState.ENRICHED)
        second = advance(repository, first.case, CaseState.ASSET_MATCHED)
        assert repository.append_case_event(first.event) == first.event
        changed = CaseEvent.model_validate({**first.event.model_dump(), "reason": "rewritten history"})
        with pytest.raises(RepositoryConflict):
            repository.append_case_event(changed)
    with tenant_session(database[0], tenant_id) as session:
        repository = Repositories(session, tenant_id)
        history = repository.list_case_history(stored["case"].case_id)
        assert history == [first.event, second.event]
        assert history[0].from_state is CaseState.DISCOVERED
        assert history[0].to_state is CaseState.ENRICHED
        assert repository.load_case(stored["case"].case_id).state is CaseState.ASSET_MATCHED


def test_append_event_applies_only_legal_transitions_atomically(database, tenant_id, stored):
    case = stored["case"]
    event_to_append = CaseEvent(
        case_id=case.case_id, from_state=CaseState.DISCOVERED, to_state=CaseState.ENRICHED,
        actor_type=ACTOR.actor_type, actor_id=ACTOR.actor_id,
        reason="Synthetic enrichment", evidence_ids=case.evidence_ids,
        correlation_id=uuid4(), created_at=case.updated_at + timedelta(minutes=1),
    )
    with tenant_session(database[0], tenant_id) as session:
        repository = Repositories(session, tenant_id)
        assert repository.append_case_event(event_to_append) == event_to_append
        assert repository.load_case(case.case_id).state is CaseState.ENRICHED
        assert repository.list_case_history(case.case_id) == [event_to_append]


def test_fabricated_event_cannot_bypass_transition_policy(database, tenant_id, stored):
    case = stored["case"]
    fabricated = CaseEvent(
        case_id=case.case_id, from_state=CaseState.DISCOVERED, to_state=CaseState.APPROVED,
        actor_type=ActorType.HUMAN, actor_id="operator-fixture",
        reason="Attempted shortcut", evidence_ids=case.evidence_ids,
        correlation_id=uuid4(), created_at=case.updated_at + timedelta(minutes=1),
    )
    with tenant_session(database[0], tenant_id) as session:
        repository = Repositories(session, tenant_id)
        with pytest.raises(TransitionError):
            repository.append_case_event(fabricated)
        assert repository.load_case(case.case_id) == case
        assert repository.list_case_history(case.case_id) == []


def test_event_insert_failure_rolls_back_state_even_if_caller_handles_error(database, tenant_id, stored):
    def fail_event_insert(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO case_events"):
            raise RuntimeError("Simulated audit storage failure")
    app = database[0]
    with tenant_session(app, tenant_id) as session:
        repository = Repositories(session, tenant_id)
        event.listen(app, "before_cursor_execute", fail_event_insert)
        try:
            with pytest.raises(RuntimeError, match="audit storage failure"):
                advance(repository, stored["case"], CaseState.ENRICHED)
        finally:
            event.remove(app, "before_cursor_execute", fail_event_insert)
        assert repository.load_case(stored["case"].case_id) == stored["case"]
        assert repository.list_case_history(stored["case"].case_id) == []


def test_missing_event_evidence_leaves_no_state_change(database, tenant_id, stored):
    with tenant_session(database[0], tenant_id) as session:
        repository = Repositories(session, tenant_id)
        with pytest.raises(MissingReference):
            advance(repository, stored["case"], CaseState.ENRICHED, evidence_ids=[uuid4()])
        assert repository.load_case(stored["case"].case_id) == stored["case"]
        assert repository.list_case_history(stored["case"].case_id) == []


def test_concurrent_workers_cannot_both_commit_a_stale_transition(database, tenant_id, stored):
    barrier = Barrier(2)
    def worker():
        try:
            with tenant_session(database[0], tenant_id) as session:
                repository = Repositories(session, tenant_id)
                barrier.wait(timeout=10)
                advance(repository, stored["case"], CaseState.ENRICHED)
            return "committed"
        except StateConflictError:
            return "stale"
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(worker) for _ in range(2)]
        assert sorted(future.result(timeout=20) for future in futures) == ["committed", "stale"]
    with tenant_session(database[0], tenant_id) as session:
        repository = Repositories(session, tenant_id)
        assert repository.load_case(stored["case"].case_id).state is CaseState.ENRICHED
        assert len(repository.list_case_history(stored["case"].case_id)) == 1


@pytest.mark.parametrize("operation", ["UPDATE", "DELETE"])
def test_runtime_role_cannot_rewrite_or_delete_events(database, tenant_id, stored, operation):
    with tenant_session(database[0], tenant_id) as session:
        advance(Repositories(session, tenant_id), stored["case"], CaseState.ENRICHED)
    with pytest.raises(DBAPIError):
        with tenant_session(database[0], tenant_id) as session:
            statement = (
                "UPDATE case_events SET payload = '{}'::jsonb WHERE tenant_id = :tenant"
                if operation == "UPDATE" else "DELETE FROM case_events WHERE tenant_id = :tenant"
            )
            session.execute(text(statement), {"tenant": tenant_id})
