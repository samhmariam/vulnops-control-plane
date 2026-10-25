"""Lifecycle policy, concurrency preconditions, prerequisites, and audit events."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnops.domain.case import AffectedStatus, VulnerabilityCase
from vulnops.workflow.events import Actor, ActorType, CaseEvent, CaseEventType
from vulnops.workflow.states import CaseState
from vulnops.workflow.transitions import (
    ALLOWED_TRANSITIONS,
    StateConflictError,
    TransitionError,
    transition_case,
)


NOW = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)
HUMAN = Actor(actor_type=ActorType.HUMAN, actor_id="operator-123")
SYSTEM = Actor(actor_type=ActorType.SYSTEM, actor_id="verification-service")
AGENT = Actor(actor_type=ActorType.AGENT, actor_id="analysis-agent")


@pytest.fixture
def case_fields():
    return {
        "vulnerability_id": uuid4(),
        "asset_id": uuid4(),
        "cve_id": "CVE-2026-12345",
        "affected_status": AffectedStatus.AFFECTED,
        "evidence_ids": [uuid4()],
        "priority": "P1",
        "remediation_plan_id": uuid4(),
        "approval_id": uuid4(),
        "verification_id": uuid4(),
        "created_at": NOW,
        "updated_at": NOW,
    }


def request(case, new_state, **overrides):
    fields = {
        "case": case,
        "expected_current_state": case.state,
        "new_state": new_state,
        "actor": HUMAN,
        "reason": "Recorded prerequisite evidence supports this step.",
        "evidence_ids": [uuid4()],
        "occurred_at": NOW + timedelta(hours=1),
    }
    fields.update(overrides)
    return transition_case(**fields)


@pytest.mark.parametrize(
    ("from_state", "to_state"),
    [
        (CaseState.DISCOVERED, CaseState.APPROVED),
        (CaseState.AFFECTED_CONFIRMED, CaseState.ROLLOUT),
        (CaseState.PATCH_PLAN_CREATED, CaseState.VERIFIED_FIXED),
        (CaseState.AWAITING_APPROVAL, CaseState.ROLLOUT),
    ],
)
def test_required_illegal_state_skips_fail(case_fields, from_state, to_state):
    case = VulnerabilityCase(**case_fields, state=from_state)
    before = case.model_dump()

    with pytest.raises(TransitionError, match="not permitted"):
        request(case, to_state)

    assert case.model_dump() == before


def test_complete_primary_path_preserves_identity_and_emits_linked_events(case_fields):
    path = [
        CaseState.DISCOVERED, CaseState.ENRICHED, CaseState.ASSET_MATCHED,
        CaseState.AFFECTED_CONFIRMED, CaseState.PRIORITISED, CaseState.PATCH_PLAN_CREATED,
        CaseState.SANDBOX_TESTED, CaseState.AWAITING_APPROVAL, CaseState.APPROVED,
        CaseState.CANARY_DEPLOYED, CaseState.CANARY_VERIFIED, CaseState.ROLLOUT,
        CaseState.RESCANNED, CaseState.VERIFIED_FIXED,
    ]
    case = VulnerabilityCase(**case_fields)
    original = case
    correlation_id = uuid4()
    events = []
    for step, new_state in enumerate(path[1:], start=1):
        previous = case
        timestamp = NOW + timedelta(minutes=step)
        evidence_id = uuid4()
        actor = HUMAN if new_state is CaseState.APPROVED else SYSTEM
        result = request(
            case, new_state, actor=actor, evidence_ids=[evidence_id],
            occurred_at=timestamp, correlation_id=correlation_id,
        )
        case = result.case
        events.append(result.event)

        assert previous.state is path[step - 1]
        assert case is not previous
        assert case.state is new_state
        assert case.case_id == original.case_id
        assert case.asset_id == original.asset_id
        assert case.vulnerability_id == original.vulnerability_id
        assert case.created_at == original.created_at
        assert case.updated_at == result.event.created_at == timestamp
        assert result.event.from_state is previous.state
        assert result.event.to_state is new_state
        assert result.event.case_id == case.case_id
        assert result.event.event_type is CaseEventType.STATE_TRANSITION
        assert result.event.actor_type is actor.actor_type
        assert result.event.actor_id == actor.actor_id
        assert result.event.reason == "Recorded prerequisite evidence supports this step."
        assert result.event.evidence_ids == (evidence_id,)
        assert result.event.correlation_id == correlation_id
        assert evidence_id in case.evidence_ids

    assert original.state is CaseState.DISCOVERED
    assert case.state is CaseState.VERIFIED_FIXED
    assert len({event.event_id for event in events}) == len(events)


@pytest.mark.parametrize(
    ("from_state", "to_state"),
    [
        (CaseState.DISCOVERED, CaseState.MANUAL_INVESTIGATION),
        (CaseState.AFFECTED_CONFIRMED, CaseState.MITIGATED),
        (CaseState.PRIORITISED, CaseState.DEFERRED),
        (CaseState.AWAITING_APPROVAL, CaseState.APPROVAL_REJECTED),
        (CaseState.PATCH_PLAN_CREATED, CaseState.PATCH_FAILED),
        (CaseState.ROLLOUT, CaseState.PATCH_FAILED),
        (CaseState.PATCH_FAILED, CaseState.ROLLED_BACK),
    ],
)
def test_alternate_paths_are_explicit(case_fields, from_state, to_state):
    case = VulnerabilityCase(**case_fields, state=from_state)

    assert request(case, to_state).case.state is to_state


def test_not_affected_requires_explicit_assessment_and_preserves_provenance(case_fields):
    case = VulnerabilityCase(
        **{**case_fields, "affected_status": AffectedStatus.NOT_AFFECTED},
        state=CaseState.ASSET_MATCHED,
    )

    result = request(case, CaseState.NOT_AFFECTED)

    assert result.case.affected_status is AffectedStatus.NOT_AFFECTED
    assert result.case.state is CaseState.NOT_AFFECTED
    assert result.event.evidence_ids


@pytest.mark.parametrize("target", [CaseState.AFFECTED_CONFIRMED, CaseState.NOT_AFFECTED])
def test_unknown_cannot_silently_become_a_definitive_assessment(case_fields, target):
    case = VulnerabilityCase(
        **{**case_fields, "affected_status": AffectedStatus.UNKNOWN, "evidence_ids": []},
        state=CaseState.ASSET_MATCHED,
    )

    with pytest.raises(TransitionError, match="assessment"):
        request(case, target)
    assert case.affected_status is AffectedStatus.UNKNOWN


def test_expected_state_conflict_fails_on_current_snapshot(case_fields):
    case = VulnerabilityCase(**case_fields)
    updated = request(case, CaseState.ENRICHED).case

    with pytest.raises(StateConflictError):
        request(updated, CaseState.ASSET_MATCHED, expected_current_state=CaseState.DISCOVERED)
    assert updated.state is CaseState.ENRICHED


@pytest.mark.parametrize("actor", [None, "", {}])
def test_missing_or_untyped_actor_fails(case_fields, actor):
    with pytest.raises(TransitionError, match="actor is required"):
        request(VulnerabilityCase(**case_fields), CaseState.ENRICHED, actor=actor)


@pytest.mark.parametrize("reason", [None, "", " \n\t", 123])
def test_missing_or_blank_reason_fails(case_fields, reason):
    with pytest.raises(TransitionError, match="reason is required"):
        request(VulnerabilityCase(**case_fields), CaseState.ENRICHED, reason=reason)


@pytest.mark.parametrize("actor_id", ["", " \t"])
def test_actor_identity_cannot_be_blank(actor_id):
    with pytest.raises(ValidationError):
        Actor(actor_type=ActorType.HUMAN, actor_id=actor_id)


@pytest.mark.parametrize("references", [[], ["not-a-uuid"]])
def test_transition_requires_valid_nonempty_event_evidence(case_fields, references):
    with pytest.raises(ValidationError):
        request(VulnerabilityCase(**case_fields), CaseState.ENRICHED, evidence_ids=references)


@pytest.mark.parametrize("actor", [AGENT, SYSTEM])
def test_nonhuman_cannot_approve_production_changes(case_fields, actor):
    case = VulnerabilityCase(**case_fields, state=CaseState.AWAITING_APPROVAL)

    with pytest.raises(TransitionError, match="HUMAN"):
        request(case, CaseState.APPROVED, actor=actor)


@pytest.mark.parametrize(
    ("from_state", "to_state", "missing_field"),
    [
        (CaseState.AFFECTED_CONFIRMED, CaseState.PRIORITISED, "priority"),
        (CaseState.PRIORITISED, CaseState.PATCH_PLAN_CREATED, "remediation_plan_id"),
        (CaseState.AWAITING_APPROVAL, CaseState.APPROVED, "approval_id"),
        (CaseState.APPROVED, CaseState.CANARY_DEPLOYED, "approval_id"),
        (CaseState.APPROVED, CaseState.CANARY_DEPLOYED, "remediation_plan_id"),
        (CaseState.CANARY_DEPLOYED, CaseState.CANARY_VERIFIED, "verification_id"),
        (CaseState.RESCANNED, CaseState.VERIFIED_FIXED, "verification_id"),
    ],
)
def test_state_prerequisites_cannot_be_skipped(case_fields, from_state, to_state, missing_field):
    case = VulnerabilityCase(**{**case_fields, missing_field: None}, state=from_state)

    with pytest.raises(TransitionError):
        request(case, to_state)
    assert case.state is from_state


def test_agent_can_request_enrichment_but_cannot_attest_verified_closure(case_fields):
    discovered = VulnerabilityCase(**case_fields)
    assert request(discovered, CaseState.ENRICHED, actor=AGENT).case.state is CaseState.ENRICHED
    rescanned = VulnerabilityCase(**case_fields, state=CaseState.RESCANNED)

    with pytest.raises(TransitionError, match="verifier"):
        request(rescanned, CaseState.VERIFIED_FIXED, actor=AGENT)


@pytest.mark.parametrize(
    "terminal",
    [
        CaseState.NOT_AFFECTED, CaseState.VERIFIED_FIXED, CaseState.MITIGATED,
        CaseState.DEFERRED, CaseState.APPROVAL_REJECTED, CaseState.ROLLED_BACK,
        CaseState.MANUAL_INVESTIGATION,
    ],
)
def test_terminal_states_cannot_automatically_restart(case_fields, terminal):
    case = VulnerabilityCase(**case_fields, state=terminal)

    with pytest.raises(TransitionError, match="not permitted"):
        request(case, CaseState.DISCOVERED)


def test_event_and_case_cannot_be_mutated_outside_transition_service(case_fields):
    result = request(VulnerabilityCase(**case_fields), CaseState.ENRICHED)
    with pytest.raises(ValidationError):
        result.case.state = CaseState.APPROVED
    with pytest.raises(ValidationError):
        result.event.to_state = CaseState.APPROVED
    assert CaseEvent.model_validate_json(result.event.model_dump_json()) == result.event


def test_caller_cannot_clear_returned_evidence_by_mutating_input(case_fields):
    references = [uuid4()]
    original_reference = references[0]
    case = VulnerabilityCase(**case_fields)
    result = request(case, CaseState.ENRICHED, evidence_ids=references)
    references.clear()

    assert result.event.evidence_ids == (original_reference,)
    assert original_reference in result.case.evidence_ids
    assert case.evidence_ids == tuple(case_fields["evidence_ids"])


@pytest.mark.parametrize("timestamp", [NOW - timedelta(seconds=1), datetime(2026, 10, 25)])
def test_stale_or_naive_event_timestamps_fail(case_fields, timestamp):
    with pytest.raises((TransitionError, ValidationError)):
        request(VulnerabilityCase(**case_fields), CaseState.ENRICHED, occurred_at=timestamp)


def test_state_inputs_must_be_typed_not_arbitrary_labels(case_fields):
    with pytest.raises(TransitionError, match="CaseState"):
        request(VulnerabilityCase(**case_fields), "APPROVED")


def test_one_immutable_mapping_covers_every_state():
    assert set(ALLOWED_TRANSITIONS) == set(CaseState)
    assert all(isinstance(targets, frozenset) for targets in ALLOWED_TRANSITIONS.values())
    with pytest.raises(TypeError):
        ALLOWED_TRANSITIONS[CaseState.DISCOVERED] = frozenset({CaseState.APPROVED})
