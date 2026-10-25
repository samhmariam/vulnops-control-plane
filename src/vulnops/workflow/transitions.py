"""Authoritative transition graph and an in-memory validation service."""

from datetime import datetime, timezone
from types import MappingProxyType
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict

from vulnops.domain.case import AffectedStatus, VulnerabilityCase
from vulnops.workflow.events import Actor, ActorType, CaseEvent
from vulnops.workflow.states import CaseState


# This is the sole edge policy. Empty successor sets stop automatic progression.
ALLOWED_TRANSITIONS = MappingProxyType({
    CaseState.DISCOVERED: frozenset({CaseState.ENRICHED, CaseState.MANUAL_INVESTIGATION}),
    CaseState.ENRICHED: frozenset({CaseState.ASSET_MATCHED, CaseState.MANUAL_INVESTIGATION}),
    CaseState.ASSET_MATCHED: frozenset({
        CaseState.AFFECTED_CONFIRMED, CaseState.NOT_AFFECTED, CaseState.MANUAL_INVESTIGATION,
    }),
    CaseState.AFFECTED_CONFIRMED: frozenset({
        CaseState.PRIORITISED, CaseState.MITIGATED, CaseState.DEFERRED, CaseState.MANUAL_INVESTIGATION,
    }),
    CaseState.PRIORITISED: frozenset({
        CaseState.PATCH_PLAN_CREATED, CaseState.MITIGATED, CaseState.DEFERRED, CaseState.MANUAL_INVESTIGATION,
    }),
    CaseState.PATCH_PLAN_CREATED: frozenset({
        CaseState.SANDBOX_TESTED, CaseState.PATCH_FAILED, CaseState.MANUAL_INVESTIGATION,
    }),
    CaseState.SANDBOX_TESTED: frozenset({CaseState.AWAITING_APPROVAL, CaseState.MANUAL_INVESTIGATION}),
    CaseState.AWAITING_APPROVAL: frozenset({
        CaseState.APPROVED, CaseState.APPROVAL_REJECTED, CaseState.DEFERRED, CaseState.MANUAL_INVESTIGATION,
    }),
    CaseState.APPROVED: frozenset({
        CaseState.CANARY_DEPLOYED, CaseState.PATCH_FAILED, CaseState.MANUAL_INVESTIGATION,
    }),
    CaseState.CANARY_DEPLOYED: frozenset({
        CaseState.CANARY_VERIFIED, CaseState.PATCH_FAILED, CaseState.MANUAL_INVESTIGATION,
    }),
    CaseState.CANARY_VERIFIED: frozenset({
        CaseState.ROLLOUT, CaseState.PATCH_FAILED, CaseState.MANUAL_INVESTIGATION,
    }),
    CaseState.ROLLOUT: frozenset({CaseState.RESCANNED, CaseState.PATCH_FAILED, CaseState.MANUAL_INVESTIGATION}),
    CaseState.RESCANNED: frozenset({CaseState.VERIFIED_FIXED, CaseState.PATCH_FAILED, CaseState.MANUAL_INVESTIGATION}),
    CaseState.PATCH_FAILED: frozenset({CaseState.ROLLED_BACK, CaseState.MANUAL_INVESTIGATION}),
    CaseState.VERIFIED_FIXED: frozenset(),
    CaseState.NOT_AFFECTED: frozenset(),
    CaseState.MITIGATED: frozenset(),
    CaseState.DEFERRED: frozenset(),
    CaseState.APPROVAL_REJECTED: frozenset(),
    CaseState.ROLLED_BACK: frozenset(),
    CaseState.MANUAL_INVESTIGATION: frozenset(),
})

_AFFECTED_STATES = frozenset({
    CaseState.AFFECTED_CONFIRMED, CaseState.PRIORITISED, CaseState.PATCH_PLAN_CREATED,
    CaseState.SANDBOX_TESTED, CaseState.AWAITING_APPROVAL, CaseState.APPROVED,
    CaseState.CANARY_DEPLOYED, CaseState.CANARY_VERIFIED, CaseState.ROLLOUT,
    CaseState.RESCANNED, CaseState.VERIFIED_FIXED, CaseState.MITIGATED,
})
_PRODUCTION_STATES = frozenset({
    CaseState.CANARY_DEPLOYED, CaseState.CANARY_VERIFIED, CaseState.ROLLOUT,
    CaseState.RESCANNED, CaseState.VERIFIED_FIXED, CaseState.ROLLED_BACK,
})


class TransitionError(ValueError):
    """A transition request violates lifecycle policy."""


class StateConflictError(TransitionError):
    """The request's expected state is stale for the supplied snapshot."""


class TransitionResult(BaseModel):
    """The replacement snapshot and the event that must be persisted with it."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    case: VulnerabilityCase
    event: CaseEvent


def transition_case(
    *,
    case: VulnerabilityCase,
    expected_current_state: CaseState,
    new_state: CaseState,
    actor: Actor,
    reason: str,
    evidence_ids: list[UUID] | tuple[UUID, ...],
    correlation_id: UUID | None = None,
    occurred_at: datetime | None = None,
) -> TransitionResult:
    """Validate an edge and return its snapshot/event without external side effects.

    Callers must resolve authenticated identity, evidence, and referenced records.
    Database compare-and-set and atomic event persistence are future boundaries.
    """
    if not isinstance(case, VulnerabilityCase):
        raise TransitionError("case must be a VulnerabilityCase")
    if not isinstance(expected_current_state, CaseState) or not isinstance(new_state, CaseState):
        raise TransitionError("expected_current_state and new_state must be CaseState values")
    if case.state is not expected_current_state:
        raise StateConflictError("Current state differs from expected_current_state")
    if new_state not in ALLOWED_TRANSITIONS[case.state]:
        raise TransitionError(f"Transition {case.state.value} -> {new_state.value} is not permitted")
    if not isinstance(actor, Actor):
        raise TransitionError("actor is required and must be an Actor")
    if not isinstance(reason, str) or not reason.strip():
        raise TransitionError("reason is required and must not be blank")

    event = CaseEvent(
        case_id=case.case_id,
        from_state=case.state,
        to_state=new_state,
        actor_type=actor.actor_type,
        actor_id=actor.actor_id,
        reason=reason,
        evidence_ids=evidence_ids,
        correlation_id=uuid4() if correlation_id is None else correlation_id,
        created_at=datetime.now(timezone.utc) if occurred_at is None else occurred_at,
    )
    if event.created_at < case.updated_at:
        raise TransitionError("Transition time must not precede the latest case update")
    if new_state in _AFFECTED_STATES and case.affected_status is not AffectedStatus.AFFECTED:
        raise TransitionError("Remediation progression requires an AFFECTED assessment")
    if new_state is CaseState.NOT_AFFECTED and case.affected_status is not AffectedStatus.NOT_AFFECTED:
        raise TransitionError("NOT_AFFECTED requires an explicit NOT_AFFECTED assessment")
    if new_state is CaseState.PRIORITISED and case.priority is None:
        raise TransitionError("PRIORITISED requires a priority from application policy")
    if new_state is CaseState.PATCH_PLAN_CREATED and case.remediation_plan_id is None:
        raise TransitionError("PATCH_PLAN_CREATED requires remediation_plan_id")
    if new_state in {CaseState.APPROVED, CaseState.APPROVAL_REJECTED}:
        if actor.actor_type is not ActorType.HUMAN:
            raise TransitionError("Approval decisions require a HUMAN actor")
        if new_state is CaseState.APPROVED and case.approval_id is None:
            raise TransitionError("APPROVED requires approval_id")
    if new_state in _PRODUCTION_STATES:
        if case.approval_id is None or case.remediation_plan_id is None:
            raise TransitionError("Production progression requires approval and remediation plan references")
    if new_state in {CaseState.CANARY_VERIFIED, CaseState.VERIFIED_FIXED}:
        if case.verification_id is None or actor.actor_type is ActorType.AGENT:
            raise TransitionError("Verification requires verification_id and a HUMAN or SYSTEM verifier")

    fields = case.model_dump()
    fields.update(
        state=new_state,
        updated_at=event.created_at,
        evidence_ids=tuple(dict.fromkeys((*case.evidence_ids, *event.evidence_ids))),
    )
    updated_case = VulnerabilityCase.model_validate(fields)
    return TransitionResult(case=updated_case, event=event)
