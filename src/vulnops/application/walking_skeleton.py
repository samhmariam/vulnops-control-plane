"""Deterministic fixture ingestion, assessed cases, audit, and acceptance checks."""

from dataclasses import dataclass
from datetime import timedelta
import json
from pathlib import Path
from typing import Protocol
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict

from vulnops.application.assessment import AssetAssessment, assess_asset
from vulnops.domain.asset import Asset
from vulnops.domain.case import AffectedStatus, CaseExposure, VulnerabilityCase
from vulnops.domain.evidence import Evidence, EvidenceSource
from vulnops.domain.vulnerability import Vulnerability
from vulnops.sources.fixtures import FixtureVulnerabilitySource, load_fixture_inventory
from vulnops.sources.base import SourcedVulnerability
from vulnops.workflow.events import Actor, ActorType, CaseEvent
from vulnops.workflow.states import CaseState
from vulnops.workflow.transitions import TransitionError, transition_case


DEMO_TENANT_ID = UUID("d383a693-f08c-504b-bf7e-d7008885b119")
_NAMESPACE = UUID("43a1cd36-fae1-4a7f-a2db-068d02947c37")
_CVE = "CVE-2099-900001"
_ACTOR = Actor(actor_type=ActorType.SYSTEM, actor_id="vulnops-day1-demo-v1")
_DENIAL = "Transition AFFECTED_CONFIRMED -> APPROVED is not permitted"


class DemoAcceptanceError(RuntimeError):
    """The walking skeleton did not establish every required acceptance condition."""


class DemoRepository(Protocol):
    def save_evidence(self, value: Evidence) -> Evidence: ...
    def load_evidence(self, identity: UUID) -> Evidence | None: ...
    def save_vulnerability(self, value: Vulnerability) -> Vulnerability: ...
    def load_vulnerability(self, identity: UUID) -> Vulnerability | None: ...
    def save_asset(self, value: Asset) -> Asset: ...
    def load_asset(self, identity: UUID) -> Asset | None: ...
    def save_case(self, value: VulnerabilityCase) -> VulnerabilityCase: ...
    def load_case(self, identity: UUID) -> VulnerabilityCase | None: ...
    def append_case_event(self, value: CaseEvent) -> CaseEvent: ...
    def list_case_history(self, identity: UUID) -> list[CaseEvent]: ...
    def transition_case(self, identity: UUID, **request): ...


@dataclass(frozen=True)
class PlannedCase:
    initial: VulnerabilityCase
    final: VulnerabilityCase
    history: tuple[CaseEvent, ...]


@dataclass(frozen=True)
class DemoPlan:
    vulnerability: Vulnerability
    assets: tuple[Asset, ...]
    evidence: tuple[Evidence, ...]
    assessments: tuple[AssetAssessment, ...]
    cases: tuple[PlannedCase, ...]


class CaseOutcome(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    case: VulnerabilityCase
    history: list[CaseEvent]


class WalkingDemoReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    synthetic: bool = True
    persisted: bool = True
    tenant_id: UUID
    vulnerability: Vulnerability
    assets: list[Asset]
    assessments: list[AssetAssessment]
    outcomes: list[CaseOutcome]
    evidence: list[Evidence]
    blocked_transition: Evidence


def _require(condition, message):
    if not condition:
        raise DemoAcceptanceError(message)


def load_demo_vulnerability(lab_dir: Path) -> SourcedVulnerability:
    source, = FixtureVulnerabilitySource(lab_dir / "fixtures", cve_id=_CVE).fetch()
    return source


def prepare_demo(lab_dir: Path, *, source: SourcedVulnerability | None = None) -> DemoPlan:
    source = source or load_demo_vulnerability(lab_dir)
    inventory = load_fixture_inventory(lab_dir / "inventory")
    evidence = (*source.evidence, *(record for item in inventory for record in item.evidence))
    assessments = tuple(assess_asset(source.vulnerability, item.asset, list(evidence)) for item in inventory)
    by_asset = {item.asset.asset_id: item.asset for item in inventory}
    required = {
        "vulnops-lab:asset-web-01": AffectedStatus.AFFECTED,
        "vulnops-lab:asset-web-02": AffectedStatus.NOT_AFFECTED,
        "vulnops-lab:asset-legacy-01": AffectedStatus.UNKNOWN,
    }
    observed = {by_asset[item.asset_id].external_id: item.status for item in assessments if item.candidate}
    _require(all(observed.get(key) is value for key, value in required.items()), "Required fixture scenarios did not resolve as expected")
    cases = []
    timestamp = source.evidence[0].retrieved_at
    for assessment in assessments:
        if not assessment.candidate:
            continue
        asset = by_asset[assessment.asset_id]
        initial = VulnerabilityCase(
            case_id=uuid5(_NAMESPACE, f"case:{source.vulnerability.vulnerability_id}:{asset.asset_id}"),
            vulnerability_id=source.vulnerability.vulnerability_id, cve_id=source.vulnerability.cve_id,
            asset_id=asset.asset_id, affected_status=assessment.status,
            exposure=CaseExposure(internet_exposed=asset.internet_exposed, externally_reachable=asset.externally_reachable),
            evidence_ids=assessment.evidence_ids, created_at=timestamp, updated_at=timestamp,
        )
        case = initial
        history = []
        target = {
            AffectedStatus.AFFECTED: CaseState.AFFECTED_CONFIRMED,
            AffectedStatus.NOT_AFFECTED: CaseState.NOT_AFFECTED,
            AffectedStatus.UNKNOWN: CaseState.MANUAL_INVESTIGATION,
        }[assessment.status]
        for step, state in enumerate((CaseState.ENRICHED, CaseState.ASSET_MATCHED, target), start=1):
            result = transition_case(
                case=case, expected_current_state=case.state, new_state=state, actor=_ACTOR,
                reason=("Deterministic asset assessment: " + assessment.model_dump_json()
                        if state is CaseState.ASSET_MATCHED else f"Synthetic Day 1: {assessment.reason}"),
                evidence_ids=assessment.evidence_ids, correlation_id=initial.case_id,
                occurred_at=timestamp + timedelta(seconds=step),
            )
            event = CaseEvent.model_validate({**result.event.model_dump(),
                "event_id": uuid5(_NAMESPACE, f"event:{initial.case_id}:{step}:{state.value}")})
            history.append(event)
            case = result.case
        cases.append(PlannedCase(initial, case, tuple(history)))
    return DemoPlan(source.vulnerability, tuple(item.asset for item in inventory), tuple(evidence),
                    tuple(item for item in assessments if item.candidate), tuple(cases))


def persist_demo(repository: DemoRepository, plan: DemoPlan) -> Evidence:
    for evidence in plan.evidence:
        _require(repository.save_evidence(evidence) == evidence, "Evidence identity/content changed")
    _require(repository.save_vulnerability(plan.vulnerability) == plan.vulnerability, "Vulnerability did not persist exactly")
    for asset in plan.assets:
        _require(repository.save_asset(asset) == asset, "Asset did not persist exactly")
    for item in plan.cases:
        existing = repository.load_case(item.initial.case_id)
        if existing is None:
            _require(repository.save_case(item.initial) == item.initial, "Unexpected existing case identity")
        else:
            _require(existing == item.final and repository.list_case_history(existing.case_id) == list(item.history),
                     "Existing demo case or history differs; no reset or overwrite is allowed")
        for event in item.history:
            _require(repository.append_case_event(event) == event, "Case event did not persist exactly")

    affected = next(item.final for item in plan.cases if item.final.state is CaseState.AFFECTED_CONFIRMED)
    before = repository.list_case_history(affected.case_id)
    try:
        repository.transition_case(
            affected.case_id, expected_current_state=CaseState.AFFECTED_CONFIRMED,
            new_state=CaseState.APPROVED, actor=_ACTOR,
            reason="Demonstrate rejection of an approval shortcut", evidence_ids=affected.evidence_ids,
            correlation_id=affected.case_id, occurred_at=affected.updated_at + timedelta(seconds=1),
        )
    except TransitionError as error:
        _require(type(error) is TransitionError and str(error) == _DENIAL, "Approval attempt failed for a reason other than the prohibited edge")
    else:
        raise DemoAcceptanceError("Illegal approval transition was accepted")
    _require(repository.load_case(affected.case_id) == affected and repository.list_case_history(affected.case_id) == before,
             "Denied transition changed authoritative state or history")
    blocked = Evidence(
        evidence_id=uuid5(_NAMESPACE, f"blocked:{affected.case_id}:approved"),
        source_type=EvidenceSource.SYSTEM, source_name="VulnOps Day 1 transition policy probe",
        retrieved_at=affected.updated_at + timedelta(seconds=1), subject_type="case", subject_id=str(affected.case_id),
        claim_type="blocked_transition_attempt", claim=json.dumps({
            "from_state": "AFFECTED_CONFIRMED", "requested_state": "APPROVED", "blocked": True,
            "reason": _DENIAL, "state_unchanged": True, "history_unchanged": True,
            "correlation_id": str(affected.case_id),
        }, sort_keys=True), metadata={"synthetic": True},
    )
    _require(repository.save_evidence(blocked) == blocked, "Denied-attempt observation did not persist")
    return blocked


def verify_demo(repository: DemoRepository, plan: DemoPlan, blocked: Evidence, tenant_id: UUID) -> WalkingDemoReport:
    _require(repository.load_vulnerability(plan.vulnerability.vulnerability_id) == plan.vulnerability, "Vulnerability readback failed")
    loaded_assets = []
    for asset in plan.assets:
        loaded = repository.load_asset(asset.asset_id)
        _require(loaded == asset, "Inventory readback failed")
        loaded_assets.append(loaded)
    evidence = []
    for record in (*plan.evidence, blocked):
        loaded = repository.load_evidence(record.evidence_id)
        _require(loaded == record, "Evidence readback failed")
        evidence.append(loaded)
    outcomes = []
    for item in plan.cases:
        case = repository.load_case(item.final.case_id)
        history = repository.list_case_history(item.final.case_id)
        _require(case == item.final and history == list(item.history), "Case or history readback failed")
        outcomes.append(CaseOutcome(case=case, history=history))
    assets = {asset.asset_id: asset.external_id for asset in plan.assets}
    scenarios = {assets[item.case.asset_id]: item for item in outcomes}
    for name, status, state in (
        ("asset-web-01", AffectedStatus.AFFECTED, CaseState.AFFECTED_CONFIRMED),
        ("asset-web-02", AffectedStatus.NOT_AFFECTED, CaseState.NOT_AFFECTED),
        ("asset-legacy-01", AffectedStatus.UNKNOWN, CaseState.MANUAL_INVESTIGATION),
    ):
        result = scenarios.get(f"vulnops-lab:{name}")
        _require(result is not None and result.case.affected_status is status and result.case.state is state,
                 "A required persisted scenario did not reach its required outcome")
        _require([event.to_state for event in result.history] == [CaseState.ENRICHED, CaseState.ASSET_MATCHED, state],
                 "A required scenario has incomplete lifecycle history")
    return WalkingDemoReport(
        tenant_id=tenant_id, vulnerability=plan.vulnerability, assets=loaded_assets, assessments=list(plan.assessments),
        outcomes=outcomes, evidence=evidence, blocked_transition=blocked,
    )
