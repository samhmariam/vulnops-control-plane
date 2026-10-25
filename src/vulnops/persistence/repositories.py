"""Tenant-scoped repositories returning domain objects, never ORM records.

Saves create or exactly replay snapshots. Conflicting content is explicit rather
than silently merging claims. Lifecycle changes and audit appends are atomic.
"""

import json
from uuid import UUID

from sqlalchemy import or_, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from vulnops.domain.asset import Asset
from vulnops.domain.case import VulnerabilityCase
from vulnops.domain.evidence import Evidence
from vulnops.domain.vulnerability import Vulnerability
from vulnops.persistence.models import (
    AssetRecord, CaseEventRecord, CaseRecord, EvidenceRecord,
    InstalledComponentRecord, VulnerabilityRecord,
)
from vulnops.workflow.events import Actor, CaseEvent
from vulnops.workflow.states import CaseState
from vulnops.workflow.transitions import StateConflictError, TransitionResult
from vulnops.workflow.transitions import transition_case as validate_transition


class RepositoryConflict(ValueError):
    """An existing identity was replayed with different content."""


class MissingReference(ValueError):
    """Required evidence or related records are absent in this tenant."""


def _decode(model, payload):
    return model.model_validate_json(json.dumps(payload))


def _revalidate(value):
    return type(value).model_validate_json(value.model_dump_json())


class Repositories:
    def __init__(self, session: Session, tenant_id: UUID):
        if not session.in_transaction() or session.info.get("tenant_id") != tenant_id:
            raise ValueError("Repositories require an active matching tenant_session")
        self._session = session
        self._tenant_id = tenant_id

    def _row(self, model, predicate, *, lock=False):
        query = select(model).where(model.tenant_id == self._tenant_id, predicate)
        if lock:
            query = query.with_for_update().execution_options(populate_existing=True)
        return self._session.scalars(query).one_or_none()

    def _require_evidence(self, references):
        required = set(references)
        if not required:
            return
        found = set(self._session.scalars(select(EvidenceRecord.evidence_id).where(
            EvidenceRecord.tenant_id == self._tenant_id,
            EvidenceRecord.evidence_id.in_(required),
        )))
        if found != required:
            raise MissingReference("Evidence references must exist in the current tenant")

    def _insert_snapshot(self, record, values, predicate, id_field):
        inserted = self._session.execute(
            insert(record).values(tenant_id=self._tenant_id, **values)
            .on_conflict_do_nothing().returning(getattr(record, id_field))
        ).scalar_one_or_none()
        row = self._row(record, predicate)
        if row is None:
            raise RepositoryConflict("Snapshot identity conflicts with an existing record")
        incoming = {key: value for key, value in values["payload"].items() if key != id_field}
        stored = {key: value for key, value in row.payload.items() if key != id_field}
        if incoming != stored:
            raise RepositoryConflict("Existing snapshot differs; explicit reconciliation is required")
        return row, inserted is not None

    def save_evidence(self, evidence: Evidence) -> Evidence:
        evidence = _revalidate(evidence)
        with self._session.begin_nested():
            row, _ = self._insert_snapshot(
                EvidenceRecord,
                {"evidence_id": evidence.evidence_id, "retrieved_at": evidence.retrieved_at,
                 "payload": evidence.model_dump(mode="json")},
                EvidenceRecord.evidence_id == evidence.evidence_id, "evidence_id",
            )
            return _decode(Evidence, row.payload)

    def load_evidence(self, evidence_id: UUID) -> Evidence | None:
        row = self._row(EvidenceRecord, EvidenceRecord.evidence_id == evidence_id)
        return _decode(Evidence, row.payload) if row else None

    def save_vulnerability(self, vulnerability: Vulnerability) -> Vulnerability:
        vulnerability = _revalidate(vulnerability)
        references = list(vulnerability.evidence_ids)
        for product in vulnerability.affected_products:
            references.extend(product.evidence_ids)
        for observation in [*vulnerability.cvss_observations, vulnerability.kev_observation, vulnerability.epss_observation]:
            if observation is not None:
                references.extend(observation.evidence_ids)
        with self._session.begin_nested():
            self._require_evidence(references)
            predicate = VulnerabilityRecord.vulnerability_id == vulnerability.vulnerability_id
            if vulnerability.cve_id is not None:
                predicate = or_(predicate, VulnerabilityRecord.cve_id == vulnerability.cve_id)
            row, _ = self._insert_snapshot(
                VulnerabilityRecord,
                {"vulnerability_id": vulnerability.vulnerability_id, "cve_id": vulnerability.cve_id,
                 "payload": vulnerability.model_dump(mode="json")},
                predicate, "vulnerability_id",
            )
            return _decode(Vulnerability, row.payload)

    def load_vulnerability(self, vulnerability_id: UUID) -> Vulnerability | None:
        row = self._row(VulnerabilityRecord, VulnerabilityRecord.vulnerability_id == vulnerability_id)
        return _decode(Vulnerability, row.payload) if row else None

    def save_asset(self, asset: Asset) -> Asset:
        asset = _revalidate(asset)
        with self._session.begin_nested():
            self._require_evidence([*asset.evidence_ids, *(ref for component in asset.components for ref in component.evidence_ids)])
            predicate = AssetRecord.asset_id == asset.asset_id
            if asset.external_id is not None:
                predicate = or_(predicate, AssetRecord.external_id == asset.external_id)
            row, created = self._insert_snapshot(
                AssetRecord,
                {"asset_id": asset.asset_id, "external_id": asset.external_id,
                 "payload": asset.model_dump(mode="json", exclude={"components"})},
                predicate, "asset_id",
            )
            expected_components = []
            for position, component in enumerate(asset.components):
                payload = component.model_dump(mode="json")
                payload["asset_id"] = str(row.asset_id)
                expected_components.append(payload)
                if created:
                    self._session.execute(insert(InstalledComponentRecord).values(
                        tenant_id=self._tenant_id, component_id=component.component_id,
                        asset_id=row.asset_id, position=position, payload=payload,
                    ))
            loaded = self.load_asset(row.asset_id)
            if [component.model_dump(mode="json") for component in loaded.components] != expected_components:
                raise RepositoryConflict("Installed component snapshot differs; reconcile explicitly")
            return loaded

    def load_asset(self, asset_id: UUID) -> Asset | None:
        row = self._row(AssetRecord, AssetRecord.asset_id == asset_id)
        if row is None:
            return None
        components = self._session.scalars(select(InstalledComponentRecord).where(
            InstalledComponentRecord.tenant_id == self._tenant_id,
            InstalledComponentRecord.asset_id == asset_id,
        ).order_by(InstalledComponentRecord.position))
        return _decode(Asset, {**row.payload, "components": [component.payload for component in components]})

    def save_case(self, case: VulnerabilityCase) -> VulnerabilityCase:
        case = _revalidate(case)
        if case.state is not CaseState.DISCOVERED:
            raise RepositoryConflict("New cases must be DISCOVERED; use transition_case for changes")
        with self._session.begin_nested():
            self._require_evidence(case.evidence_ids)
            vulnerability = self.load_vulnerability(case.vulnerability_id)
            if vulnerability is None or self.load_asset(case.asset_id) is None:
                raise MissingReference("Case vulnerability and asset must exist in this tenant")
            if case.cve_id != vulnerability.cve_id:
                raise MissingReference("Case CVE must match its canonical vulnerability")
            row, _ = self._insert_snapshot(
                CaseRecord,
                {"case_id": case.case_id, "vulnerability_id": case.vulnerability_id,
                 "asset_id": case.asset_id, "state": case.state.value, "revision": 0,
                 "updated_at": case.updated_at, "payload": case.model_dump(mode="json")},
                or_(CaseRecord.case_id == case.case_id,
                    (CaseRecord.vulnerability_id == case.vulnerability_id) & (CaseRecord.asset_id == case.asset_id)),
                "case_id",
            )
            return _decode(VulnerabilityCase, row.payload)

    def load_case(self, case_id: UUID) -> VulnerabilityCase | None:
        row = self._row(CaseRecord, CaseRecord.case_id == case_id)
        return _decode(VulnerabilityCase, row.payload) if row else None

    def _locked_case(self, case_id):
        row = self._row(CaseRecord, CaseRecord.case_id == case_id, lock=True)
        if row is None:
            raise MissingReference("Case does not exist in this tenant")
        return row

    def _store_transition(self, row, result: TransitionResult):
        self._require_evidence(result.case.evidence_ids)
        sequence = row.revision + 1
        changed = self._session.execute(update(CaseRecord).where(
            CaseRecord.tenant_id == self._tenant_id, CaseRecord.case_id == row.case_id,
            CaseRecord.state == result.event.from_state.value, CaseRecord.revision == row.revision,
        ).values(
            state=result.case.state.value, updated_at=result.case.updated_at,
            revision=sequence, payload=result.case.model_dump(mode="json"),
        ).returning(CaseRecord.case_id)).scalar_one_or_none()
        if changed is None:
            raise StateConflictError("Stored case state or revision changed")
        self._session.execute(insert(CaseEventRecord).values(
            tenant_id=self._tenant_id, event_id=result.event.event_id,
            case_id=result.event.case_id, sequence=sequence, created_at=result.event.created_at,
            payload=result.event.model_dump(mode="json"),
        ))
        return result

    def transition_case(self, case_id: UUID, **request) -> TransitionResult:
        """Check the current stored case, update it, and append its event atomically."""
        with self._session.begin_nested():
            row = self._locked_case(case_id)
            result = validate_transition(case=_decode(VulnerabilityCase, row.payload), **request)
            return self._store_transition(row, result)

    def append_case_event(self, event: CaseEvent) -> CaseEvent:
        """Append an event by applying its validated transition, or exactly replay it."""
        event = _revalidate(event)
        with self._session.begin_nested():
            row = self._locked_case(event.case_id)
            existing = self._row(CaseEventRecord, CaseEventRecord.event_id == event.event_id)
            if existing is not None:
                if existing.payload != event.model_dump(mode="json"):
                    raise RepositoryConflict("Historical events cannot be replaced")
                return _decode(CaseEvent, existing.payload)
            result = validate_transition(
                case=_decode(VulnerabilityCase, row.payload),
                expected_current_state=event.from_state, new_state=event.to_state,
                actor=Actor(actor_type=event.actor_type, actor_id=event.actor_id),
                reason=event.reason, evidence_ids=event.evidence_ids,
                correlation_id=event.correlation_id, occurred_at=event.created_at,
            )
            self._store_transition(row, TransitionResult(case=result.case, event=event))
            return event

    def list_case_history(self, case_id: UUID) -> list[CaseEvent]:
        rows = self._session.scalars(select(CaseEventRecord).where(
            CaseEventRecord.tenant_id == self._tenant_id, CaseEventRecord.case_id == case_id,
        ).order_by(CaseEventRecord.sequence))
        return [_decode(CaseEvent, row.payload) for row in rows]
