"""Day 1 regression boundary: observable capabilities over real PostgreSQL.

These scenarios do not inspect policy mappings, SQLAlchemy record classes, or
private application helpers. SQL counts check durable record cardinality only.
"""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import UUID, uuid4

from pydantic import ValidationError
import pytest
from sqlalchemy import text

from vulnops.application.assessment import assess_asset
from vulnops.application.bootstrap import open_inspection, run_walking_demo
from vulnops.domain.case import AffectedStatus, VulnerabilityCase
from vulnops.domain.evidence import EvidenceSource
from vulnops.matching.affected_resolver import resolve_affected
from vulnops.persistence.repositories import MissingReference, Repositories
from vulnops.persistence.session import tenant_session
from vulnops.workflow.states import CaseState


pytestmark = [pytest.mark.acceptance, pytest.mark.integration]
LAB = Path(__file__).resolve().parents[2] / "lab"


@dataclass(frozen=True)
class Context:
    tenant_id: UUID
    engine: object
    report: object


@pytest.fixture(scope="module")
def context(acceptance_database):
    tenant_id = uuid4()
    engine = acceptance_database[0]
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("DATABASE_URL", engine.url.render_as_string(hide_password=False))
        report = run_walking_demo(LAB, tenant_id)
        yield Context(tenant_id, engine, report)


def asset_and_case(context, name):
    with open_inspection(context.tenant_id) as service:
        assets = service.list_assets()
        asset = next(item for item in assets if item.external_id == f"vulnops-lab:{name}")
        case, = [item for item in service.list_cases() if item.asset_id == asset.asset_id]
        return asset, service.show_case(case.case_id)


def supporting_evidence(context, references):
    assert references, "A material conclusion must carry supporting provenance"
    with tenant_session(context.engine, context.tenant_id) as session:
        repository = Repositories(session, context.tenant_id)
        records = [repository.load_evidence(identity) for identity in references]
    assert all(record is not None for record in records)
    return records


def test_scenario_1_confirmed_affected_has_case_and_supporting_evidence(context):
    asset, case = asset_and_case(context, "asset-web-01")
    with open_inspection(context.tenant_id) as service:
        vulnerability = service.show_vulnerability(case.cve_id)
    component = next(item for item in asset.components if item.identity.purl == "pkg:pypi/vulnops-lab-web")
    product, = vulnerability.affected_products
    assert component.identity.purl == product.product.purl
    assert component.installed_version == "1.4.0"
    assert any(item.introduced_version == "1.0.0" and item.fixed_version == "2.0.0"
               for item in product.version_constraints)
    assert resolve_affected(component, product).status is AffectedStatus.AFFECTED
    assert case.affected_status is AffectedStatus.AFFECTED
    assert case.state is CaseState.AFFECTED_CONFIRMED
    records = supporting_evidence(context, case.evidence_ids)
    assert {EvidenceSource.CVE, EvidenceSource.ASSET_INVENTORY} <= {item.source_type for item in records}


def test_scenario_2_fixed_version_is_not_affected_with_complete_inventory(context):
    asset, case = asset_and_case(context, "asset-web-02")
    with open_inspection(context.tenant_id) as service:
        vulnerability = service.show_vulnerability(case.cve_id)
    component = next(item for item in asset.components if item.identity.purl == "pkg:pypi/vulnops-lab-web")
    product, = vulnerability.affected_products
    assert component.installed_version == "2.0.0"
    assert any(item.fixed_version == component.installed_version for item in product.version_constraints)
    assert resolve_affected(component, product).status is AffectedStatus.NOT_AFFECTED
    assert case.affected_status is AffectedStatus.NOT_AFFECTED
    assert case.state is CaseState.NOT_AFFECTED
    records = supporting_evidence(context, case.evidence_ids)
    assert any(item.source_type is EvidenceSource.ASSET_INVENTORY
               and item.subject_id == str(asset.asset_id)
               and item.metadata.get("component_inventory_complete") is True for item in records)


def test_scenario_3_missing_version_stays_unknown_and_requires_manual_investigation(context):
    asset, case = asset_and_case(context, "asset-legacy-01")
    assert all(item.installed_version is None for item in asset.components)
    assert case.affected_status is AffectedStatus.UNKNOWN
    assert case.state is CaseState.MANUAL_INVESTIGATION
    with open_inspection(context.tenant_id) as service:
        history = service.case_history(case.case_id)
    assert history[-1].to_state is CaseState.MANUAL_INVESTIGATION
    assert all(item.to_state is not CaseState.NOT_AFFECTED for item in history)
    for event in history:
        supporting_evidence(context, event.evidence_ids)


def test_scenario_4_illegal_approval_is_denied_and_its_attempt_remains_observable(context):
    with open_inspection(context.tenant_id) as service:
        before = {case.case_id: case for case in service.list_cases()}
        histories_before = {identity: service.case_history(identity) for identity in before}
    # Exercise the application operation that attempts the edge and records its denial;
    # a bare repository exception alone would not prove an observable audit attempt.
    report = run_walking_demo(LAB, context.tenant_id)
    with open_inspection(context.tenant_id) as service:
        for identity, case in before.items():
            assert service.show_case(identity) == case
            assert service.case_history(identity) == histories_before[identity]
    observation, = supporting_evidence(context, [report.blocked_transition.evidence_id])
    assert observation.source_type is EvidenceSource.SYSTEM
    target = before[UUID(observation.subject_id)]
    assert target.state is CaseState.AFFECTED_CONFIRMED
    attempt = json.loads(observation.claim)
    assert (attempt["from_state"], attempt["requested_state"]) == ("AFFECTED_CONFIRMED", "APPROVED")
    assert attempt["blocked"] and attempt["state_unchanged"] and attempt["history_unchanged"]
    assert attempt["reason"] and attempt["correlation_id"]


def test_scenario_5_missing_unresolved_or_foreign_provenance_cannot_authorize_affectedness(context):
    asset, case = asset_and_case(context, "asset-web-01")
    with pytest.raises(ValidationError):
        VulnerabilityCase.model_validate({**case.model_dump(), "case_id": uuid4(), "evidence_ids": ()})
    with pytest.raises(ValueError):
        assess_asset(context.report.vulnerability, asset, [])
    forged = VulnerabilityCase.model_validate({**case.model_dump(), "case_id": uuid4(),
        "state": CaseState.DISCOVERED, "evidence_ids": (uuid4(),)})
    with tenant_session(context.engine, context.tenant_id) as session:
        with pytest.raises(MissingReference):
            Repositories(session, context.tenant_id).save_case(forged)
    foreign_tenant = uuid4()
    with tenant_session(context.engine, foreign_tenant) as session:
        repository = Repositories(session, foreign_tenant)
        foreign = VulnerabilityCase.model_validate({**forged.model_dump(), "evidence_ids": case.evidence_ids})
        with pytest.raises(MissingReference):
            repository.save_case(foreign)
        assert repository.load_case(foreign.case_id) is None


def test_scenario_6_new_application_process_reloads_cases_and_complete_histories(context):
    program = """
import json, os
from uuid import UUID
from vulnops.application.bootstrap import open_inspection
with open_inspection(UUID(os.environ['VULNOPS_TENANT_ID'])) as service:
    cases = service.list_cases()
    result = [{'case': case.model_dump(mode='json'),
               'history': [event.model_dump(mode='json') for event in service.case_history(case.case_id)]}
              for case in cases]
print(json.dumps(result, sort_keys=True))
"""
    completed = subprocess.run(
        [sys.executable, "-I", "-c", program], cwd=LAB.parent,
        env={**os.environ, "VULNOPS_TENANT_ID": str(context.tenant_id)},
        capture_output=True, text=True, timeout=60, check=True,
    )
    expected = [{"case": item.case.model_dump(mode="json"),
                 "history": [event.model_dump(mode="json") for event in item.history]}
                for item in sorted(context.report.outcomes, key=lambda item: item.case.case_id)]
    assert json.loads(completed.stdout) == expected
    assert all(item["history"] for item in expected)


def record_counts(context):
    tables = ("vulnerabilities", "assets", "installed_components", "vulnerability_cases", "evidence", "case_events")
    with tenant_session(context.engine, context.tenant_id) as session:
        # Fixed table names; tenant identity is bound and the runtime role also enforces RLS.
        return {table: session.scalar(text(f"SELECT count(*) FROM {table} WHERE tenant_id = :tenant"),
                                      {"tenant": context.tenant_id}) for table in tables}


def test_scenario_7_exact_fixture_replay_does_not_duplicate_core_records(context):
    before = record_counts(context)
    assert before["vulnerabilities"] == 1
    assert before["assets"] == len(context.report.assets)
    assert before["installed_components"] == sum(len(asset.components) for asset in context.report.assets)
    assert before["vulnerability_cases"] == len(context.report.outcomes)
    assert before["evidence"] == len(context.report.evidence)
    assert before["case_events"] == sum(len(item.history) for item in context.report.outcomes)
    replay = run_walking_demo(LAB, context.tenant_id)
    assert record_counts(context) == before
    assert replay == context.report


def test_scenario_8_one_cve_has_independent_affected_unaffected_and_unknown_assets(context):
    with open_inspection(context.tenant_id) as service:
        cases = service.list_cases()
    assert {case.cve_id for case in cases} == {context.report.vulnerability.cve_id}
    assert {case.vulnerability_id for case in cases} == {context.report.vulnerability.vulnerability_id}
    assert len({case.asset_id for case in cases}) == len(cases)
    assert {case.affected_status for case in cases} == {
        AffectedStatus.AFFECTED, AffectedStatus.NOT_AFFECTED, AffectedStatus.UNKNOWN,
    }
