"""A separate application process used by the persistence restart test."""

from datetime import timedelta
import json
import os
from pathlib import Path
import sys
from uuid import UUID

from vulnops.domain.asset import Asset
from vulnops.domain.case import VulnerabilityCase
from vulnops.domain.evidence import Evidence
from vulnops.domain.vulnerability import Vulnerability
from vulnops.persistence.repositories import Repositories
from vulnops.persistence.session import create_database_engine, tenant_session
from vulnops.workflow.events import Actor, ActorType
from vulnops.workflow.states import CaseState


mode, tenant_text, fixture_path = sys.argv[1:]
fixture = json.loads(Path(fixture_path).read_text(encoding="utf-8"))
tenant_id = UUID(tenant_text)
case = VulnerabilityCase.model_validate_json(json.dumps(fixture["case"]))
engine = create_database_engine(os.environ["VULNOPS_TEST_DATABASE_URL"])
try:
    with tenant_session(engine, tenant_id) as session:
        repository = Repositories(session, tenant_id)
        if mode == "write":
            repository.save_evidence(Evidence.model_validate_json(json.dumps(fixture["evidence"])))
            repository.save_vulnerability(Vulnerability.model_validate_json(json.dumps(fixture["vulnerability"])))
            repository.save_asset(Asset.model_validate_json(json.dumps(fixture["asset"])))
            repository.save_case(case)
            repository.transition_case(
                case.case_id, expected_current_state=CaseState.DISCOVERED, new_state=CaseState.ENRICHED,
                actor=Actor(actor_type=ActorType.SYSTEM, actor_id="restart-probe"),
                reason="Synthetic enrichment completed", evidence_ids=case.evidence_ids,
                occurred_at=case.updated_at + timedelta(minutes=1),
            )
        output = {
            "pid": os.getpid(),
            "case": repository.load_case(case.case_id).model_dump(mode="json"),
            "vulnerability": repository.load_vulnerability(case.vulnerability_id).model_dump(mode="json"),
            "asset": repository.load_asset(case.asset_id).model_dump(mode="json"),
            "history": [event.model_dump(mode="json") for event in repository.list_case_history(case.case_id)],
        }
    print(json.dumps(output))
finally:
    engine.dispose()
