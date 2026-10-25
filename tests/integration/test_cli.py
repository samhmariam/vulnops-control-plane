from datetime import timedelta
import json
from uuid import uuid4

import pytest

from vulnops.cli import main
from vulnops.application.inspection import InspectionService, RecordNotFound
from vulnops.persistence.repositories import Repositories
from vulnops.persistence.session import tenant_session
from vulnops.workflow.events import Actor, ActorType
from vulnops.workflow.states import CaseState


pytestmark = pytest.mark.integration


def test_all_database_commands_and_evidence_references(database, tenant_id, stored, monkeypatch, capsys):
    monkeypatch.setenv("DATABASE_URL", database[0].url.render_as_string(hide_password=False))
    with tenant_session(database[0], tenant_id) as session:
        Repositories(session, tenant_id).transition_case(
            stored["case"].case_id, expected_current_state=CaseState.DISCOVERED,
            new_state=CaseState.ENRICHED, actor=Actor(actor_type=ActorType.SYSTEM, actor_id="cli-test"),
            reason="Synthetic enrichment", evidence_ids=stored["case"].evidence_ids,
            occurred_at=stored["case"].updated_at + timedelta(seconds=1),
        )
    prefix = ["--tenant-id", str(tenant_id)]
    results = {}
    for name, arguments in {
        "vulnerability": ["vulnerability", "show", stored["vulnerability"].cve_id],
        "assets": ["asset", "list"],
        "asset": ["asset", "show", str(stored["asset"].asset_id)],
        "cases": ["case", "list"],
        "case": ["case", "show", str(stored["case"].case_id)],
        "history": ["case", "history", str(stored["case"].case_id)],
    }.items():
        assert main([*prefix, *arguments]) == 0
        results[name] = json.loads(capsys.readouterr().out)
    evidence_id = str(stored["evidence"].evidence_id)
    assert results["vulnerability"]["cve_id"] == stored["vulnerability"].cve_id
    assert results["asset"] == results["assets"][0]
    assert results["asset"]["components"][0]["evidence_ids"] == [evidence_id]
    assert results["case"] == results["cases"][0]
    assert results["case"]["affected_status"] == "UNKNOWN"
    assert results["case"]["evidence_ids"] == [evidence_id]
    event = results["history"][0]
    assert (event["from_state"], event["to_state"]) == ("DISCOVERED", "ENRICHED")
    assert event["evidence_ids"] == [evidence_id]
    assert event["actor_id"] and event["reason"] and event["correlation_id"] and event["created_at"]


def test_inspection_queries_and_cli_do_not_leak_other_tenant(database, tenant_id, stored, monkeypatch, capsys):
    other_tenant = uuid4()
    with tenant_session(database[0], other_tenant) as session:
        service = InspectionService(Repositories(session, other_tenant))
        assert service.list_assets() == []
        assert service.list_cases() == []
        for operation, identifier in [
            (service.show_vulnerability, stored["vulnerability"].cve_id),
            (service.show_asset, stored["asset"].asset_id),
            (service.show_case, stored["case"].case_id),
            (service.case_history, stored["case"].case_id),
        ]:
            with pytest.raises(RecordNotFound):
                operation(identifier)
    monkeypatch.setenv("DATABASE_URL", database[0].url.render_as_string(hide_password=False))
    for identifier in (stored["case"].case_id, uuid4()):
        assert main(["--tenant-id", str(other_tenant), "case", "show", str(identifier)]) == 3
        assert capsys.readouterr().err == "Record not found in this tenant.\n"


def test_empty_history_and_paginated_reads(database, tenant_id, stored):
    with tenant_session(database[0], tenant_id) as session:
        service = InspectionService(Repositories(session, tenant_id))
        assert service.case_history(stored["case"].case_id) == []
        assert service.list_assets(limit=1) == [stored["asset"]]
        assert service.list_assets(offset=1) == []
        assert service.list_cases(limit=1) == [stored["case"]]
        assert service.list_cases(offset=1) == []
