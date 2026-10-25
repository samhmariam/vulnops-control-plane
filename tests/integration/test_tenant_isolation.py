"""Cross-tenant repository and PostgreSQL RLS checks with a non-superuser role."""

from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from vulnops.persistence.repositories import MissingReference, Repositories
from vulnops.persistence.session import tenant_session
from vulnops.domain.asset import Asset
from vulnops.workflow.events import Actor, ActorType
from vulnops.workflow.states import CaseState


pytestmark = pytest.mark.integration
TABLES = ("vulnerabilities", "assets", "installed_components", "evidence", "vulnerability_cases", "case_events")


@pytest.mark.parametrize("table", TABLES)
def test_forced_rls_hides_other_tenant_even_without_application_filter(database, tenant_id, stored, table):
    other_tenant = uuid4()
    with tenant_session(database[0], tenant_id) as session:
        repository = Repositories(session, tenant_id)
        repository.transition_case(
            stored["case"].case_id, expected_current_state=CaseState.DISCOVERED,
            new_state=CaseState.ENRICHED, actor=Actor(actor_type=ActorType.SYSTEM, actor_id="rls-test"),
            reason="Synthetic enrichment", evidence_ids=stored["case"].evidence_ids,
            occurred_at=stored["case"].updated_at + timedelta(minutes=1),
        )
        assert len(repository.list_case_history(stored["case"].case_id)) == 1
    with tenant_session(database[0], other_tenant) as session:
        # Deliberately omit a tenant filter to prove the database defence itself.
        assert session.scalar(text(f'SELECT count(*) FROM "{table}"')) == 0
        repository = Repositories(session, other_tenant)
        assert repository.load_case(stored["case"].case_id) is None
        assert repository.load_asset(stored["asset"].asset_id) is None
        assert repository.load_vulnerability(stored["vulnerability"].vulnerability_id) is None
        assert repository.list_case_history(stored["case"].case_id) == []
        assert session.execute(text(
            "UPDATE vulnerability_cases SET state = state WHERE tenant_id = :tenant"
        ), {"tenant": tenant_id}).rowcount == 0


def test_runtime_role_cannot_insert_another_tenants_rows(database, tenant_id, stored):
    with pytest.raises(DBAPIError) as error:
        with tenant_session(database[0], uuid4()) as session:
            session.execute(text(
                "INSERT INTO evidence (tenant_id, evidence_id, retrieved_at, payload) "
                "VALUES (:tenant, :evidence, now(), '{}'::jsonb)"
            ), {"tenant": tenant_id, "evidence": uuid4()})
    assert error.value.orig.sqlstate == "42501"


def test_foreign_tenant_evidence_and_case_references_are_rejected(database, tenant_id, stored):
    other_tenant = uuid4()
    with tenant_session(database[0], other_tenant) as session:
        repository = Repositories(session, other_tenant)
        with pytest.raises(MissingReference):
            repository.save_vulnerability(stored["vulnerability"])
        with pytest.raises(MissingReference):
            repository.save_case(stored["case"])


def test_same_identifiers_in_two_tenants_remain_independent(database, tenant_id, stored):
    other_tenant = uuid4()
    changed_asset = Asset.model_validate({**stored["asset"].model_dump(), "owner": "other-tenant-team"})
    with tenant_session(database[0], other_tenant) as session:
        repository = Repositories(session, other_tenant)
        repository.save_evidence(stored["evidence"])
        repository.save_vulnerability(stored["vulnerability"])
        repository.save_asset(changed_asset)
        repository.save_case(stored["case"])
        assert repository.load_asset(changed_asset.asset_id).owner == "other-tenant-team"
    with tenant_session(database[0], tenant_id) as session:
        assert Repositories(session, tenant_id).load_asset(changed_asset.asset_id).owner is None


def test_database_foreign_keys_cannot_attach_component_to_foreign_tenant_asset(database, tenant_id, stored):
    with pytest.raises(DBAPIError) as error:
        with tenant_session(database[0], uuid4()) as session:
            session.execute(text(
                "INSERT INTO installed_components (tenant_id, component_id, asset_id, position, payload) "
                "VALUES (NULLIF(current_setting('app.current_tenant_id'), '')::uuid, :component, :asset, 0, '{}'::jsonb)"
            ), {"component": uuid4(), "asset": stored["asset"].asset_id})
    assert error.value.orig.sqlstate == "23503"


def test_tenant_context_is_transaction_local_and_missing_context_defaults_to_deny(database, tenant_id, stored):
    with tenant_session(database[0], tenant_id) as session:
        assert session.scalar(text("SELECT count(*) FROM assets WHERE tenant_id = :tenant"), {"tenant": tenant_id}) == 1
    with database[0].connect() as connection:
        # Deliberately query without context/filter to prove pooled sessions fail closed.
        assert connection.scalar(text("SELECT count(*) FROM assets")) == 0


def test_every_table_has_forced_rls_and_a_policy(database):
    with database[1].connect() as connection:
        for table in TABLES:
            assert connection.execute(text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE oid = CAST(:table AS regclass)"
            ), {"table": table}).one() == (True, True)
            assert connection.scalar(text(
                "SELECT count(*) FROM pg_policies WHERE schemaname = 'public' "
                "AND tablename = :table AND policyname = 'tenant_isolation'"
            ), {"table": table}) == 1
