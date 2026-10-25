"""Infrastructure composition and tenant transaction boundaries for application use cases."""

from contextlib import contextmanager
from pathlib import Path
from uuid import UUID

from vulnops.application.inspection import InspectionService
from vulnops.application.walking_skeleton import (
    DEMO_TENANT_ID, WalkingDemoReport, load_demo_vulnerability,
    prepare_demo, persist_demo, verify_demo,
)
from vulnops.persistence.repositories import Repositories
from vulnops.persistence.session import create_database_engine, tenant_session


@contextmanager
def open_inspection(tenant_id: UUID):
    engine = create_database_engine()
    try:
        with tenant_session(engine, tenant_id) as session:
            yield InspectionService(Repositories(session, tenant_id))
    finally:
        engine.dispose()


def run_walking_demo(lab_dir: Path, tenant_id: UUID = DEMO_TENANT_ID) -> WalkingDemoReport:
    source = load_demo_vulnerability(lab_dir)
    engine = create_database_engine()
    try:
        with tenant_session(engine, tenant_id) as session:
            repository = Repositories(session, tenant_id)
            for evidence in source.evidence:
                repository.save_evidence(evidence)
            repository.save_vulnerability(source.vulnerability)
            plan = prepare_demo(lab_dir, source=source)
            blocked = persist_demo(repository, plan)
            verify_demo(repository, plan, blocked, tenant_id)
        # A separate transaction verifies committed data, not just uncommitted writes.
        with tenant_session(engine, tenant_id) as session:
            return verify_demo(Repositories(session, tenant_id), plan, blocked, tenant_id)
    finally:
        engine.dispose()
