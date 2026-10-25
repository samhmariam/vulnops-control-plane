"""Infrastructure composition for a single tenant-scoped inspection operation."""

from contextlib import contextmanager
from uuid import UUID

from vulnops.application.inspection import InspectionService
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
