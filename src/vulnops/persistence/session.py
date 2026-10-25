"""Explicit PostgreSQL engines and transaction-local tenant context."""

from contextlib import contextmanager
import os
from uuid import UUID

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session


def create_database_engine(url: str | None = None) -> Engine:
    database_url = url or os.environ.get("DATABASE_URL")
    if not database_url:
        raise ValueError("Set DATABASE_URL to a PostgreSQL psycopg connection URL")
    parsed = make_url(database_url)
    if parsed.drivername != "postgresql+psycopg":
        raise ValueError("Only postgresql+psycopg is supported")
    return create_engine(
        parsed, pool_pre_ping=True, hide_parameters=True,
        connect_args={"connect_timeout": 5},
    )


@contextmanager
def tenant_session(engine: Engine, tenant_id: UUID):
    """Commit one unit of work or roll it back; tenant state never escapes it."""
    if not isinstance(tenant_id, UUID):
        raise ValueError("tenant_id must be a UUID resolved by the application")
    with Session(engine, expire_on_commit=False) as session:
        with session.begin():
            session.execute(
                text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
                {"tenant_id": str(tenant_id)},
            )
            session.info["tenant_id"] = tenant_id
            yield session
