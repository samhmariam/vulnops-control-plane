"""Shared real-PostgreSQL setup for integration and acceptance capabilities."""

import os
from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import text

from vulnops.persistence.session import create_database_engine


@pytest.fixture(scope="session")
def database():
    app_url = os.environ.get("VULNOPS_TEST_DATABASE_URL")
    admin_url = os.environ.get("VULNOPS_TEST_ADMIN_DATABASE_URL")
    if not app_url or not admin_url:
        pytest.skip("Set VULNOPS_TEST_DATABASE_URL and VULNOPS_TEST_ADMIN_DATABASE_URL for PostgreSQL tests")
    admin = create_database_engine(admin_url)
    app = create_database_engine(app_url)
    try:
        configuration = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
        with admin.begin() as connection:
            configuration.attributes["connection"] = connection
            command.upgrade(configuration, "head")
        with app.connect() as connection:
            role = connection.execute(text(
                "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
            )).one()
            assert role == (False, False), "Database tests must use a restricted runtime role"
        yield app, admin
    finally:
        app.dispose()
        admin.dispose()


@pytest.fixture
def tenant_id():
    return uuid4()
