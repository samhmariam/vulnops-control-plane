"""The persistence adapter requires explicit PostgreSQL configuration."""

import pytest

from vulnops.persistence.session import create_database_engine


def test_missing_database_configuration_fails_explicitly(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValueError, match="Set DATABASE_URL"):
        create_database_engine()


@pytest.mark.parametrize("url", ["sqlite:///:memory:", "postgresql://localhost/vulnops"])
def test_only_postgresql_psycopg_is_supported(url):
    with pytest.raises(ValueError, match="postgresql\\+psycopg"):
        create_database_engine(url)
