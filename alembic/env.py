"""Migration connections use an administrative URL, never runtime credentials."""

import os

from alembic import context

from vulnops.persistence.models import Base
from vulnops.persistence.session import create_database_engine


def run(connection):
    context.configure(connection=connection, target_metadata=Base.metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


connection = context.config.attributes.get("connection")
if connection is not None:
    run(connection)
else:
    url = os.environ.get("VULNOPS_MIGRATION_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if context.is_offline_mode():
        if not url:
            raise ValueError("Set VULNOPS_MIGRATION_DATABASE_URL")
        context.configure(url=url, target_metadata=Base.metadata, literal_binds=True)
        with context.begin_transaction():
            context.run_migrations()
    else:
        engine = create_database_engine(url)
        try:
            with engine.connect() as connection:
                run(connection)
        finally:
            engine.dispose()
