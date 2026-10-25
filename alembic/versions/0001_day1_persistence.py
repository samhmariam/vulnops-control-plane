"""Day 1 snapshots, relational identities, audit order, and forced tenant RLS."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0001_day1"
down_revision = None
branch_labels = None
depends_on = None


TABLES = (
    "vulnerabilities", "assets", "installed_components", "evidence",
    "vulnerability_cases", "case_events",
)


def snapshot_columns():
    return [
        sa.Column("tenant_id", sa.Uuid(), primary_key=True),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
    ]


def upgrade():
    op.create_table(
        "vulnerabilities", *snapshot_columns(),
        sa.Column("vulnerability_id", sa.Uuid(), primary_key=True),
        sa.Column("cve_id", sa.String(), nullable=True),
        sa.UniqueConstraint("tenant_id", "cve_id", name="uq_vulnerabilities_cve"),
    )
    op.create_table(
        "assets", *snapshot_columns(),
        sa.Column("asset_id", sa.Uuid(), primary_key=True),
        sa.Column("external_id", sa.String(), nullable=True),
        sa.UniqueConstraint("tenant_id", "external_id", name="uq_assets_external_id"),
    )
    op.create_table(
        "installed_components", *snapshot_columns(),
        sa.Column("component_id", sa.Uuid(), primary_key=True),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id", "asset_id"], ["assets.tenant_id", "assets.asset_id"]),
        sa.UniqueConstraint("tenant_id", "asset_id", "position", name="uq_component_position"),
    )
    op.create_table(
        "evidence", *snapshot_columns(),
        sa.Column("evidence_id", sa.Uuid(), primary_key=True),
        sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "vulnerability_cases", *snapshot_columns(),
        sa.Column("case_id", sa.Uuid(), primary_key=True),
        sa.Column("vulnerability_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "vulnerability_id"], ["vulnerabilities.tenant_id", "vulnerabilities.vulnerability_id"],
        ),
        sa.ForeignKeyConstraint(["tenant_id", "asset_id"], ["assets.tenant_id", "assets.asset_id"]),
        sa.UniqueConstraint("tenant_id", "vulnerability_id", "asset_id", name="uq_case_pair"),
    )
    op.create_table(
        "case_events", *snapshot_columns(),
        sa.Column("event_id", sa.Uuid(), primary_key=True),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id", "case_id"], ["vulnerability_cases.tenant_id", "vulnerability_cases.case_id"]),
        sa.UniqueConstraint("tenant_id", "case_id", "sequence", name="uq_case_event_sequence"),
    )
    for table in TABLES:
        # Table names are static migration constants, never external identifiers.
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        predicate = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid"
        op.execute(f'CREATE POLICY tenant_isolation ON "{table}" USING ({predicate}) WITH CHECK ({predicate})')
        op.execute(f'GRANT SELECT, INSERT ON "{table}" TO vulnops_app')
    op.execute('GRANT UPDATE ON vulnerability_cases TO vulnops_app')


def downgrade():
    for table in reversed(TABLES):
        op.drop_table(table)
