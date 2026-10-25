# VulnOps control plane

VulnOps will connect vulnerability evidence to controlled, auditable remediation.
This repository currently contains the Python foundation, documented system
invariants, and validated Evidence, Vulnerability, ProductIdentity, and
VersionConstraint domain models, minimal Asset and InstalledComponent context,
and evidence-backed VulnerabilityCase snapshots with deterministic lifecycle policy
and audit events. PostgreSQL stores source snapshots, cases, and append-oriented
history. It does not yet ingest vulnerabilities, run agents, or remediate assets.
Conservative product/version matching resolves individual component/product pairs
as AFFECTED, NOT_AFFECTED, or UNKNOWN with reasons and evidence references.

Use Python 3.12+ and uv. The default local interpreter is Python 3.12.

```bash
uv sync --locked
uv run --locked python -c "import vulnops; print('VulnOps imports successfully')"
uv run --locked pytest -m 'not integration'
uv build
```

Pydantic v2 validates domain contracts; SQLAlchemy 2, Alembic, and psycopg provide
PostgreSQL persistence; packageurl-python parses structured Package URLs.
pytest is a development dependency. Commit `uv.lock` to
keep installations reproducible; update it deliberately when changing dependencies.

## Local PostgreSQL and integration tests

Docker Compose runs PostgreSQL 16 with a persistent named volume, listening on
`127.0.0.1:55432`. The example credentials are for this local database only.

```bash
cp .env.example .env
docker compose up -d --wait postgres
uv run --env-file .env --locked alembic upgrade head
uv run --env-file .env --locked alembic check
uv run --env-file .env --locked pytest
```

The full suite includes PostgreSQL integration tests when both `VULNOPS_TEST_*`
database URLs are set. Without them those tests skip; skips do not satisfy the
persistence acceptance gate. Use a dedicated local/test database, never production.
Tests migrate the schema and create synthetic rows under random tenant IDs.
They do not truncate tables or delete database volumes. `docker compose stop`
stops the database while retaining its data.

Alembic uses `VULNOPS_MIGRATION_DATABASE_URL` (owner credentials); application code
uses `DATABASE_URL` (restricted `vulnops_app` credentials). The local init script
creates that role on the first volume initialisation. Provision it separately
outside Compose. Changing environment passwords does not rotate an existing
PostgreSQL volume's role passwords.

Use `tenant_session(engine, tenant_id)` and `Repositories(session, tenant_id)` for
a transactional unit of work. Saves return canonical domain objects. Save Evidence
before the source records referencing it, then vulnerabilities/assets before cases.
Preserve fixture/component/evidence IDs for exact replay and namespace external
asset IDs by upstream system. Conflicting snapshots raise an explicit error rather
than silently merging. New cases start DISCOVERED; use the repository's
`transition_case` for an atomic state change plus audit event. `append_case_event`
also enforces transition policy and cannot insert an unauthorised state shortcut.

## Layout

- `src/vulnops/`: framework-independent domain/application package.
- `tests/`: automated behaviour and packaging tests.
- `src/vulnops/workflow/`: lifecycle states, transition policy, and audit events.
- `src/vulnops/persistence/`: PostgreSQL models, tenant transactions, and repositories.
- `src/vulnops/matching/`: conservative identity, version, and pair resolution.
- `alembic/`: reviewed schema and row-level security migrations.
- `lab/`: isolated future experiments; excluded from the production package.
- `docs/`: scope, evidence, and architecture.
- `docs/decisions/`: architectural decision records (ADRs).

Read [V1 scope](docs/v1-scope.md), [system invariants](docs/invariants.md),
[ADR-001](docs/decisions/ADR-001-core-architecture.md), and
[reference inspection notes](docs/reference-notes.md) before extending the system.
The [Evidence design](docs/decisions/ADR-002-evidence-first-domain-model.md) explains
the first domain object and the distinction between observations and conclusions.
The [canonical vulnerability design](docs/decisions/ADR-003-canonical-vulnerability-model.md)
explains product identity, descriptive version constraints, and separate source
observations without an aggregate risk score.
The [enterprise asset design](docs/decisions/ADR-004-minimal-enterprise-asset-model.md)
defines the boundary with upstream inventory and separates components from asset
exposure and business context.
The [case granularity design](docs/decisions/ADR-005-vulnerability-case-granularity.md)
defines one operational case per vulnerability/asset pair and its evidence boundary.
The [state machine design](docs/decisions/ADR-006-authoritative-state-machine.md)
defines legal transitions, prerequisites, and the future atomic persistence boundary.
The [persistence design](docs/decisions/ADR-007-postgres-and-append-audit.md) implements
that atomic boundary and documents tenant isolation, replay, and audit limitations.
The [matching design](docs/decisions/ADR-008-conservative-affected-resolution.md)
defines supported identifiers/version semantics and when a result must stay UNKNOWN.

## Implementation workflow

Execute prompts sequentially: inspect current code, ADRs and invariants; implement;
test; explain architectural choices; pass the acceptance gate; commit; then proceed
to the next supplied prompt. Fix a failed gate before continuing. A material change
to an accepted decision requires a new ADR explaining why it supersedes that decision.
