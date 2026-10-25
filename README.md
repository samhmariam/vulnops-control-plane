# VulnOps control plane

VulnOps will connect vulnerability evidence to controlled, auditable remediation.
This repository currently contains the Python foundation, documented system
invariants, and validated Evidence, Vulnerability, ProductIdentity, and
VersionConstraint domain models, minimal Asset and InstalledComponent context,
and evidence-backed VulnerabilityCase snapshots with deterministic lifecycle policy
and audit events. PostgreSQL stores source snapshots, cases, and append-oriented
history. Offline fixture adapters now ingest synthetic vulnerability and inventory
snapshots. Live feeds, agents, and remediation execution remain future work.
Conservative product/version matching resolves individual component/product pairs
as AFFECTED, NOT_AFFECTED, or UNKNOWN with reasons and evidence references.
Application services and a CLI expose tenant-scoped records and a persisted Day 1 demo.

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

## Day 1 CLI

After starting and migrating local PostgreSQL as described below, run the persisted
walking skeleton from this checkout:

```bash
uv run --locked vulnops --help
uv run --env-file .env --locked vulnops demo
```

With DATABASE_URL already exported, the command is simply `uv run vulnops demo`.
It ingests one synthetic vulnerability and six lab assets, then creates four
relevant cases with supporting Evidence and twelve persisted lifecycle events:
web-01/dev-01 AFFECTED, web-02 NOT_AFFECTED, and legacy-01 UNKNOWN →
MANUAL_INVESTIGATION. An explicit complete-inventory claim is required for the
negative asset conclusion. The command attempts AFFECTED_CONFIRMED → APPROVED and
requires the state-transition policy to block it without changing state/history.
Only after commit and readback does it print `DAY-1 ACCEPTANCE: PASS`.

The default dedicated demo tenant is `d383a693-f08c-504b-bf7e-d7008885b119`.
Exact repeats reuse cases, evidence, and events. Changed fixtures or independently
progressed demo cases fail instead of being reset. All writes share one tenant
transaction; failures never print PASS. The demo emits JSON followed by the blocked
edge and acceptance lines. For a database-free preview of all five fixtures, run
`uv run python lab/demo.py`; that preview does not claim Day 1 acceptance.
See [ADR-011](docs/decisions/ADR-011-persisted-day1-walking-skeleton.md).

Outside this checkout, supply
`vulnops demo --lab-dir /path/to/vulnops-control-plane/lab`; fixtures are not shipped
in the production wheel.

To inspect existing database records, configure the runtime `DATABASE_URL` and
an explicit tenant UUID. After starting and migrating PostgreSQL as described below:

```bash
export VULNOPS_TENANT_ID='<your-tenant-uuid>'
uv run --env-file .env --locked vulnops vulnerability show CVE-2099-900001
uv run --env-file .env --locked vulnops asset list --limit 100 --offset 0
uv run --env-file .env --locked vulnops asset show '<asset-uuid>'
uv run --env-file .env --locked vulnops case list
uv run --env-file .env --locked vulnops case show '<case-uuid>'
uv run --env-file .env --locked vulnops case history '<case-uuid>'
```

Alternatively place `--tenant-id <uuid>` before the resource command. Asset and case
IDs are internal UUIDs returned in JSON; vulnerability lookup uses a CVE identifier.
The six inspection commands are read-only and expose evidence IDs. Lists default to
100 records, with a maximum limit of 1000; request additional pages using offset.
History retains event sequence order. A fresh database returns empty lists until
records are saved through an explicit tenant-scoped integration or the persisted
demo. To inspect the default demo, use its tenant UUID above. JSON preserves
UNKNOWN/null and escapes untrusted terminal controls.

Exit codes are 0 for success, 1 for database/source failure, 2 for invalid input or
configuration, and 3 for a record not found in the selected tenant. Tenant selection
is for trusted local operators with runtime database access; it is not a login or
membership check. A remote/multi-user interface requires authenticated tenant
authority. See [ADR-010](docs/decisions/ADR-010-cli-before-operator-console.md).

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

The full suite requires both `VULNOPS_TEST_*` database URLs. Integration-only tests
skip without them, while the Day 1 acceptance suite fails missing configuration;
skipped database checks cannot establish readiness. Use a dedicated local/test
database, never production.
Tests migrate the schema and create synthetic rows under random tenant IDs.
They do not truncate tables or delete database volumes. `docker compose stop`
stops the database while retaining its data.

Run the three disjoint regression groups separately, or use the full-suite command
above. Acceptance scenarios also carry the integration marker because they require
real PostgreSQL:

```bash
uv run --locked pytest -m 'not integration and not acceptance'
uv run --env-file .env --locked pytest -m 'integration and not acceptance'
uv run --env-file .env --locked pytest tests/acceptance/test_day01.py
```

The [Day 1 acceptance report](docs/day01-acceptance-report.md) records the eight
capability scenarios, measured results, limitations, and conditions for Day 2 work.

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
- `src/vulnops/sources/`: canonical source protocol and offline fixture adapters.
- `src/vulnops/application/`: inspection and demo use cases, with infrastructure composition.
- `src/vulnops/cli.py`: argument parsing, command dispatch, and JSON presentation.
- `lab/`: six synthetic assets, five vulnerability fixtures, and inert containers;
  see the [lab guide](lab/README.md). Excluded from the production package.
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
The [fixture adapter design](docs/decisions/ADR-009-fixture-first-source-adapters.md)
defines the offline lab, provenance, replay, and future live-source boundary.

## Implementation workflow

Execute prompts sequentially: inspect current code, ADRs and invariants; implement;
test; explain architectural choices; pass the acceptance gate; commit; then proceed
to the next supplied prompt. Fix a failed gate before continuing. A material change
to an accepted decision requires a new ADR explaining why it supersedes that decision.
