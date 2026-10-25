# ADR-007: PostgreSQL snapshots and append-oriented audit history

- Status: accepted
- Date: 25 October 2026
- Builds on: ADR-001 through ADR-006 and [system invariants](../invariants.md)

## Context and decision

Authoritative case state must outlive application processes. Adopt PostgreSQL 16,
SQLAlchemy 2, psycopg 3, and Alembic now, implementing the persistence boundary
anticipated by ADR-001 and ADR-006. Docker Compose supplies a local database with
a named volume, loopback-only port, health check, and separate administrative and
restricted application roles. SQLite, process memory, and JSON files are not
alternative authoritative stores.

PostgreSQL adds a running service, credentials, migrations, and eventual backup
operations. We accept that cost immediately for transactions, row locks, uniqueness,
foreign keys, and row-level security rather than migrating a prototype store later.
Local Compose credentials are development examples, not deployment credentials.

## Separate persistence and domain models

SQLAlchemy records remain in `persistence/`. Repositories accept and return the
existing validated Pydantic objects; no domain or workflow module imports ORM types.
This prevents database sessions, lazy loading, and persistence details from becoming
business rules. Inputs are serialised and revalidated at the adapter boundary,
including mutable nested source observations.

Six tables persist vulnerabilities, assets, installed components, cases, evidence,
and case events. Relational UUIDs and selected lookup columns provide keys, joins,
ordering, and concurrency checks. JSONB preserves the complete validated domain
snapshot without prematurely normalising every source observation. Components are
separate rows, ordered within an asset; they are not duplicated inside the asset's
stored payload. Composite foreign keys bind cases/components/events to the correct
tenant's related records. Evidence UUIDs inside snapshots are resolved explicitly
by repositories, including nested applicability, scoring, and component references.

We accept reduced SQL-level field validation and fewer reporting indexes in return
for a small, source-independent schema. JSONB is transactional database storage,
not a flat-file source of truth. Domain schema changes still require explicit data
migration or compatible snapshot readers; upstream `source_schema_version` is not
a persistence schema-version mechanism. More normalised observation tables and
query indexes should follow measured matching/reporting requirements.

## Tenant isolation

The inherited parent AGENTS.md requires tenant filters, transaction-local tenant
context, RLS migrations, and cross-tenant leakage tests. All six tables therefore
have tenant UUIDs, tenant-scoped keys, enabled and forced RLS, and a policy checking
`app.current_tenant_id`. Missing context fails closed. `tenant_session` sets this
value using transaction-local `set_config`; repository queries also filter by
tenant. These security requirements remain applicable despite the explicitly
selected Python stack replacing the parent's generic web stack in ADR-001.

The application role has no superuser or RLS-bypass privileges and does not own the
tables. It can select/insert snapshots and update current cases, but cannot normally
update/delete events or delete source records. Alembic runs with a separate owner
role. Tenant identity must eventually come from authenticated application context,
not request/model content. RLS protects against missing query filters, not against
compromised credentials that can choose arbitrary application tenant context.

## Practical idempotency

Save operations create or exactly replay source snapshots. CVE IDs and namespaced
asset external IDs additionally deduplicate within a tenant, returning the existing
canonical UUID when a new input UUID represents identical content. Without a CVE
or external ID, the caller must preserve its internal UUID. Component/evidence IDs
must remain stable across fixture replay; no universal identity inference is added.
Callers must use the returned canonical IDs for subsequent references.

Different content for an existing identity raises RepositoryConflict instead of
silently overwriting claims or resetting progressed cases. Changed inventory or
intelligence will need explicit reconciliation/update commands with provenance;
that policy is not invented here. One case per vulnerability/asset pair is enforced
by a tenant-scoped unique constraint. New cases must start DISCOVERED. Ordinary
`save_case` cannot replace a progressed case or skip lifecycle gates.

## Current state and audit history are related but distinct

The stored case snapshot is authoritative current state. CaseEvent rows explain
the sequence of lifecycle transitions, with immutable domain events retaining
their original from/to states, actor, reason, evidence, timestamp, and correlation
ID. Later case changes do not rewrite earlier events. Per-case sequence numbers,
backed by a unique index, order history independently of timestamp ties.

The repository transition operation locks the current case row, validates the
expected state and existing deterministic policy, compares state/revision in the
update, and inserts its event in the same transaction. Nested transaction savepoints
roll back both operations if event insertion fails even when a caller catches the
error. The outer tenant unit of work commits or rolls back the full transaction.
Concurrent stale workers cannot both commit. This realises ADR-006's required
atomic state/audit boundary without coupling the domain to SQLAlchemy.

`append_case_event` is not a route around transition policy: a new supplied event
must apply a legal transition to the locked stored case and is persisted together
with that replacement. Replaying the same event ID and content is a no-op, even
after later transitions. Reusing an event ID with altered content is rejected.
The application repository exposes history reads and append, with no ordinary
CaseEvent update/delete operations. Missing or cross-tenant evidence prevents the
state/event write. Evidence suitability, authenticated actor authority, scoped
approval validity, and independent verification still require future application
services; database presence is not proof of a security conclusion.

## Why strict database-level immutability is deferred

Append semantics are enforced by repository APIs and restricted runtime grants.
This is not a tamper-proof ledger: owners and administrators can still alter SQL
rows, schema, policies, or backups. We do not add immutable-table triggers, signed
event chains, independent WORM storage, or ledger infrastructure on Day 1. Migration,
correction, retention, and recovery requirements are not yet established, and a
trigger alone would not defend against a database owner.

Audit events also do not contain every source snapshot or field change needed to
rebuild the entire system. We are not implementing event sourcing. Current snapshots
and explanatory lifecycle history remain separate responsibilities.

## Alternatives, validation, and revisit conditions

Reject SQLite/JSON as the V1 store, leaking ORM objects into domain logic, blind
upserts of cases, events appended after an independent commit, and unrestricted
runtime audit mutation. Accept PostgreSQL operations, duplicated relational lookup
fields, JSONB schema evolution, and explicit reconciliation work.

Integration tests use PostgreSQL with the restricted role and real Alembic
migrations. They cover separate writer/reader processes, complete source/component
round trips, exact fixture replay, canonical identity reuse, historical events,
atomic failure rollback, concurrent stale requests, populated cross-tenant history,
RLS reads/writes, and composite foreign-key isolation. Tests use random tenant
identities without truncating shared tables. Tests skipped for missing database
configuration do not satisfy the Prompt 7 acceptance gate.

Revisit strict immutability or an independent ledger for regulatory retention,
hostile-administrator threats, external audit requirements, or provable tamper
detection. Consider event sourcing when full historical state reconstruction and
replay are explicit product requirements, with versioned events and projection
recovery designed first. Revisit snapshot reconciliation as sources change; audited
case-context commands when priority/plan/approval services arrive; schema
normalisation with measured query pressure; and backups/restore/TLS before a
production deployment. Preserve tenant isolation, deterministic transitions, and
atomic current-state/audit consistency through any change.
