# Day 1 acceptance report

Date: 25 October 2026

Scope: Prompts 0–12, through the persisted fixture-to-case walking skeleton.

Result: PASS for the Day 1 foundation and controlled progression to Day 2 source
adapter work. This is not production deployment or remediation approval.

## Test results

Validation used Python 3.12.3, pytest 9.1.1, real local PostgreSQL 16, the existing
Alembic migration, and the restricted runtime role (neither superuser nor RLS
bypass). The suite applies transaction-local tenant context and uses random tenant
IDs; it does not truncate tables, reset histories, or delete database volumes.
No external vulnerability APIs, model services, or production tools are called.

| Group | Command | Result |
| --- | --- | --- |
| Unit / database-free behavior | `uv run --locked pytest -m 'not integration and not acceptance'` | 337 passed |
| PostgreSQL integration | `uv run --env-file .env.example --locked pytest -m 'integration and not acceptance'` | 35 passed |
| Day 1 acceptance | `uv run --env-file .env.example --locked pytest tests/acceptance/test_day01.py -ra` | 8 passed |
| Missing database configuration probe | Invoke acceptance with both test URLs removed from the child environment | Correctly rejected; no skipped acceptance or success |

The three groups are disjoint: **380 tests passed in total, with no failures or
skipped selected tests**. Deselected tests in the filtered groups are executed in
the other groups. `.env.example` supplies public local Docker defaults only; use
an ignored `.env` with suitable test URLs when your local configuration differs.

The acceptance suite is [tests/acceptance/test_day01.py](../tests/acceptance/test_day01.py).
It checks observable domain/application behavior and committed PostgreSQL state.
It does not inspect policy mappings, private helpers, ORM class layouts, index
definitions, or agent execution structure. Fixed-name SQL counts check only durable
record cardinality for replay; evidence and cases are otherwise read through public
repository/application interfaces.

| Scenario | Verified behavior |
| --- | --- |
| 1. Confirmed affected | Matching structured package identity and version 1.4.0 inside the introduced/fixed range produce AFFECTED, a stored case, and resolvable CVE/inventory evidence. |
| 2. Confirmed not affected | Version 2.0.0 at the exclusive fixed boundary produces NOT_AFFECTED, supported by the explicit asset inventory completeness observation. |
| 3. Insufficient evidence | Missing installed versions stay UNKNOWN; the stored case and history enter MANUAL_INVESTIGATION without a NOT_AFFECTED transition. |
| 4. Illegal transition | The application attempts AFFECTED_CONFIRMED → APPROVED, records the denial as SYSTEM Evidence, and leaves the authoritative case and transition history unchanged. |
| 5. Missing provenance | Empty provenance fails domain validation; unresolved assessment evidence is rejected; fabricated and foreign-tenant evidence IDs cannot authorize stored affected cases. |
| 6. Persistence | A new isolated Python application process creates fresh services and reads the same cases and complete histories from PostgreSQL. |
| 7. Idempotency | Reprocessing identical fixtures preserves record counts and identities across vulnerabilities, assets, components, cases, evidence, and case events. |
| 8. One CVE, multiple outcomes | One canonical vulnerability yields AFFECTED, NOT_AFFECTED, and UNKNOWN on distinct assets, with independent case identities. |

Existing integration tests additionally verify atomic rollback after audit-write
failure, suppression of PASS when an illegal transition is accepted or post-commit
readback fails, repeat CLI execution across processes, concurrent stale-transition
rejection, append-oriented historical state, and tenant isolation/RLS enforcement.
Unit tests cover strict schemas, timezone awareness, identifier and version limits,
uncertainty, untrusted text preservation, lifecycle gates, CLI failures, and invariant
document identifiers. Documentation-presence tests alone do not prove the safety
model; production mutation invariants remain future implementation obligations.

## Architectural basis

The harness follows [system invariants](invariants.md), the existing domain ADRs,
[ADR-007](decisions/ADR-007-postgres-and-append-audit.md), and
[ADR-011](decisions/ADR-011-persisted-day1-walking-skeleton.md).
No earlier architectural decision is reversed, and no runtime behavior is changed.
PostgreSQL setup is shared between integration and acceptance suites so both use
the same migration, restricted role, and tenant transaction contract.

The alternative of asserting internal mappings or replacing storage with mocks
was rejected: such tests could pass while the vertical slice or durability failed.
The accepted costs are a running PostgreSQL dependency, slower database tests, and
maintaining deliberately small synthetic inputs. Acceptance fails if its required
database configuration is absent instead of treating skipped scenarios as readiness.

## Known limitations

* Fixtures are synthetic source-schema subsets. The walking skeleton selects one
  vulnerability; the offline lab contains five records and six logical assets.
  It does not establish real CVE assignment, source accuracy, or ecosystem coverage.
* Matching supports the documented restricted identifier and version semantics.
  Unsupported, conflicting, or incomplete comparisons remain UNKNOWN. An explicit
  complete-inventory claim is necessary for an asset-level negative conclusion;
  the lab claim does not prove real-world completeness or freshness.
* The default demo uses stable logical fixture timestamps and exact replay. Changed
  intelligence, independently progressed cases, and conflicting concurrent demo
  invocations require explicit reconciliation rather than destructive reseeding.
* Persistence tests restart application processes, not the PostgreSQL server or
  host. They do not establish disaster recovery, backup restoration, or high
  availability.
* Tenant selection is a trusted local operator facility, not authentication or
  membership enforcement. Production approval, constrained execution, verification,
  rollback, and an operator console are not implemented.
* Audit events are append-oriented under runtime permissions, not a tamper-proof
  ledger. The demo application probe retains its denied-attempt observation; a
  generic denied-operation audit service is not yet implemented.
* Real vulnerable services are not deployed. Optional lab containers are inert
  stand-ins; this gate does not validate actual patching or remediation efficacy.

## Technical debt

* Typed finding persistence remains deferred; case event reasons retain serialized
  assessment details and evidence references.
* Production raw-payload storage, retention, correction/reconciliation, refresh
  history, and cross-source deduplication need explicit policies. A hash identifies
  bytes; it does not establish authenticity or reconstruct missing source material.
* Approval/verification records are references with structural lifecycle guards;
  authenticated authority, scope/expiry checks, and independent verification need
  future application services.
* JSON output versioning, richer evidence inspection, scalable pagination, replay
  coordination, and historical schema migration remain open as usage grows.
* Tests add synthetic rows under isolated tenants without cleanup. Use a dedicated
  test database and define retention before sustained CI use. The harness adds
  no production infrastructure or runtime dependency.

## Open questions

1. Which supported inventory collectors can attest scoped completeness, and what
   freshness interval is acceptable for negative determinations?
2. How should changed advisories, contradictory sources, and reopened cases be
   reconciled while preserving earlier evidence and decisions?
3. What raw payload retention and sensitive-data access policy should live sources use?
4. Which additional ecosystems/version semantics are justified by Day 2 fixtures?
5. When should approval authority, generic denied-operation logging, typed findings,
   and independent verification become required application boundaries?

## Day 2 readiness

Ready to implement explicitly scoped live-source adapters behind VulnerabilitySource
while preserving canonical models, provenance, UNKNOWN, deterministic policy,
tenant isolation, and state/audit atomicity. Before a source becomes authoritative,
define its schema validation, retrieval time, freshness, timeouts/rate limits,
credentials, raw-material retention, and update/reconciliation semantics.

Keep these eight scenarios in the regression suite throughout Days 2–10. New source
formats should add fixtures and tests without weakening them. Revisit the harness
when a supported ecosystem or a deliberate ADR changes the external capability
contract; do not rewrite expected outcomes merely to accommodate a failing gate.
