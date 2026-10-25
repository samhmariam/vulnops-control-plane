# ADR-011: Persisted Day 1 walking skeleton and conservative asset assessment

Status: Accepted

Date: 2026-10-25

Supersedes: ADR-010's offline-only `vulnops demo` behavior. Refines ADR-008's
deferred asset aggregation for the explicit completeness contract below.
ADRs 001–009 and the read-only inspection commands remain in force.

## Context and decision

Passing component tests does not prove that fixtures, canonical models, evidence,
matching, cases, lifecycle policy, and PostgreSQL work together. Prompt 11 explicitly
requires `uv run vulnops demo` to persist a complete vertical slice and prove its
outcomes before reporting success. The CLI remains a thin presentation adapter.

The command selects one synthetic vulnerability, CVE-2099-900001, through the fixture
source boundary. It persists its evidence and canonical record, loads all six lab
assets, evaluates every installed component against the affected products, and
creates cases only for candidate assets. The current snapshot yields web-01,
web-02, dev-01, and legacy-01; unrelated structured product identities do not create
spurious cases. Source schemas, source text, and CVSS/KEV/EPSS observations never
gain instruction or approval authority.

## Asset-level conclusion and evidence

AssetAssessment is a finding separate from raw source Evidence and the operational
case. It retains each component/product comparison, method, reason, evidence IDs,
and the completeness basis. All referenced evidence must resolve before assessment.

The synthetic inventory now explicitly claims `component_inventory_complete: true`
for each asset: every installed component in this fixture snapshot is listed.
This says nothing about whether a component's version is known. The adapter retains
the original claim and hashes its file bytes, and exposes the literal boolean in
inventory Evidence metadata. Existing inventory sources without the claim do not
gain completeness implicitly. Every referenced, asset-scoped inventory observation
must explicitly claim completeness for a negative conclusion; missing or conflicting
claims prevent it.

Aggregation is deliberately conservative:

* An empty comparison set or any UNKNOWN comparison yields UNKNOWN.
* Otherwise, a supported positive comparison yields AFFECTED.
* Otherwise, NOT_AFFECTED requires an explicit complete-inventory claim and every
  component/product comparison to exclude affectedness.
* Without completeness, exclusions still yield UNKNOWN.

This accepts additional manual investigation, including when another comparison
is positive, instead of resolving ambiguity by confidence or voting. It is a narrow
snapshot contract, not a universal inventory completeness, freshness, authenticity,
or conflict-resolution system. Real collectors must establish evidence suitability
and scoped completeness before using this contract. Completeness is a source claim,
not proven truth. This demo is synthetic and performs no enterprise mutations.

Each relevant case starts DISCOVERED with its computed assessment and evidence.
It moves through ENRICHED and ASSET_MATCHED, then AFFECTED_CONFIRMED, NOT_AFFECTED,
or MANUAL_INVESTIGATION. Creation is the initial snapshot, not a fabricated state
transition. Every subsequent change has a CaseEvent. The ASSET_MATCHED event reason
retains serialized assessment details and references; case status, source snapshots,
and complete audit history persist without a new table or opaque orchestrator state.

## Transactions, replay, and the acceptance gate

The default demo tenant is `d383a693-f08c-504b-bf7e-d7008885b119`, dedicated to this
lab. Operators may explicitly select a tenant using the existing option/environment
boundary. PostgreSQL uses the configured runtime DATABASE_URL, existing migrations,
tenant filters, and forced RLS. The command never starts infrastructure, applies
migrations, resets tables, or deletes earlier history implicitly.

Case and event UUIDs, reasons, correlation IDs, and logical timestamps are stable.
Times follow the fixture observation clock plus deterministic step offsets; they
represent replayed synthetic observations, not wall-clock production activity.
Exact reruns reuse source snapshots and append_case_event's exact-replay semantics.
An existing case/history that differs from the expected completed demo fails; it
cannot be reset, silently overwritten, or advanced twice. Concurrent conflicting
invocations may fail safely; no automatic reconciliation is invented.

All source/evidence/case/event writes share one tenant transaction. Before commit,
the service attempts AFFECTED_CONFIRMED → APPROVED through the actual repository
transition service. Acceptance requires the specific prohibited-edge denial, not
an unrelated missing approval, stale-state, actor, or database failure. It checks
that state and history remain unchanged. A stable SYSTEM Evidence observation records
the denied attempt; no successful-transition CaseEvent is fabricated for it.

The service checks exact round trips before commit and reloads everything in a
separate transaction after commit. Required scenarios are explicitly checked:
web-01 AFFECTED/AFFECTED_CONFIRMED, web-02 NOT_AFFECTED/NOT_AFFECTED, and legacy-01
UNKNOWN/MANUAL_INVESTIGATION, with complete legal histories and supporting evidence.
Only then does the CLI display the report, blocked edge, and final acceptance line.
Assertions are not used for runtime gates, so Python optimization cannot disable
them. Write, validation, policy, commit, or readback failures never print PASS.
If post-commit verification fails, committed records remain available for inspection
and repeat execution; the command reports failure instead of claiming rollback.

## Alternatives and trade-offs

Reject an in-memory or mocked success demonstration, changing the existing lifecycle
graph to accommodate the demo, unrecorded state writes, and returning NOT_AFFECTED
from an excluded component without completeness. Also reject deleting/reseeding
records on every run. Accept an explicit synthetic completeness contract, verbose
audit reasons, a fixed logical clock, one running PostgreSQL dependency, and strict
conflict failures for changed fixtures or independently progressed cases.

The earlier offline preview remains `uv run python lab/demo.py`, backed by
`application.demo.preview_demo`. It does not emit Day 1 acceptance or persist data.
Inspection commands still read existing records without mutating lifecycle state.

## Revisit conditions and invariants

Revisit completeness scope, source freshness, asset reconciliation, and conflicts
before real inventory feeds; typed finding persistence when downstream queries need
it; event schemas when long-lived histories require migration; and replay locking
if concurrent demos become a requirement. Expand beyond one fixture only with
scenario-specific tests. Production approval and remediation still need the future
authenticated authority and constrained tools; this slice adds neither.

Preserve INV-01–INV-10, especially attributable evidence, UNKNOWN, deterministic
policy outside orchestration, independent asset decisions, and atomic state/audit
consistency. The blocked shortcut is evidence of policy enforcement, not an approval.
