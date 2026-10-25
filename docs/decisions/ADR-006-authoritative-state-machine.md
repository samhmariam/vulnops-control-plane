# ADR-006: Authoritative lifecycle policy outside orchestration

- Status: accepted
- Date: 25 October 2026
- Builds on: ADR-001 through ADR-005 and [system invariants](../invariants.md)
- Supersedes: ADR-005's temporary NEW-only lifecycle vocabulary

## Context and decision

Agents and workflow engines may request lifecycle changes but must not define
business truth. Introduce a deterministic transition service independent of
LangGraph or any other agent framework. `workflow/states.py` defines the shared
CaseState enum; `workflow/transitions.py` contains the sole authoritative
ALLOWED_TRANSITIONS mapping. The mapping is read-only and its successor sets are
immutable. Unknown, same-state, backward, and unlisted edges are denied.

Cases now default to DISCOVERED. This explicitly replaces Prompt 5's placeholder
NEW and extends its planned lifecycle boundary; immutable case snapshots and the
vulnerability/asset granularity remain unchanged. No persisted store exists yet.
Any external snapshots using NEW require an explicit boundary migration to
DISCOVERED, not a silent acceptance of legacy labels.

## Why transitions are separate from orchestration

An orchestrator can retry, resume, or be replaced without altering legal lifecycle
edges. The application calls `transition_case` with a case snapshot, its expected
current state, the requested new state, actor, reason, and evidence UUIDs. Optional
correlation ID and event time support linked operations and deterministic replay;
otherwise the service generates a correlation UUID and uses the UTC clock.

On success the service returns a TransitionResult containing a newly validated
case snapshot and its immutable CaseEvent. It preserves case identity, original
creation time, assessment, and existing evidence; appends new evidence without
duplicates; and uses the same timestamp for the update and event. It never mutates
the input, publishes events, invokes tools, or writes a database.

## Allowed progression and why states cannot be skipped

The primary path is:

```text
DISCOVERED -> ENRICHED -> ASSET_MATCHED -> AFFECTED_CONFIRMED
  -> PRIORITISED -> PATCH_PLAN_CREATED -> SANDBOX_TESTED
  -> AWAITING_APPROVAL -> APPROVED -> CANARY_DEPLOYED
  -> CANARY_VERIFIED -> ROLLOUT -> RESCANNED -> VERIFIED_FIXED
```

Each edge represents a distinct gate. A plan cannot jump to verified closure;
waiting for approval cannot jump to rollout. Explicit evidence and actor
attribution remain required even if the caller believes an intermediate step is
redundant. This rigidity prevents a model or retry handler from inventing shortcuts.

Alternate paths are deliberately bounded:

- Active primary states can enter MANUAL_INVESTIGATION.
- ASSET_MATCHED can enter NOT_AFFECTED with an explicit corresponding assessment.
- AFFECTED_CONFIRMED or PRIORITISED can enter MITIGATED or DEFERRED.
- AWAITING_APPROVAL can enter APPROVAL_REJECTED or DEFERRED.
- Planning or production execution can enter PATCH_FAILED at the explicit edges
  listed in the mapping; PATCH_FAILED can enter ROLLED_BACK or MANUAL_INVESTIGATION.

VERIFIED_FIXED, NOT_AFFECTED, MITIGATED, DEFERRED, APPROVAL_REJECTED, ROLLED_BACK,
and MANUAL_INVESTIGATION have no automatic successors in V1. PATCH_FAILED is an
alternate state with controlled recovery. Deferral, mitigation, rejection, rollback,
and investigation do not mean verified remediation. Reopening and retry require
later explicit policy rather than an arbitrary return to an earlier state.

## Deterministic prerequisites and provenance

Every transition needs a typed Actor with nonblank ID, nonblank reason, and
nonempty UUID event evidence. The audit event records event and case IDs, type,
from/to states, actor type/ID, reason, evidence, correlation ID, and aware timestamp.
Unknown cases may exist without evidence under ADR-005, but moving them requires
an attributable event, including entry to manual investigation.

Remediation progression requires an existing AFFECTED assessment. NOT_AFFECTED
requires that explicit assessment; the transition service never infers definitive
affectedness from UNKNOWN. PRIORITISED needs an externally supplied priority, and
PATCH_PLAN_CREATED needs a plan reference. No prioritisation or matching algorithm
is added here.

Approval decisions require a HUMAN actor; APPROVED also needs an approval reference.
Production progression, including a recorded rollback, needs approval and plan
references. Canary verification and verified closure need a verification reference
and a HUMAN or SYSTEM verifier; an AGENT cannot attest either outcome. The graph
also requires rescanning before VERIFIED_FIXED. Affectedness retains its original
assessment; recording a verified fix is not rewriting the historical assessment.

Reference presence is necessary, not sufficient. This in-memory service cannot
authenticate an actor, resolve evidence, validate an approval's scope or expiry,
or prove that a verification is independent, current, and successful. The future
application must resolve identity from authenticated context, enforce permissions,
and validate these records against the exact case, plan, and execution. User or
model-supplied HUMAN labels and arbitrary UUIDs are not authorisation. Until those
boundaries and constrained tools exist, this service records no real production
action and is not a production execution capability.

## Why expected-state checking matters

A caller may work from a stale view while another operator or worker advances a
case. The service rejects a request when its expected state differs from the
supplied case's actual state, before returning an event or replacement snapshot.
This catches stale requests when evaluated against the current snapshot.

An in-memory comparison is not a database concurrency guarantee. Two callers can
still hold the same old snapshot and independently propose successors. When
PostgreSQL persistence arrives, load/check the current record and atomically
compare-and-set its expected state (and a revision if reopening permits ABA),
update it, and insert its event in one transaction. Never persist a replacement
without its event or an event for a failed update. Separate publication would
require a transactional outbox when external consumers exist; none is added now.

## Why agents cannot own lifecycle state

Case snapshots, transition results, and events are immutable. Agent output may
request an allowed step but cannot bypass its graph, human approval, or verification
prerequisites. Constructors deserialize snapshots; they are not authoritative write
APIs. Pydantic trusted bypass methods remain unsuitable for authoritative updates
under ADR-005. The future repository must accept only policy-validated state/event
updates through the application boundary, not raw agent or graph state.

## Alternatives, trade-offs, and revisit conditions

Reject free-form state assignments, framework-defined transitions, skipping gates,
and separate uncoordinated state/event writes. Accept less workflow flexibility,
explicit prerequisite preparation, and future transactional integration for an
auditable, replaceable orchestration boundary. No database, agent framework,
approval store, verification engine, or production tool is introduced.

Revisit recovery and reopening when concrete workflows require them; verification
and approval guards when their records exist; and expected-state/revision checking
when persistence arrives. Preserve deterministic edge enforcement, human production
approval, independently verified closure, and atomic state/audit consistency. Any
material policy reversal needs a new ADR and tests for the changed paths.
