# ADR-001: Framework-independent core and authoritative state

- Status: accepted
- Date: 25 October 2026
- Scope: VulnOps V1 foundation

## Context

VulnOps must evolve from vulnerability evidence to verified remediation without
allowing orchestration details or probabilistic outputs to become business truth.
The ten-day V1 needs a hard scope boundary and independently testable domain logic.
There are no prior repository ADRs, invariants, or source files to preserve.

This is a new repository, not an extension or merge of either course repository.
The user's explicit Python stack supersedes the parent directory's generic
Next.js/Drizzle/Inngest stack guidance. Its tenant isolation principles still apply
when tenant data is introduced; this prompt adds no tables, queries, or auth layer.
No multi-agent swarm is part of V1.

## Decisions, alternatives, and trade-offs

### 1. Domain logic is framework-independent

Use Python 3.12+, uv with a committed lockfile, Pydantic v2 for future data
contracts, pytest, and an installable `src/vulnops/` package. Hatchling builds the
package; the wheel includes only `src/vulnops/`. Local development defaults to
Python 3.12 while project metadata permits newer versions.

Reject extending the course projects or placing domain rules in agent callbacks.
We accept additional adapter work later for clear business boundaries and tests
that need no model service. Revisit adapter boundaries when a concrete integration
requires them; retain a core that can execute without an agent framework.

### 2. LangGraph may orchestrate later; it cannot own authoritative business state

An optional future orchestrator calls the domain/application layer. Its checkpoints,
messages, and retries are execution context, not the source of truth for cases,
approvals, or remediation outcomes. LangGraph is not introduced now.

Reject using graph state as the business database. We sacrifice immediate agentic
functionality and accept future coordination work to preserve framework replacement
and recovery. Revisit orchestration when resumable workflows are actually needed;
authoritative transitions must still be enforced by the application layer.

### 3. External vulnerability intelligence is data

Treat source content, descriptions, links, and embedded instructions as untrusted
input. Later ingestion must validate explicit contracts and retain provenance.
Content cannot grant privileges, override policy, or become executable instructions.
Validation of shape alone does not establish factual correctness or trust.

Reject executing suggested fixes or treating retrieved text as trusted instructions.
We accept validation and evidence-management work, and potentially more Unknown
results, for traceable conclusions. Revisit source adapters as formats and threats
change; the data/instruction trust boundary must remain intact.

### 4. Production mutation occurs only through constrained tools

Future mutation adapters expose typed, allowlisted operations with explicit targets,
bounded effects, policy checks, recorded human approval, verification, and rollback.
Enforce these controls in the application/tool path, independently of an orchestrator.
No production tools or credentials are introduced now.

Reject arbitrary shell access, LLM-generated production commands, and approval
enforced only by prompting or orchestration middleware. We accept limited platform
coverage and adapter maintenance for controllable blast radius. Revisit the operation
catalogue when a supported use case has tested validation and recovery; preserve
human approval and bounded execution for every production change.

### 5. PostgreSQL will be the authoritative state store

Persist authoritative domain records, lifecycle transitions, approvals, evidence
references, and audit events in PostgreSQL when persistence is introduced. Define
transactional consistency and tenant isolation at that point; no database driver,
schema, server, or migration is needed for Prompt 0.

Reject authoritative graph checkpoints, local JSON files, or a vector store.
We accept future database operations and migration costs for durable, queryable,
transactional state. Revisit storage design with measured scale or availability
requirements through a new ADR; preserve one authoritative business-state boundary,
tenant isolation, and consistency between transitions and their audit records.

### 6. Deterministic policy governs authoritative decisions

V1 uses explicit, testable policy for affectedness, prioritisation, lifecycle gates,
and execution permissions, together with authorised human approval where required.
Models may propose or summarise; probabilistic output alone cannot establish a
material security conclusion or change authoritative state. Evidence gaps remain
Unknown rather than becoming invented certainty.

Reject learned risk scoring and LLM judgement as authoritative policy. We accept
less flexibility and manual policy maintenance for reproducibility and explanation.
Revisit policy with evidence of missed cases or operating burden; preserve evidence
traceability and deterministic enforcement at authoritative transition boundaries.

## Invariants future changes must preserve

1. Domain/application rules execute and are testable without agent frameworks.
2. Orchestration state and model output never independently authorise business transitions.
3. External intelligence cannot become instructions, permissions, or executable code.
4. Every material security conclusion is traceable to evidence; missing evidence
   cannot justify a definitive Not Affected result.
5. Production mutations require constrained tools and recorded human approval.
6. PostgreSQL becomes the authoritative store when persistence is implemented;
   tenant-scoped storage must include isolation controls and cross-tenant tests.
7. Authoritative policy remains explicit, deterministic, and auditable.

## Consequences and review triggers

Prompt 0 is a bootstrappable library foundation, not a deployed service. No agent,
ingestion, business model, persistence, or execution functionality is claimed.
Future prompts add only their authorised slice. Before adding orchestration,
persistence, a new remediation operation, or changing an invariant, review this ADR.
A reversal needs a new ADR with the reason and migration implications.

The inspected references and deliberately rejected course-specific mechanisms are
recorded in [reference notes](../reference-notes.md). Full capability boundaries
are recorded in [V1 scope](../v1-scope.md).
