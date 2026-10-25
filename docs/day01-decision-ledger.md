# Day 1 architectural decision ledger

Date: 25 October 2026. Scope: completed Prompts 0–15; no Day 2 functionality.

This records intentional choices, not a new architecture. Reviewed ADR-001–ADR-012,
INV-01–INV-10, the complete test inventory, [security review](day01-security-review.md),
[acceptance report](day01-acceptance-report.md), and
[architecture walkthrough](day01-architecture-walkthrough.md).

Confidence describes confidence in the choice for its stated scope, not proof that
an observation is true. Reversal cost includes contracts, stored data, history, and
revalidation work: LOW is mostly a local addition/replacement; MEDIUM crosses several
consumers or requires migration; HIGH changes core identity, authority, or audit
semantics. A reconsideration trigger permits review, not silent invariant removal.

## D01 — A new standalone VulnOps repository

* **Decision:** Create vulnops-control-plane independently of the reference repositories.
* **Reason:** Own the security/domain boundary without inheriting course orchestration; [ADR-001](decisions/ADR-001-core-architecture.md).
* **Alternative rejected:** Merge or extend either Udacity reference architecture wholesale.
* **Trade-off:** Build packaging and integrations explicitly instead of reusing a complete course stack.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** MEDIUM.
* **Trigger for reconsideration:** Organisational consolidation with a concrete migration plan that preserves domain contracts and history.

## D02 — Framework-independent domain layer

* **Decision:** Domain rules are Python/Pydantic contracts independent of orchestration and ORM sessions.
* **Reason:** Rules must execute and be testable without an agent framework; ADR-001.
* **Alternative rejected:** Put business truth in graph state, callbacks, or ORM entities.
* **Trade-off:** Adapter/composition code and explicit translation between layers.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** HIGH.
* **Trigger for reconsideration:** Measured boundary friction justifies restructuring adapters; framework convenience alone does not justify transferring business authority.

## D03 — Evidence as a first-class object

* **Decision:** Independently identify attributable observations and reference them from findings/cases.
* **Reason:** Preserve provenance and disagreement across consumers; [ADR-002](decisions/ADR-002-evidence-first-domain-model.md), INV-02/03.
* **Alternative rejected:** Duplicate raw evidence inside every vulnerability, asset, or model response.
* **Trade-off:** More UUIDs, reference resolution, retention, and eventual joins.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** HIGH.
* **Trigger for reconsideration:** Demonstrated retention/volume requirements justify storage changes while preserving attribution and evidence/conclusion separation.

## D04 — Canonical vulnerability schema

* **Decision:** Adapt external records into Vulnerability and its supporting domain types.
* **Reason:** Keep downstream logic independent of feed schemas; [ADR-003](decisions/ADR-003-canonical-vulnerability-model.md).
* **Alternative rejected:** Pass source dictionaries through application logic.
* **Trade-off:** Explicit source adapters and canonical schema evolution.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** HIGH.
* **Trigger for reconsideration:** Real source semantics cannot be represented without loss; extend/version the contract rather than leaking schemas downstream.

## D05 — Structured product identifiers

* **Decision:** Retain PURL, CPE, ecosystem/package, vendor/product, and aliases; prefer supported structured matches.
* **Reason:** Human-readable names alone do not establish identity; ADR-003/008.
* **Alternative rejected:** Name-only or fuzzy similarity as authoritative equivalence.
* **Trade-off:** Parser coverage, conflict handling, and UNKNOWN results for unsupported identity scope.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** MEDIUM.
* **Trigger for reconsideration:** Supported ecosystems or reviewed alias mappings require additional explicit semantics.

## D06 — UNKNOWN is a first-class affected status

* **Decision:** Preserve AFFECTED, NOT_AFFECTED, and UNKNOWN without an automatic safe default.
* **Reason:** Missing evidence must not create false reassurance; INV-04 and ADR-008.
* **Alternative rejected:** Boolean affectedness, absent-match-means-safe, or confidence-based clearance.
* **Trade-off:** More manual investigation and uncertainty visible to operators.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** HIGH.
* **Trigger for reconsideration:** A new supported evidence source can resolve specific unknowns; it does not justify deleting the unknown outcome.

## D07 — Vulnerability × asset case granularity

* **Decision:** One current operational case per tenant/vulnerability/asset pair.
* **Reason:** Ownership, impact, exceptions, remediation, and verification differ by asset; [ADR-005](decisions/ADR-005-vulnerability-case-granularity.md), INV-10.
* **Alternative rejected:** One enterprise-wide operational object per CVE or eagerly creating the full Cartesian product.
* **Trade-off:** More records and aggregate reporting requirements.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** HIGH.
* **Trigger for reconsideration:** Separate installations require remediation subrecords or reopening policy, without collapsing independent asset decisions.

## D08 — Explicit deterministic state machine

* **Decision:** One authoritative transition mapping and validated state/event results outside orchestration.
* **Reason:** Prevent skipped approval, verification, and lifecycle gates; [ADR-006](decisions/ADR-006-authoritative-state-machine.md).
* **Alternative rejected:** Arbitrary state assignments or workflow-framework-owned legality.
* **Trade-off:** Less flexibility and explicit recovery/prerequisite design.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** HIGH.
* **Trigger for reconsideration:** Concrete reopening/recovery requirements justify new reviewed edges and behavioral tests.

## D09 — PostgreSQL is authoritative storage

* **Decision:** Use PostgreSQL, SQLAlchemy 2, and Alembic from Day 1.
* **Reason:** Durable queryable state, constraints, concurrency control, and tenant isolation; [ADR-007](decisions/ADR-007-postgres-and-append-audit.md).
* **Alternative rejected:** SQLite, flat JSON, process memory, or graph checkpoints as the V1 source of truth.
* **Trade-off:** A running server, credential separation, migrations, and future recovery operations.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** HIGH.
* **Trigger for reconsideration:** Measured availability/scale requirements justify a new storage ADR and migration preserving transactional authority.

## D10 — Append-oriented audit history alongside current snapshots

* **Decision:** Persist current cases separately from immutable domain CaseEvents; expose append/read, not normal historical update/delete APIs.
* **Reason:** Explain progression without rewriting earlier events; ADR-007, INV-08.
* **Alternative rejected:** Overwrite-only cases, immediate full event sourcing, or claiming a tamper-proof ledger.
* **Trade-off:** Some duplicated information; administrators remain able to alter storage.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** HIGH.
* **Trigger for reconsideration:** Regulatory retention, hostile-administrator threats, or full rebuild requirements justify stronger ledger/event-sourcing techniques.

## D11 — Conservative deterministic product/version matching

* **Decision:** Use explicit identity rules and a limited numeric SemVer/exact-version subset; unsupported semantics remain UNKNOWN.
* **Reason:** False negatives are particularly dangerous; [ADR-008](decisions/ADR-008-conservative-affected-resolution.md).
* **Alternative rejected:** Universal string ordering, inferred version schemes, embeddings, or LLM guesses as authority.
* **Trade-off:** Limited ecosystem coverage and more manual review.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** MEDIUM.
* **Trigger for reconsideration:** Source-specific fixtures and documented version rules justify additional comparators; probabilistic assistance remains advisory.

## D12 — Fixture-first source adapters

* **Decision:** Exercise a source protocol using synthetic OSV-like and enrichment inputs before live feeds.
* **Reason:** Separate domain failures from upstream availability/schema changes; [ADR-009](decisions/ADR-009-fixture-first-source-adapters.md).
* **Alternative rejected:** Immediate live feeds or canonical-only fixtures that bypass translation.
* **Trade-off:** Static, deliberately narrow data does not establish real-world coverage.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** LOW.
* **Trigger for reconsideration:** Day 2 source work can add live adapters with provenance, freshness, retention, and refresh policies; retain fixtures for regression.

## D13 — CLI before web UI

* **Decision:** Use an argparse console entry point and JSON output for operations.
* **Reason:** Inspect the walking skeleton without frontend/API infrastructure; [ADR-010](decisions/ADR-010-cli-before-operator-console.md).
* **Alternative rejected:** Premature web console, FastAPI service, or additional CLI framework.
* **Trade-off:** Verbose JSON, limited visual comparison, and trusted local operator configuration.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** LOW.
* **Trigger for reconsideration:** Collaboration, approval queues, or evidence drill-down require a console and authenticated tenant authority.

## D14 — No LangGraph on Day 1

* **Decision:** Defer orchestration infrastructure; domain/application operations run directly.
* **Reason:** Establish business state and policy before workflow technology; ADR-001.
* **Alternative rejected:** Introduce graph checkpoints as the initial business-state model.
* **Trade-off:** No immediate resumable agent workflow.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** LOW.
* **Trigger for reconsideration:** Concrete resumable orchestration requirements justify an adapter that still calls the authoritative application layer.

## D15 — No LLM authority on Day 1

* **Decision:** Models/probabilistic processes do not establish authoritative assessments, lifecycle state, or production permission.
* **Reason:** Decisions require evidence and deterministic validation or explicit human authority; ADR-001, INV-05/06.
* **Alternative rejected:** Let model judgment, confidence, or natural-language approval directly write business/production state.
* **Trade-off:** Manual policy/adapter work and deferred agentic convenience.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** HIGH.
* **Trigger for reconsideration:** Evaluated advisory assistance may be added; better model quality alone cannot remove validation, authority, or human production approval.

## D16 — Minimal assets and separate installed components

* **Decision:** Consume essential enterprise context without becoming a CMDB; give installations independent IDs and ownership.
* **Reason:** Connect applicability to exposure/business impact while preserving upstream responsibility; [ADR-004](decisions/ADR-004-minimal-enterprise-asset-model.md).
* **Alternative rejected:** Full CMDB replication or one product/version field per asset.
* **Trade-off:** Omitted upstream relationships and explicit inventory mapping.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** MEDIUM.
* **Trigger for reconsideration:** Actual remediation needs justify additional context or installation scope.

## D17 — CVSS, KEV, and EPSS remain separate observations

* **Decision:** Preserve severity, catalog membership, and dated exploitation forecast with independent provenance.
* **Reason:** Their meanings differ and enterprise context is still required; ADR-003.
* **Alternative rejected:** Collapse source observations into one risk score or interpret absent enrichment as a negative.
* **Trade-off:** More fields and later explicit prioritisation policy; only one KEV/EPSS snapshot slot today.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** MEDIUM.
* **Trigger for reconsideration:** Concurrent observation history or a reviewed asset-context priority policy is required; preserve original observations.

## D18 — Separate domain/ORM models with JSONB snapshots

* **Decision:** Keep ORM records in persistence; store domain payloads plus relational keys/constraints and separate component rows.
* **Reason:** Stable business contracts without prematurely normalising every observation; ADR-007.
* **Alternative rejected:** ORM objects throughout domain code or fully normalised source-specific schemas immediately.
* **Trade-off:** Serialization/revalidation, JSONB reporting limits, and explicit future schema evolution.
* **Confidence in decision:** MEDIUM.
* **Cost of reversing it:** MEDIUM.
* **Trigger for reconsideration:** Measured query pressure or schema migration needs justify normalised observation/finding tables.

## D19 — Tenant filters plus forced RLS and scoped references

* **Decision:** Enforce tenant filters, transaction-local context, forced RLS, composite keys/FKs, and restricted runtime grants.
* **Reason:** Tenant isolation is an inherited security requirement; ADR-007.
* **Alternative rejected:** Application filters alone, globally unscoped identities, or normal runtime use of owner credentials.
* **Trade-off:** PostgreSQL-specific policy, context plumbing, and cross-tenant tests; current tenant selection is not authentication.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** HIGH.
* **Trigger for reconsideration:** Authenticated deployment context or different tenancy topology requires reviewed policy migration without weakening isolation.

## D20 — Atomic case/event writes with expected-state checking

* **Decision:** Lock/reload the stored case, validate policy, compare state/revision, and write the replacement and event together.
* **Reason:** A failed audit append or stale worker must not create an unexplained state; ADR-006/007.
* **Alternative rejected:** Independent state/event commits or relying on an old in-memory snapshot.
* **Trade-off:** Row locking, savepoints, and explicit concurrency conflicts.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** HIGH.
* **Trigger for reconsideration:** Measured contention or external event publication requires a reviewed concurrency/outbox design preserving atomicity.

## D21 — Exact replay instead of silent refresh/upsert

* **Decision:** Reuse identical snapshots/events; reject different content for existing identities and progressed demo cases.
* **Reason:** Prevent duplicates, evidence replacement, and accidental workflow reset; ADR-007/011.
* **Alternative rejected:** Last-write-wins merges or destructive reseeding on every source run.
* **Trade-off:** New source versions require explicit reconciliation rather than a convenient blind save.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** MEDIUM.
* **Trigger for reconsideration:** Live refresh introduces changed observations; design audited/versioned reconciliation before enabling updates.

## D22 — Full snapshot revalidation and nonblank attribution

* **Decision:** Revalidate assessment inputs, reject cross-asset components/conflicting evidence UUID content, and forbid blank attribution.
* **Reason:** Prompt 13 reproduced incorrect cross-asset exclusion and empty required provenance; [ADR-012](decisions/ADR-012-assessment-boundary-revalidation.md).
* **Alternative rejected:** Trust earlier construction, validate only individual components, or infer provenance from UUID presence.
* **Trade-off:** Additional serialization; invalid historical evidence fails rather than receiving fabricated attribution.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** LOW.
* **Trigger for reconsideration:** Deeply immutable/versioned input snapshots can replace the mechanism if equivalent ownership/provenance guarantees remain tested.

## D23 — Asset negatives require complete inventory and conservative aggregation

* **Decision:** Any unknown comparison/no comparisons yields UNKNOWN; otherwise a positive yields AFFECTED; all exclusions need explicit completeness for NOT_AFFECTED.
* **Reason:** A single excluded pair cannot prove asset-wide safety; [ADR-011](decisions/ADR-011-persisted-day1-walking-skeleton.md).
* **Alternative rejected:** Missing match means safe or a probabilistic/majority vote resolves gaps.
* **Trade-off:** Additional investigation, including unknowns alongside positive pairs; completeness remains a source claim.
* **Confidence in decision:** MEDIUM.
* **Cost of reversing it:** MEDIUM.
* **Trigger for reconsideration:** Real collectors establish scoped completeness, freshness, and contradiction semantics under a reviewed policy.

## D24 — Thin interfaces and a persisted application walking skeleton

* **Decision:** Business operations live in services; demo persists one fixture, relevant cases/history, and verifies committed readback before PASS.
* **Reason:** Prove the vertical slice and reuse logic across interfaces; ADR-010/011.
* **Alternative rejected:** Business logic in handlers, an in-memory acceptance claim, or skipping commit/readback checks.
* **Trade-off:** Demo requires PostgreSQL and an explicit synthetic tenant/context; it is not general live-ingestion infrastructure.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** LOW.
* **Trigger for reconsideration:** Add a general application ingestion operation when real sources/reconciliation are specified, preserving the deterministic demo gate.

## D25 — Capability acceptance against real PostgreSQL

* **Decision:** Preserve eight end-to-end capability scenarios, including restart, provenance rejection, denial retention, and replay; missing DB configuration fails acceptance.
* **Reason:** Mock-only or structure tests cannot prove durability and boundaries; Prompt 12 acceptance report.
* **Alternative rejected:** Declare readiness from skipped database tests or tests tied only to internal mappings.
* **Trade-off:** Slower tests, a configured database, and synthetic test-data retention.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** LOW.
* **Trigger for reconsideration:** Extend the harness for deliberate new contracts; refactor its mechanics without weakening the required outcomes.

## D26 — Exact source-byte hashes and a stable synthetic replay clock

* **Decision:** Retain fixture bytes, SHA-256 file hashes, deterministic source IDs, and fixed logical demo timestamps.
* **Reason:** Make provenance and exact repeat execution inspectable; ADR-002/009/011.
* **Alternative rejected:** Mutable URI-only evidence or regenerate unrelated identities/times on every replay.
* **Trade-off:** Byte changes cause snapshot conflicts; fixture-clock semantics are unsuitable as live retrieval timestamps.
* **Confidence in decision:** MEDIUM.
* **Cost of reversing it:** MEDIUM.
* **Trigger for reconsideration:** Live sources need actual observation clocks, retention/correction policy, and reviewed cross-source identity reconciliation.

## D27 — Future mutation remains bounded, approved, and independently verified

* **Decision:** Preserve constrained/default-deny tool execution, human production approval, and independent verification before verified closure as requirements.
* **Reason:** External content/model output cannot grant production authority; ADR-001, INV-05–INV-09.
* **Alternative rejected:** Arbitrary shell execution, LLM production commands, autonomous approval, or deployment success equalling verified remediation.
* **Trade-off:** Limited eventual operation coverage and explicit action/approval/verification services, still unimplemented today.
* **Confidence in decision:** HIGH.
* **Cost of reversing it:** HIGH.
* **Trigger for reconsideration:** Specify concrete platforms/operations, immutable approval binding, and global mutation denial before adding execution; do not waive the safety requirements.

## Intentional changes during Day 1

* ADR-006 replaces ADR-005's temporary NEW lifecycle with DISCOVERED and the explicit graph.
* ADR-008 introduces a tested limited version comparator while retaining ADR-003's universal-semantics deferral.
* ADR-011 explicitly supersedes ADR-010's offline-only demo: the CLI demo now persists and verifies; the separate lab preview remains offline.
* ADR-012 implements complete-snapshot validation promised by ADR-004 and rejects blank attribution after security review.

The remaining deliberate deferrals are source authenticity/freshness/suitability,
refresh reconciliation, authenticated tenant/actor authority, immutable action-bound
approvals, a global default-deny mutation/kill-switch boundary, real remediation,
independent verification services, and administrator-resistant audit storage.
They are not evidence that today's type names implement tomorrow's features.

## Closeout verification and release

Release target: `v0.1.0-day1-foundation`, an annotated local tag on the closeout
commit after successful verification. The project version remains `0.1.0`.
The tag is not a remote push, hosted release, deployment, or production approval.

Closeout verification on 2026-10-25:

* `UV_CACHE_DIR=/tmp/vulnops-uv-cache uv run --env-file .env.example --locked pytest --junitxml=/tmp/vulnops-day1-closeout.xml`: **405 passed in 72.07 seconds**, with no failures, errors, or skips. This includes unit, PostgreSQL integration, and acceptance tests.
* `uv run vulnops demo`, with the local PostgreSQL configuration loaded: **DAY-1 ACCEPTANCE: PASS**. Four cases and twelve historical transitions persisted; the illegal AFFECTED_CONFIRMED → APPROVED transition was blocked.
* The security review has no outstanding BLOCKER or HIGH findings. Its documented future controls and limitations remain applicable.

This closeout adds documentation only. The separate
[Day 2 handoff](day02-handoff.md) contains only the four requested handoff categories.
