# VulnOps Day 1: an architecture walkthrough for the next maintainer

A vulnerability announcement does not equal enterprise risk.

An advisory can say that Lab Web versions before 2.0.0 are vulnerable. It cannot
tell us whether this organisation runs Lab Web, which version is installed, which
asset contains it, or whether that asset is public and business-critical. Those
are different questions, supported by different observations.

Day 1 makes those distinctions executable. It turns attributable source claims
and inventory into conservative asset assessments, creates independent cases,
and persists controlled lifecycle changes with their history. It does not yet
prioritise risk, create real remediation plans, authenticate approvals, execute
patches, or verify a production fix. Later lifecycle state names already exist;
their existence is not an implementation of those future capabilities.

This walkthrough describes the repository after the Prompt 13 security fixes
(`db6eb19`). Its authority is the current code, [invariants](invariants.md), and
[ADRs](decisions/). The [acceptance report](day01-acceptance-report.md) and
[security review](day01-security-review.md) record what has been verified and what
still needs a future control boundary.

## Start with the joins, not a framework

The central relationship is:

```text
Vulnerability -> AffectedProduct -> ProductIdentity + VersionConstraint
                                         |
                                  deterministic matching
                                         |
Asset -> InstalledComponent -> ProductIdentity + installed_version
```

Evidence supports both sides. Matching produces findings; application policy
turns those findings into a VulnerabilityCase for one vulnerability and one asset.
Lifecycle policy governs what happens to that case. PostgreSQL retains the current
case and the CaseEvents explaining how it reached its current state.

The packages express those responsibilities:

| Location | Responsibility today |
| --- | --- |
| `src/vulnops/domain/` | Validated source observations, enterprise context, and case snapshots |
| `src/vulnops/matching/` | Product identity, limited version semantics, and component/product resolution |
| `src/vulnops/application/` | Asset assessment, inspection, demo coordination, and transaction composition |
| `src/vulnops/workflow/` | Legal states, deterministic transitions, actors, and events |
| `src/vulnops/persistence/` | Domain-to-PostgreSQL mapping, tenant transactions, and repositories |
| `src/vulnops/sources/` | The source protocol and offline fixture adapters |
| `src/vulnops/cli.py` | Arguments, application dispatch, JSON presentation, and exit codes |
| `lab/` and `tests/` | Synthetic inputs, inert stand-ins, and executable regression boundaries |

There is no LangGraph dependency. A later orchestrator can call application
operations, but its checkpoints must never replace cases, evidence, or approval
authority. Start from the business types below; the framework is replaceable.

## 1. Evidence: what did a source actually report?

Source: [domain/evidence.py](../src/vulnops/domain/evidence.py).

**Problem and separation.** An installed version or an advisory's fixed version
needs an attributable basis. Evidence records the source category/name, subject,
claim, retrieval time, optional publication time/URI/hash, and extensible metadata.
It is separate because multiple findings and decisions may reference the same
observation, and two sources may disagree without either observation disappearing.

**Consumers and limits.** Vulnerabilities, applicability claims, scoring observations,
assets, components, cases, and lifecycle events carry evidence UUIDs. Application
assessment resolves its inputs; repositories check references within the tenant.
Evidence must never decide risk, grant approval, execute instructions in a claim,
or turn confidence into truth. Strict types, aware timestamps, forbidden extra
fields, nonblank attribution, and finite confidence in 0–1 validate representation,
not factual correctness. Internal evidence may have no public URI.

**Alternative, choice, and cost.** Embedding raw claims separately in every asset
or vulnerability would reduce joins initially but duplicate provenance. Independent
records make disagreement and replay inspectable, at the cost of more identifiers,
references, and retention work. Fixtures retain source bytes and SHA-256 hashes;
a hash cannot recreate missing bytes or authenticate the source.

**Revisit when** live-source retention, sensitive data, correction, or recurring
claim structures demand stronger contracts. Preserve the Evidence → finding →
decision distinction in [ADR-002](decisions/ADR-002-evidence-first-domain-model.md).

## 2. Vulnerability: a canonical account of source claims

Source: [domain/vulnerability.py](../src/vulnops/domain/vulnerability.py).

**Problem and separation.** Sources describe vulnerabilities differently. Vulnerability
provides one internal schema: UUID, optional CVE ID, description/times, affected
products, references, evidence IDs, source schema version, and separate CVSS/KEV/EPSS
observations. Its internal UUID supports an observation that has no CVE yet; a
well-formed CVE string does not prove assignment or existence.

**Consumers and limits.** Adapters construct it; matching/application services read
its applicability claims; repositories persist it; cases reference its UUID.
It must never claim enterprise exposure, own per-asset remediation progress, or
collapse severity, observed exploitation catalog membership, and a forecast into
an invented risk score. Missing enrichment remains None, not a negative assertion.

**Alternative, choice, and cost.** Passing CVE/OSV/vendor dictionaries directly into
business logic would save adapter code but make each consumer depend on upstream
schemas. The canonical model accepts translation and schema-maintenance work to
keep downstream logic source-independent. Single optional KEV/EPSS slots are a
deliberate limit, not a complete historical observation store.

**Revisit when** concurrent enrichment histories, new source semantics, or supported
non-CVE identities require richer representation. See [ADR-003](decisions/ADR-003-canonical-vulnerability-model.md).

## 3. AffectedProduct: what product/version claim belongs together?

Source: [domain/product.py](../src/vulnops/domain/product.py).

**Problem and separation.** A vulnerability can concern multiple products with
different ranges and fixes. AffectedProduct binds one identity to its version
constraints and applicability evidence. It keeps “fixed in 2.0.0” attached to the
correct product rather than making that version a global CVE property.

The actual model's essential fields are:

```python
    product: ProductIdentity
    version_constraints: list[VersionConstraint] = Field(default_factory=list)
    evidence_ids: list[UUID] = Field(min_length=1)
```

**Consumers and limits.** Vulnerability contains these claims; resolve_affected
compares each with InstalledComponent. AffectedProduct must never identify an
enterprise asset or assert that an organisation is affected. An empty constraint
list means missing usable version information, not proof of no affected versions.

**Alternative, choice, and cost.** A flat vulnerability-wide product list plus one
version range would be smaller but lose the association between identities, ranges,
and evidence. Explicit grouping accepts nested structures and iteration to preserve
the meaning of each source claim.

**Revisit when** product-specific exceptions, release branches, or evidence needs
cannot be represented faithfully. Extend the claim boundary without moving asset
decisions into source data.

## 4. ProductIdentity: what exactly is the thing being named?

Source: [domain/product.py](../src/vulnops/domain/product.py); interpretation lives
in [matching/product_matcher.py](../src/vulnops/matching/product_matcher.py).

**Problem and separation.** Display names collide. ProductIdentity retains vendor,
product, ecosystem, PURL, CPE, package name, and aliases. PURL names a package in
an ecosystem; CPE supplies a structured platform/product identity. The type is
shared by advisory products and installed components, independently of versions
and enterprise ownership.

**Consumers and limits.** Both sides of matching depend on it. The model stores
identifiers; the matcher interprets a deliberately supported subset. Identity must
never assert that two aliases are equivalent, infer a version range, or replace
asset context. The aliases field is retained data, not an active fuzzy-match rule.

**Alternative, choice, and cost.** Name-only matching is convenient but can confuse
unrelated packages; one mandatory identifier scheme would exclude useful sources.
Multiple identifiers preserve source detail, with parser work and more UNKNOWN
results when identifiers conflict or have unsupported qualifiers.

**Revisit when** concrete integrations justify new namespaces, reviewed alias maps,
or broader CPE/PURL support. Keep contradictions visible rather than allowing a
higher-priority identifier to erase them.

## 5. VersionConstraint: represent the claim before comparing it

Source: [domain/version.py](../src/vulnops/domain/version.py); comparison lives in
[matching/version_matcher.py](../src/vulnops/matching/version_matcher.py).

**Problem and separation.** Sources may report an exact affected version, an
introduced release, the last affected release, a fixed release, or incomplete
information. VersionConstraint retains these boundaries, source status, and an
optional scheme without pretending that all ecosystems use one ordering.

**Consumers and limits.** AffectedProduct groups constraints; the version matcher
evaluates them. The model must never compare arbitrary strings or infer a fix.
Introduced/last-affected are inclusive; fixed is exclusive. None stays unknown.
VersionStatus describes a source claim; AffectedStatus describes an assessed asset
or candidate pair. Their similar words do not make them interchangeable authority.

The actual supported comparison uses these inequalities:

```python
    applies = (
        (exact is None or parsed == exact)
        and (introduced is None or parsed >= introduced)
        and (last is None or parsed <= last)
        and (fixed is None or parsed < fixed)
    )
```

Here parsed values are numeric major/minor/patch tuples under explicit `semver`,
not arbitrary strings. Prereleases, build metadata, epochs, suffixes, and unknown
schemes remain unsupported for ordering. Opaque exact equality is supported
without inventing an order; unequal opaque strings do not prove non-affectedness.

**Alternative, choice, and cost.** A universal version comparator would look simpler
but misread ecosystem rules. Narrow explicit semantics accept investigation work
and manual extensions to avoid false reassurance. Multiple affected ranges form
a union; an unsupported gap prevents a negative conclusion. A supported positive
can still establish pair-level affectedness unless an explicit exemption conflicts.

**Revisit when** a real supported ecosystem and fixtures justify its version rules.
Do not generalise by removing UNKNOWN from [ADR-008](decisions/ADR-008-conservative-affected-resolution.md).

## 6. Asset: which enterprise resource matters?

Source: [domain/asset.py](../src/vulnops/domain/asset.py).

**Problem and separation.** The same product can run on a critical public production
VM and a low-criticality development repository. Asset holds the resource UUID,
namespaced upstream ID, hostname when applicable, type, environment, business
context, ownership label, exposure, components, and evidence. Enterprise context
belongs here because it varies independently of the vulnerability.

**Consumers and limits.** Inventory adapters build assets; components reference
them; assessment and cases depend on their context; CLI exposes them. Asset must
never become a replacement CMDB, calculate CVE severity, or grant approval from
an owner label. None exposure means unknown, not internal. An empty component list
does not establish completeness. Component ownership is validated against asset_id.

**Alternative, choice, and cost.** Importing a full CMDB schema would preserve more
attributes but duplicate upstream responsibilities. The minimal snapshot accepts
adapter mapping and omitted relationships for a smaller security/remediation domain.
Business criticality is a category, not a computed numeric risk score.

**Revisit when** measured remediation needs require finer exposure, per-field
freshness, or additional context. Preserve upstream authority and unknown values
under [ADR-004](decisions/ADR-004-minimal-enterprise-asset-model.md).

## 7. InstalledComponent: what does this asset reportedly run?

Source: [domain/asset.py](../src/vulnops/domain/asset.py).

**Problem and separation.** One asset can contain several products and installations.
InstalledComponent gives each installation a UUID, owning asset UUID, ProductIdentity,
optional installed version, discovery time, collector/source name, and evidence.
It separates a product in an advisory from a reported installation on an asset.

**Consumers and limits.** Asset groups components; the matcher compares each with
AffectedProduct; PostgreSQL stores components as separate ordered rows. A component
must never decide whole-asset safety, own business criticality, or silently move to
another asset. Its IDs/asset reference are frozen, but containing Python lists are
mutable; application entry points must still revalidate full snapshots.

**Alternative, choice, and cost.** A single product/version field on Asset would
be easy to query but cannot represent multiple installations. Components accept
more records and matching work for faithful inventory and component-level evidence.

**Revisit when** container layers, installation paths, or installation-specific
remediation need explicit scope. The current lab uses installation IDs, not actual
runtime discovery inside the inert stand-in images.

## 8. Affected-resolution: connect claims without guessing

Sources: [product_matcher.py](../src/vulnops/matching/product_matcher.py),
[version_matcher.py](../src/vulnops/matching/version_matcher.py),
[affected_resolver.py](../src/vulnops/matching/affected_resolver.py), and
[application/assessment.py](../src/vulnops/application/assessment.py).

**Problem and separation.** Neither an advisory nor inventory alone answers whether
an installation is affected. resolve_affected returns a finding for one component/
product pair: status, identities, reason, evidence references, methods, and certainty
explanation. Matching is separate from storage/lifecycle so its result can be
evaluated without a database, agent, or production action.

**Consumers and limits.** assess_asset aggregates pair findings; the walking skeleton
creates cases from relevant assessments. Resolution must never compute priority,
close cases, deploy patches, or treat a model confidence value as proof. Different
structured products exclude that pair, not every product on the asset.

Product matching prefers PURL, CPE, ecosystem/package, then complete normalised
vendor/product names. It preserves structured conflicts and unsupported ambiguity.
Name-only identity cannot justify a definitive version-based exclusion. Package
fallback currently supports PyPI/npm; retaining other PURL types is not universal
ecosystem version support.

Asset assessment is deliberately stricter than a positive pair: any UNKNOWN
comparison, or no comparisons, yields UNKNOWN; otherwise a positive yields
AFFECTED. Only all exclusions plus explicit complete-inventory evidence can yield
NOT_AFFECTED. All referenced asset-scoped inventory claims must explicitly assert
completeness. “Every component is listed” does not mean “every version is known.”

The security fix at this entry point is actual code, not an instruction to callers:

```python
    vulnerability = Vulnerability.model_validate_json(vulnerability.model_dump_json())
    asset = Asset.model_validate_json(asset.model_dump_json())
    evidence = [Evidence.model_validate_json(item.model_dump_json()) for item in evidence]
```

Without full Asset revalidation, replacing web-01's mutable component list with
web-02's fixed components could return a false negative for the wrong owner.
Conflicting contents for one evidence UUID are also rejected. See [ADR-012](decisions/ADR-012-assessment-boundary-revalidation.md).

**Alternative, choice, and cost.** Fuzzy/LLM matching or a default-safe result could
reduce investigation work but hide unsupported assumptions. Deterministic narrow
rules accept more UNKNOWN cases, serialization cost, and explicit completeness
claims. Evidence resolution proves presence, not authenticity or freshness.

**Revisit when** supported source semantics, inventory scope, or ecosystem fixtures
justify an extension. Preserve evidence and distinguish pair-level range union
from asset-level aggregation; they apply different conservatism rules.

## 9. VulnerabilityCase: the operational unit is vulnerability × asset

Source: [domain/case.py](../src/vulnops/domain/case.py).

**Problem and separation.** A global CVE cannot carry independent outcomes for a
fixed web server, vulnerable development server, and unknown legacy host. A case
references one vulnerability UUID and one asset UUID, with its own UUID, assessment,
lifecycle state, exposure snapshot, evidence, timestamps, and optional future
priority/plan/approval/verification references. Database uniqueness is per tenant
and vulnerability/asset pair.

**Consumers and limits.** Application operations create cases; workflow validates
their changes; repositories store them; CLI/history views inspect them. Cases must
never overwrite shared vulnerability claims or progress every asset together.
They also do not execute the plan or authenticate the approval named by a UUID.

Definitive assessments cannot omit evidence references:

```python
        if self.affected_status is not AffectedStatus.UNKNOWN and not self.evidence_ids:
            raise ValueError("AFFECTED and NOT_AFFECTED cases require evidence_ids")
```

Cases and exposure are frozen snapshots; evidence references are tuples. This is
stronger than the mutable source containers, but trusted bypass APIs such as
model_copy are not authorised business updates. Repository/application validation
remains necessary. `priority=None` means no prioritisation decision has been made.

**Alternative, choice, and cost.** One enterprise object per CVE would save records
but conflate ownership, exceptions, rollout, and verification. One case per component
would fragment the requested asset-level workflow. The chosen pair accepts more
records and aggregate reporting for independent decisions.

**Revisit when** multiple installations need separate remediation subrecords or
reopening needs new policy. Keep the asset operational boundary from [ADR-005](decisions/ADR-005-vulnerability-case-granularity.md).

## 10. State machine: which changes are actually legal?

Sources: [workflow/states.py](../src/vulnops/workflow/states.py) and
[workflow/transitions.py](../src/vulnops/workflow/transitions.py).

**Problem and separation.** An agent, retry, or command must not invent an approval
shortcut. One immutable ALLOWED_TRANSITIONS mapping defines legal edges. The pure
transition_case function takes an expected state, actor, reason, evidence, and
optional time/correlation ID; it returns a validated replacement case and event.
It does not write the database.

These actual guards explain why a stale request differs from a forbidden edge:

```python
    if case.state is not expected_current_state:
        raise StateConflictError("Current state differs from expected_current_state")
    if new_state not in ALLOWED_TRANSITIONS[case.state]:
        raise TransitionError(f"Transition {case.state.value} -> {new_state.value} is not permitted")
```

**Consumers and limits.** The planner and persisted repository use this policy.
The state machine must never be defined by an orchestration checkpoint or silently
skip prerequisites. AFFECTED_CONFIRMED → APPROVED is absent from the graph.
Approval-related edges require a HUMAN actor and appropriate references; verification
requires its reference and a HUMAN/SYSTEM verifier. Those are structural guards,
not implemented authentication or proof of independent verification.

The main vocabulary runs from DISCOVERED through enrichment, asset matching,
confirmation, prioritisation, planning, sandbox, approval, canary, rollout, rescan,
and VERIFIED_FIXED. Alternate outcomes include NOT_AFFECTED, deferral, mitigation,
rejection, failure, rollback, and manual investigation. Most alternate outcomes
have no automatic successor; PATCH_FAILED has explicit recovery edges. Mitigation,
deferral, and rollback do not mean a verified fix.

**Alternative, choice, and cost.** Free-form assignments or graph-owned business
state would be flexible but bypassable. Explicit edges accept rigidity, prerequisite
work, and separately designed recovery policies for reproducible control.

**Revisit when** reopening, retry, or recovery workflows are specified. Do not add
an edge solely to make a failing demo pass; record the policy decision in an ADR.

## 11. CaseEvent and audit history: how did this state happen?

Source: [workflow/events.py](../src/vulnops/workflow/events.py) and repository
append/history methods in [repositories.py](../src/vulnops/persistence/repositories.py).

**Problem and separation.** The current state cannot explain its own history.
CaseEvent records event/case IDs, type, from/to states, actor type/ID, reason,
evidence IDs, correlation ID, and aware timestamp. It is separate because a new
case snapshot must not rewrite the explanation of earlier transitions.

**Consumers and limits.** Workflow emits events; repositories append them; the demo
and CLI inspect them. Events must never be edited to match today's state or serve
as credentials. History is ordered by per-case database sequence, not solely by
timestamps. A denied transition is not a successful CaseEvent; the demo retains
its denial as a SYSTEM Evidence observation instead.

**Alternative, choice, and cost.** Overwriting a case alone loses accountability.
Full event sourcing would require complete rebuildable event schemas/projections;
Day 1 instead stores authoritative snapshots plus explanatory events. That accepts
some duplicated information and does not promise full system reconstruction or
administrator-resistant immutability.

**Revisit when** hostile-administrator threats, regulated retention, or full replay
justify a ledger/event-sourcing design. Current append APIs and runtime grants
constrain ordinary application writes, not database owners.

## 12. Persistence: make current state and its explanation durable together

Sources: [models.py](../src/vulnops/persistence/models.py),
[session.py](../src/vulnops/persistence/session.py),
[repositories.py](../src/vulnops/persistence/repositories.py), and
[initial migration](../alembic/versions/0001_day1_persistence.py).

**Problem and separation.** Process memory cannot retain authoritative cases after
a restart. PostgreSQL stores six tables: vulnerabilities, assets, installed_components,
evidence, vulnerability_cases, and case_events. SQLAlchemy models represent storage;
Pydantic models represent domain contracts. Repositories return domain objects,
keeping sessions/lazy loading out of domain logic.

**Consumers and limits.** Application composition opens tenant transactions and
uses repositories for saves, reads, transitions, and history. Persistence must
never infer affectedness or accept an arbitrary progressed snapshot as a legal
update. save_case creates DISCOVERED cases; transition/append paths load the locked
current row and invoke the policy. Reference existence is checked, not universal
evidence suitability.

Payloads are JSONB snapshots with relational identity/lookup fields, composite
tenant foreign keys, uniqueness constraints, and ordered component/event rows.
JSONB here is database storage, not a flat-file source of truth. Forced RLS and
explicit query filters both select the tenant; tenant_session sets transaction-local
`app.current_tenant_id`. The runtime role is separate from the migration owner.
Caller-selected tenant context is still a trusted local facility, not authentication.

The actual persisted transition boundary is small:

```python
        with self._session.begin_nested():
            row = self._locked_case(case_id)
            result = validate_transition(case=_decode(VulnerabilityCase, row.payload), **request)
            return self._store_transition(row, result)
```

_store_transition checks evidence, compares expected state/revision, updates the
case, and inserts its event in the same transaction. A nested savepoint protects
the pair even if an outer caller catches an exception; the outer unit of work
decides commit/rollback. append_case_event also validates policy for new events,
and treats identical historical event replay as a no-op.

**Alternative, choice, and cost.** SQLite/JSON would reduce local operations, and
leaking ORM models would reduce conversion code. PostgreSQL plus adapters accepts
a running server, credentials, migrations, JSONB/schema evolution, and validation
cost for transactional integrity and a stable domain boundary. Exact saves replay;
different content for an existing identity conflicts instead of silently merging.

**Revisit when** measured reporting pressure needs normalised observations/indexes,
source changes require reconciliation, or recovery requirements demand stronger
operations. Preserve atomic case/event writes and tenant isolation in [ADR-007](decisions/ADR-007-postgres-and-append-audit.md).

## 13. Fixture source adapter: external schemas stop here

Sources: [sources/base.py](../src/vulnops/sources/base.py) and
[sources/fixtures.py](../src/vulnops/sources/fixtures.py).

**Problem and separation.** Downstream logic needs repeatable canonical inputs,
not knowledge of a feed's field names. VulnerabilitySource defines the boundary;
FixtureVulnerabilitySource translates an explicit OSV-like subset and separate
KEV/EPSS/vendor records. SourcedVulnerability carries both the canonical model and
its Evidence. Inventory has a separate loader returning SourcedAsset records.

The protocol's actual signature is:

```python
@runtime_checkable
class VulnerabilitySource(Protocol):
    def fetch(self) -> Iterable[SourcedVulnerability]:
        """Return canonical observations plus the evidence needed to persist them."""
        ...
```

**Consumers and limits.** The application and offline preview consume these records.
Adapters must never execute advisory instructions, fetch reference URLs implicitly,
own case state, or hide unsupported semantics. The current adapter validates a
small batch, rejects malformed/duplicate/orphan/conflicting supported inputs, uses
stable UUIDs and exact source-byte hashes, and performs no vulnerability API calls.
It can select one CVE fixture; enrichment outside that selected CVE is ignored.

**Alternative, choice, and cost.** Immediate live feeds would add availability,
authentication, limits, and schema drift before the core was proved. Canonical JSON
fixtures would avoid translation but fail to exercise adapters. Source-like synthetic
snapshots accept limited realism and batch memory for reproducibility.

**Revisit when** live sources require pagination, timeouts, credentials, retention,
freshness, and update reconciliation. Implement the same boundary without pretending
the fixture subset is a complete upstream specification. See [ADR-009](decisions/ADR-009-fixture-first-source-adapters.md).

## 14. CLI: presentation around application operations

Sources: [cli.py](../src/vulnops/cli.py),
[application/inspection.py](../src/vulnops/application/inspection.py), and
[application/bootstrap.py](../src/vulnops/application/bootstrap.py).

**Problem and separation.** Maintainers need to inspect the walking skeleton without
building a web application. The `vulnops` entry point uses argparse for vulnerability
show, asset list/show, case list/show/history, and demo. InspectionService owns input
and pagination rules through its repository protocol; composition owns engine and
transaction lifetimes. Handlers parse, dispatch, serialize, and choose exit codes.

**Consumers and limits.** Human operators, scripts, and acceptance/process tests
invoke it. The CLI must never implement a second matching policy, grant approval,
or make advisory strings executable. JSON preserves UNKNOWN/null and evidence
references and escapes terminal controls. Asset/case IDs are UUIDs; CVE lookup is
separate. Lists default to 100, max 1000, with offset pagination.

The six inspection commands are read-only and require an explicit tenant option
or VULNOPS_TENANT_ID. The demo is different: it writes the selected fixtures/cases
to the dedicated lab tenant unless explicitly overridden. It needs configured
PostgreSQL and DATABASE_URL; it does not start Docker or run migrations implicitly.
After successful committed readback it emits JSON, a blocked-edge line, then PASS.
Errors return nonzero; an empty valid list/history is success.

**Alternative, choice, and cost.** A web console or HTTP API would add hosting,
identity, session, and UI work. A small standard-library CLI accepts verbose JSON,
per-command connection setup, and trusted operator configuration for fast iteration.
Exit codes are 0 success, 1 source/database/acceptance failure, 2 invalid input/config,
and 3 a record not visible in this tenant.

**Revisit when** collaboration, approval queues, evidence drill-down, or frequent
comparison/filtering justify a console. Reuse the services and first establish
authenticated tenant/actor authority; the current CLI is not that authority.

## 15. Acceptance harness: what must a future change preserve?

Sources: [acceptance/test_day01.py](../tests/acceptance/test_day01.py),
[acceptance/conftest.py](../tests/acceptance/conftest.py), and
[shared PostgreSQL setup](../tests/conftest.py).

**Problem and separation.** Model tests alone cannot prove that sources, matching,
cases, state changes, and storage work together. Eight acceptance scenarios exercise
the application and committed PostgreSQL state. They are separate from unit tests
so changes can preserve externally meaningful behavior without preserving internal
function layout or policy-map representation.

**Consumers and limits.** Engineers and later CI use this gate. It must never fake
durability with in-memory storage or count skipped database checks as readiness.
It tests affected, unaffected, unknown/manual investigation, a retained denied
approval attempt, missing/foreign provenance rejection, fresh-process readback,
exact replay counts, and different asset outcomes for one CVE. Acceptance carries
both acceptance and integration markers and fails missing database configuration.

**Alternative, choice, and cost.** Mock-only tests would run faster but could miss
missing commits and cross-layer mistakes; structure assertions could reject harmless
refactors. Capability tests accept PostgreSQL startup, migrations, slower execution,
and synthetic test data retention. Fixed-table SQL counts are used only to verify
durable cardinality, not private application implementation.

**Revisit when** new supported capabilities add contracts, or a deliberate ADR
changes a contract. Extend fixtures and scenarios without weakening UNKNOWN,
provenance, identity, or atomicity just to obtain green tests. The last verified
post-security baseline was 405 passing tests, including all eight acceptance cases;
this documentation-only change does not imply a new runtime test run.

## Trace the actual Lab Web example end to end

### The inputs are fictional, but their relationships are real

The demo selects [CVE-2099-900001.json](../lab/fixtures/vulnerabilities/CVE-2099-900001.json),
not an assigned real CVE. Its OSV-like record claims:

| Input fact | Actual fixture value |
| --- | --- |
| Package | `vulnops-lab-web` |
| PURL | `pkg:pypi/vulnops-lab-web` |
| Display vendor/product | `VulnOps Lab` / `Lab Web` |
| Declared range type | `SEMVER` |
| Introduced / fixed | `1.0.0` / `2.0.0` |
| CVSS observation | version `3.1`, base score `9.8` |
| Snapshot observation clock | `2026-10-25T08:00:00Z` |

The [inventory](../lab/inventory/assets.json) reports web-01 as a production,
internet-exposed, CRITICAL VM. Its external ID is `vulnops-lab:asset-web-01`;
its internal asset UUID is a different identifier. It contains Lab Web 1.4.0 and
Lab Common 1.0.0. These products are inventory fiction, not packages actually
installed in the stand-in HTTP image.

### 1. Bytes become Evidence, then a canonical Vulnerability

cli.main dispatches demo to run_walking_demo. load_demo_vulnerability selects the
one CVE through FixtureVulnerabilitySource. _read parses the record inside the
selected directory and hashes the exact file bytes. _evidence attributes the claim
to the source, subject CVE, fixture URI, and fixed observation clock.

The adapter creates a stable internal vulnerability UUID, translates `summary`
to title and `details` to description, and constructs the AffectedProduct with its
ProductIdentity and explicit introduced/fixed VersionConstraint. Its version_scheme
becomes `semver`, its source status AFFECTED, and applicability evidence references
the vulnerability-record Evidence. KEV, EPSS, and vendor enrichment contribute
their own evidence. None of their scores/listing flags decides this asset's status.

Four source Evidence records and the canonical vulnerability are saved before
enterprise inventory is loaded. Evidence hashes refer to entire source file bytes;
an enrichment Evidence claim can describe one entry within such a file. Neither
the URI nor the hash causes a network fetch.

### 2. The installed component is tied to the right enterprise asset

load_fixture_inventory builds asset-scoped inventory Evidence, then the component
observations and their containing Asset. Each component references that asset's
UUID, not its hostname or the advisory's product name. The raw inventory's explicit
component_inventory_complete claim is retained in Evidence metadata.

For web-01, the matcher receives an InstalledComponent for Lab Web with version
1.4.0 and the AffectedProduct for Lab Web with the range `[1.0.0, 2.0.0)`.
The identity comparison succeeds using PURL. The version comparison uses numeric
tuples: `(1, 4, 0)` is at least `(1, 0, 0)` and below `(2, 0, 0)`.
The pair finding is AFFECTED and references both inventory and advisory evidence.

Lab Common has a different structured product identity and is excluded for this
pair. That exclusion does not cancel Lab Web's positive result. With no UNKNOWN
comparison, assess_asset returns AFFECTED for web-01. Completeness is not required
to establish this positive result; it is required for negative asset conclusions.

### 3. The conclusion becomes one case, not a global CVE decision

prepare_demo constructs a stable case UUID from the vulnerability/asset identities.
The initial case already has affected_status AFFECTED, because matching preceded
case construction. Its lifecycle state is DISCOVERED. These are separate axes:
“what the assessment says” and “which controlled workflow gates were recorded.”
Priority and plan/approval/verification references remain None.

The same function plans three transitions with the pure workflow service:

| Step | State change | Logical event time |
| --- | --- | --- |
| Initial snapshot | Case created DISCOVERED | `08:00:00Z` |
| 1 | DISCOVERED → ENRICHED | `08:00:01Z` |
| 2 | ENRICHED → ASSET_MATCHED | `08:00:02Z` |
| 3 | ASSET_MATCHED → AFFECTED_CONFIRMED | `08:00:03Z` |

These are offsets from the fixture clock on 25 October 2026, not measurements of
current wall-clock runtime. Event IDs, actor (`SYSTEM`, `vulnops-day1-demo-v1`),
correlation, reasons, and times are repeatable. The ASSET_MATCHED event reason
retains serialized AssetAssessment details; there is no separate finding table.

### 4. Planned events must still pass persisted transition policy

An in-memory plan is not authoritative state. persist_demo saves the source and
asset snapshots, creates the DISCOVERED case if absent, and appends the planned
events through Repositories.append_case_event. That method validates each new
event against the locked current case and updates snapshot/history atomically.
It is not a backdoor for bypassing the graph.

For web-01, vulnerability_cases now contains AFFECTED/AFFECTED_CONFIRMED, while
case_events retains the three from/to records in sequence. Earlier events are
not rewritten to AFFECTED_CONFIRMED. Their evidence UUIDs resolve to stored
observations and retained fixture bytes.

The other relevant assets take independent paths:

| Asset for this CVE | Assessment | Final recorded state | Why |
| --- | --- | --- | --- |
| web-01 | AFFECTED | AFFECTED_CONFIRMED | Lab Web 1.4.0 is inside the range |
| web-02 | NOT_AFFECTED | NOT_AFFECTED | Lab Web 2.0.0 reaches the fixed boundary; complete inventory and all exclusions support the negative |
| dev-01 | AFFECTED | AFFECTED_CONFIRMED | The vulnerable component remains affected in development; no priority is inferred |
| legacy-01 | UNKNOWN | MANUAL_INVESTIGATION | Lab Web version is missing; inventory completeness does not supply a version |

The API and database assets contain different structured products for this CVE.
They are persisted inventory, but not candidate cases. The demo does not create
the entire vulnerability × inventory Cartesian product. Missing/ambiguous identities
would need conservative handling; these two exclusions are structured and explicit.

### 5. The forbidden approval is tested, then committed data is reread

persist_demo attempts AFFECTED_CONFIRMED → APPROVED on an affected stored case.
The authoritative graph rejects the edge before approval prerequisites could
provide some unrelated reason for failure. The demo requires that specific denial,
checks state/history equality, and stores a SYSTEM blocked_transition_attempt
observation. It does not fabricate a successful approval event or patch anything.

All writes share one outer tenant transaction. Before commit, verify_demo checks
source/evidence/assets/cases/history against the expected result. After commit,
run_walking_demo opens a separate tenant transaction and checks them again. Only
then may the CLI print its blocked-edge message and `DAY-1 ACCEPTANCE: PASS`.
Write/commit failures cannot produce PASS; post-commit readback failure also cannot,
although already committed records remain available for inspection.

The current selected demo yields one vulnerability, six assets, twelve installed
components, four cases, twelve CaseEvents, and eleven Evidence records: four
vulnerability/enrichment observations, six inventory observations, and one denial
observation. These counts describe these fixtures, not a universal architecture rule.

### 6. Repeat execution is replay, not reseeding

Case/event IDs and source identities are stable. On an exact repeat, existing
final cases/history must match the plan; append_case_event recognises identical
historical event IDs/content without advancing state again. No duplicate workflow
or production action is created. Changed snapshot bytes, conflicting event content,
or independently progressed cases fail instead of being reset. Reconciliation is
a future explicit operation, not an implicit “latest value wins” rule.

To inspect this locally, configure the database as in the root README. With
DATABASE_URL exported, `uv run vulnops demo` is the command. An ignored `.env`
can instead be loaded explicitly:

```bash
export VULNOPS_TENANT_ID=d383a693-f08c-504b-bf7e-d7008885b119
uv run --env-file .env --locked vulnops demo
uv run --env-file .env --locked vulnops vulnerability show CVE-2099-900001
uv run --env-file .env --locked vulnops case list
uv run --env-file .env --locked vulnops case history '<case-uuid-from-list>'
```

The default tenant above is for the demo. It is not authentication. Running
`uv run python lab/demo.py` is a separate database-free preview across all five
vulnerability fixtures; it calls preview_demo and never claims persisted acceptance.

## A maintenance checkpoint before changing anything

With this document closed, explain why a different-product exclusion cannot clear
an entire asset, why DISCOVERED can coexist with an AFFECTED assessment, and why
the case update/event insert must commit together. Then locate the actual functions
that enforce each rule. If an intended change crosses one of those boundaries,
read its ADR and add behavior tests before changing the contract.

Read [the security review](day01-security-review.md) before giving an agent write
access. An agent with raw database credentials or host process authority can bypass
Python policy. Source authenticity/freshness, authenticated actor context, exact
immutable action-bound approvals, and a shared default-deny mutation/kill-switch
boundary are required future work, not capabilities implied by today's type names.

If you understand only ten things about Day 1, understand these:

1. **A vulnerability announcement is a source claim, not enterprise risk.** Match
   its product/version claims to evidence-backed inventory before making an asset decision.
2. **Evidence is attribution, not truth.** Preserve what was observed, its source,
   and its bytes/reference; never execute its text or let confidence grant authority.
3. **Product identity, version semantics, and enterprise context are distinct.**
   A product name alone and a universal string comparator cannot replace them.
4. **UNKNOWN is an operational outcome.** Missing versions and ambiguous semantics
   require investigation; they do not become NOT_AFFECTED by default.
5. **Pair exclusion is not whole-asset safety.** Asset negatives require complete
   inventory evidence and every relevant comparison to support exclusion.
6. **One vulnerability × one asset is one independent case.** Shared CVEs do not
   imply shared assessment, ownership, progress, or eventual verification.
7. **Assessment and lifecycle state answer different questions.** Matching supplies
   the assessment; deterministic policy governs recorded workflow progression.
8. **A current snapshot and its history have different jobs.** PostgreSQL owns
   authoritative state; atomic append-oriented events explain how it changed.
9. **A validated object is not a permanent security boundary.** Revalidate mutable
   snapshots, preserve asset/tenant scope, and keep credentials/actor authority outside agents.
10. **The framework and interface are replaceable; the acceptance contract is not
    disposable.** New sources, agents, or consoles must preserve provenance, UNKNOWN,
    legal transitions, durable history, and exact replay before adding new capabilities.
