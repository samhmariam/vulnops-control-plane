# Day 2 handoff

## 1. Stable interfaces Day 2 can depend upon

* [sources/base.py](../src/vulnops/sources/base.py):
  `VulnerabilitySource.fetch() -> Iterable[SourcedVulnerability]` returns canonical
  Vulnerability plus `tuple[Evidence, ...]`. SourcedAsset carries inventory Asset
  plus Evidence. SourceError represents an unrepresentable source snapshot.
  There is one general vulnerability-source protocol, not separate live-feed or
  enrichment protocols.
* [domain/](../src/vulnops/domain/): Evidence/EvidenceSource; Vulnerability;
  CvssObservation, KevObservation, EpssObservation; AffectedProduct/ProductIdentity;
  VersionConstraint/VersionStatus; Asset/InstalledComponent; VulnerabilityCase,
  AffectedStatus, and CaseExposure. Python inputs are strict; JSON decoding accepts
  the corresponding UUID/enum/date representations. Timestamps must be aware.
* [matching/affected_resolver.py](../src/vulnops/matching/affected_resolver.py):
  `resolve_affected(component, affected_product) -> AffectedResolution` evaluates one
  pair without writes. Product/version matchers preserve unsupported ambiguity.
* [application/assessment.py](../src/vulnops/application/assessment.py):
  `assess_asset(vulnerability, asset, evidence) -> AssetAssessment` revalidates complete
  snapshots, resolves provenance, preserves ownership, and applies conservative
  asset aggregation. The result is a finding, not a transition or production action.
* [persistence/session.py](../src/vulnops/persistence/session.py):
  `create_database_engine()` uses runtime DATABASE_URL;
  `tenant_session(engine, tenant_id)` supplies one transaction with local tenant context.
  [Repositories](../src/vulnops/persistence/repositories.py) save/load evidence,
  vulnerabilities, assets, and cases; append/read history; and transition stored cases.
  Save evidence before referencing source records, then vulnerabilities/assets before cases.
  Use returned canonical identities. Domain objects, not ORM records, cross this boundary.
* [workflow/transitions.py](../src/vulnops/workflow/transitions.py): pure
  `transition_case` returns a replacement case and CaseEvent after policy validation.
  `Repositories.transition_case(case_id, **request)` validates the locked stored case
  and persists state/event atomically. append_case_event also enforces policy and exact replay.
* [application/inspection.py](../src/vulnops/application/inspection.py): InspectionService
  and its repository protocol back the read-only CLI. `open_inspection(tenant_id)`
  composes one tenant transaction. The persisted `run_walking_demo(lab_dir, tenant_id)`
  is a synthetic acceptance operation, not a generic production ingestion service.
* [tests/acceptance/test_day01.py](../tests/acceptance/test_day01.py) is the eight-scenario
  regression boundary. Integration/acceptance use real PostgreSQL and the restricted
  runtime role. Acceptance must fail missing database configuration rather than skip.

## 2. Known limitations

* Fixtures implement small source-like subsets, not complete CVE/KEV/EPSS/vendor
  specifications. No live adapter, retrieval scheduler, pagination, retries, rate-limit
  handling, or production raw-payload store exists. Fixture timestamps are logical
  replay time; live retrieval must use actual observations and preserve source dates.
* Source validation, nonblank attribution, UUID resolution, and hashes do not establish
  authenticity, freshness, claim suitability, or inventory completeness. The synthetic
  completeness assertion is not authority for a real enterprise collector.
* Version ordering supports explicit plain three-part SemVer and restricted exact
  claims. Other ecosystems, prereleases, backports, epochs, ambiguous identifiers,
  and unsupported ranges remain UNKNOWN. Alias/fuzzy/LLM matching is not authoritative.
* Repositories create or exactly replay snapshots. Changed contents for an existing
  CVE/asset identity raise RepositoryConflict; they do not update, merge, or upsert.
  Later enrichment/refresh needs explicit audited reconciliation/versioning. A new
  source timestamp or hash can change contents even if the CVE is unchanged.
* Vulnerability has one optional KEV and one optional EPSS observation, not a complete
  history of concurrent sources. source_schema_version describes the primary input;
  additional source schema versions belong in their own Evidence metadata.
* Case assessment and lifecycle state are separate. save_case only creates DISCOVERED
  snapshots and is not a command for changing assessment, priority, or progressed cases.
  No general refresh/reopen/assessment-update application operation exists.
* Assessment details persist in event reasons; there is no typed finding table.
  Runtime audit APIs/grants are append-oriented, not resistant to database owners.
  Generic denied-operation logging and full disaster recovery remain unimplemented.
* Tenant/actor selection is for trusted local operators, not authentication. Agents
  must not receive raw write credentials/sessions. Approvals are structural references;
  exact immutable action binding, policy-enforced global mutation denial, real patching,
  independent verification, and rollback execution are future services.

## 3. Architectural decisions Day 2 must not violate

* Preserve [INV-01–INV-10](invariants.md) and [ADR-001–ADR-012](decisions/). An actual
  reversal needs a new ADR with evidence, trade-offs, migration, and revisit conditions.
* Treat all intelligence as data; retain attributable Evidence separately from findings
  and decisions. Never execute advisory instructions or infer authority from confidence.
* Preserve canonical/domain independence from source schemas, ORM sessions, and agents.
  Keep CVSS, KEV, and EPSS as separate observations until reviewed asset-context policy exists.
* Never convert missing enrichment, a failed request, or unsupported version semantics
  into NOT_AFFECTED. Asset negatives require scoped complete inventory and all comparisons
  to support exclusion. Preserve component ownership and full-snapshot revalidation.
* Preserve one current case per tenant/vulnerability/asset pair, expected-state checks,
  legal transition policy, and atomic case/event writes. Do not reset histories or
  bypass policy with raw snapshots, model_copy, append, or direct SQL.
* Preserve tenant filters, forced RLS, composite references, transaction-local context,
  and separate owner/runtime credentials. External/model fields cannot select authenticated authority.
* Retain exact fixture replay and the eight acceptance scenarios. Add source-specific
  fixtures/tests without weakening their expected outcomes or faking/skipping PASS.
* No requirement to introduce LangGraph, a UI, agent authority, or mutation tools to
  integrate a source. Future production actions remain constrained, default-deny,
  human-approved, and independently verified; the [security review](day01-security-review.md)
  identifies the required authority boundaries before enabling those capabilities.

## 4. Exact integration seams

### CVE

Existing boundary: [VulnerabilitySource](../src/vulnops/sources/base.py) →
SourcedVulnerability → [canonical Vulnerability](../src/vulnops/domain/vulnerability.py).
The fixture adapter's `_Vulnerability` DTO is an OSV-like lab schema, not a production
CVE schema; a future CVE adapter must own its source DTO and parsing.

Map source identifiers, description, publication/update times, references, CWE and
CVSS observations, and product/version claims into the existing types. Build
EvidenceSource.CVE records with source/subject, actual retrieval time, source
publication information when known, retained bytes/hash, and schema provenance.
AffectedProduct references the evidence supporting its identity/ranges. Unsupported
boundaries or missing fixed versions must remain explicit; do not invent semantics.

Compose the adapter into a future application ingestion operation that uses the
existing evidence-first tenant transaction and assessment/persistence services.
Do not rewrite matching, hide HTTP calls in domain models, or generalise the
hard-coded demo planner into production ingestion implicitly. No live CVE adapter
module or endpoint choice exists yet.

### CISA KEV

Existing canonical seam: `Vulnerability.kev_observation: KevObservation | None`, with
listed, optional date_added, observed_at, and evidence_ids. Use EvidenceSource.CISA_KEV
and include the KEV evidence UUID in the vulnerability's top-level evidence_ids.
The current translation example is the `kev`/`vulnerabilities`/`cveID` branch in
[FixtureVulnerabilitySource.fetch](../src/vulnops/sources/fixtures.py).

Join by validated CVE identifier. A missing/failed/partial catalog retrieval is
unknown enrichment, not listed=False and not proof of no exploitation. A deliberate
negative membership observation needs a complete dated catalog basis. KEV membership
does not directly change affected status, priority, lifecycle, or approval.

There is no separate KEV source protocol today. An adapter-specific translator can
provide KevObservation plus its Evidence to canonical snapshot assembly before the
first save. Enrichment of an already stored snapshot requires the explicit
reconciliation operation that does not yet exist.

### FIRST EPSS

Existing canonical seam: `Vulnerability.epss_observation: EpssObservation | None`, with
probability, score_date, optional percentile/model_version, observed_at, and evidence_ids.
Use EvidenceSource.EPSS and retain its reference in top-level evidence_ids. The
fixture translation example is the `epss`/`data`/`cve` branch in the same fetch method.

Parse finite probability/percentile values in 0–1 and preserve the source's score
date separately from retrieval time. A missing score stays None; a forecast is
neither proof of exploitation nor an enterprise risk/approval decision. Do not
collapse it into CVSS or use its confidence to resolve UNKNOWN.

No dedicated EPSS adapter/protocol or time-series store exists. Translate a dated
observation plus Evidence into canonical snapshot assembly; later daily updates
need the same explicit reconciliation/history decision as other changed sources.

### Vendor advisories

Existing seams: EvidenceSource.VENDOR → Evidence, plus attributable
AffectedProduct/ProductIdentity/VersionConstraint claims and Vulnerability references.
There is no VendorObservation model. The fixture vendor branch validates that a
non-null fixed_version is already represented by the vulnerability snapshot; it
does not implement a general vendor schema or silently rewrite affected ranges.

A future vendor-specific adapter must establish exact product/version applicability,
source/date/schema provenance, fixed-version semantics, and conflicts with CVE
claims. Retain the vendor evidence supporting any mapped constraint; unsupported
or contradictory claims must not silently produce a convenient safe conclusion.
An advisory's suggested shell command is inert text, never an execution plan.

Use canonical snapshot assembly and evidence-first persistence. Preserve the
primary source_schema_version and record vendor schema details on vendor Evidence.
If the CVE already exists, do not mutate the returned model and assume save_vulnerability
will update it: changed contents conflict until a reviewed reconciliation command exists.
